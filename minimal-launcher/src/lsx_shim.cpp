#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>

#include "lsx_server.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>

namespace {

using ConnectProc = int (WSAAPI*)(SOCKET, const sockaddr*, int);
using WsaConnectProc = int (WSAAPI*)(SOCKET, const sockaddr*, int, LPWSABUF,
                                     LPWSABUF, LPQOS, LPQOS);
using BindProc = int (WSAAPI*)(SOCKET, const sockaddr*, int);
using SendToProc = int (WSAAPI*)(SOCKET, const char*, int, int,
                                 const sockaddr*, int);
using RecvFromProc = int (WSAAPI*)(SOCKET, char*, int, int, sockaddr*, int*);
using SendProc = int (WSAAPI*)(SOCKET, const char*, int, int);
using RecvProc = int (WSAAPI*)(SOCKET, char*, int, int);
using WsaSendToProc = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD,
                                    const sockaddr*, int, LPWSAOVERLAPPED,
                                    LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using WsaRecvFromProc = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD,
                                      sockaddr*, LPINT, LPWSAOVERLAPPED,
                                      LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using WsaGetOverlappedResultProc = BOOL (WSAAPI*)(SOCKET, LPWSAOVERLAPPED,
                                                  LPDWORD, BOOL, LPDWORD);
using GetAdaptersAddressesProc = ULONG (WINAPI*)(ULONG, ULONG, PVOID,
                                                  PIP_ADAPTER_ADDRESSES,
                                                  PULONG);
using GetProcAddressProc = FARPROC (WINAPI*)(HMODULE, LPCSTR);

ConnectProc real_connect = nullptr;
WsaConnectProc real_wsa_connect = nullptr;
BindProc real_bind = nullptr;
BindProc bind_export = nullptr;
SendToProc real_sendto = nullptr;
SendToProc sendto_export = nullptr;
RecvFromProc real_recvfrom = nullptr;
RecvFromProc recvfrom_export = nullptr;
SendProc real_send = nullptr;
SendProc send_export = nullptr;
RecvProc real_recv = nullptr;
RecvProc recv_export = nullptr;
WsaSendToProc real_wsa_sendto = nullptr;
WsaSendToProc wsa_sendto_export = nullptr;
WsaRecvFromProc real_wsa_recvfrom = nullptr;
WsaRecvFromProc wsa_recvfrom_export = nullptr;
WsaGetOverlappedResultProc real_wsa_get_overlapped_result = nullptr;
WsaGetOverlappedResultProc wsa_get_overlapped_result_export = nullptr;
GetAdaptersAddressesProc real_get_adapters_addresses = nullptr;
GetAdaptersAddressesProc get_adapters_addresses_export = nullptr;
GetProcAddressProc real_get_proc_address = nullptr;
HMODULE winsock_module = nullptr;
HMODULE iphlpapi_module = nullptr;
std::atomic<std::uint16_t> local_lsx_port{0};
std::atomic<std::uint16_t> local_game_port{0};
std::atomic<std::uint32_t> local_game_address{0};
std::array<unsigned char, 6> local_machine_address{};
std::atomic<bool> virtualize_machine_identity{false};
std::atomic<bool> network_hooks_enabled{false};
std::atomic<unsigned> machine_identity_trace_count{0};
std::unique_ptr<LsxServer> server;
HMODULE shim_module = nullptr;
SRWLOCK log_lock = SRWLOCK_INIT;
std::wstring log_path;
HANDLE port_mapping = nullptr;
void* port_view = nullptr;
void* bind_trampoline = nullptr;
void* sendto_trampoline = nullptr;
void* recvfrom_trampoline = nullptr;
void* send_trampoline = nullptr;
void* recv_trampoline = nullptr;
void* wsa_sendto_trampoline = nullptr;
void* wsa_recvfrom_trampoline = nullptr;
std::atomic<unsigned> udp_trace_count{0};
struct PendingReceive {
    LPWSAOVERLAPPED overlapped = nullptr;
    sockaddr* source = nullptr;
    LPINT source_length = nullptr;
    char* first_buffer = nullptr;
    ULONG first_buffer_length = 0;
    SOCKET socket = INVALID_SOCKET;
    LPWSAOVERLAPPED_COMPLETION_ROUTINE completion = nullptr;
};
SRWLOCK pending_receive_lock = SRWLOCK_INIT;
std::array<PendingReceive, 256> pending_receives{};
std::atomic<bool> pending_receive_overflow_logged{false};

void log_message(const char* format, ...) {
    if (log_path.empty()) return;
    char message[1024]{};
    va_list arguments;
    va_start(arguments, format);
    const int length = std::vsnprintf(message, sizeof(message), format, arguments);
    va_end(arguments);
    if (length <= 0) return;

    AcquireSRWLockExclusive(&log_lock);
    HANDLE file = CreateFileW(log_path.c_str(), FILE_APPEND_DATA,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file != INVALID_HANDLE_VALUE) {
        const DWORD bytes = static_cast<DWORD>(
            std::min<int>(length, static_cast<int>(sizeof(message) - 1)));
        DWORD written = 0;
        WriteFile(file, message, bytes, &written, nullptr);
        CloseHandle(file);
    }
    ReleaseSRWLockExclusive(&log_lock);
}

void initialize_log() {
    std::wstring path(32768, L'\0');
    const DWORD length = GetModuleFileNameW(shim_module, path.data(),
                                            static_cast<DWORD>(path.size()));
    if (!length || length >= path.size()) return;
    path.resize(length);
    const std::size_t separator = path.find_last_of(L"\\/");
    if (separator != std::wstring::npos) path.resize(separator + 1);
    else path.clear();
    log_path = path + L"ZClient.LsxShim-" +
               std::to_wstring(GetCurrentProcessId()) + L".log";
    DeleteFileW(log_path.c_str());
    log_message("LSX shim process %lu started\r\n", GetCurrentProcessId());
}

template <typename To, typename From>
To function_cast(From value) {
    static_assert(sizeof(To) == sizeof(From));
    To result{};
    std::memcpy(&result, &value, sizeof(result));
    return result;
}

int WSAAPI shim_bind(SOCKET socket, const sockaddr* address, int length);
int WSAAPI shim_sendto(SOCKET socket, const char* buffer, int length, int flags,
                       const sockaddr* destination, int destination_length);
int WSAAPI shim_recvfrom(SOCKET socket, char* buffer, int length, int flags,
                         sockaddr* source, int* source_length);
int WSAAPI shim_send(SOCKET socket, const char* buffer, int length, int flags);
int WSAAPI shim_recv(SOCKET socket, char* buffer, int length, int flags);
int WSAAPI shim_wsa_sendto(SOCKET socket, LPWSABUF buffers, DWORD count,
                           LPDWORD sent, DWORD flags, const sockaddr* destination,
                           int destination_length, LPWSAOVERLAPPED overlapped,
                           LPWSAOVERLAPPED_COMPLETION_ROUTINE completion);
int WSAAPI shim_wsa_recvfrom(SOCKET socket, LPWSABUF buffers, DWORD count,
                             LPDWORD received, LPDWORD flags, sockaddr* source,
                             LPINT source_length, LPWSAOVERLAPPED overlapped,
                             LPWSAOVERLAPPED_COMPLETION_ROUTINE completion);
BOOL WSAAPI shim_wsa_get_overlapped_result(SOCKET socket,
                                            LPWSAOVERLAPPED overlapped,
                                            LPDWORD transferred, BOOL wait,
                                            LPDWORD flags);
ULONG WINAPI shim_get_adapters_addresses(ULONG family, ULONG flags,
                                         PVOID reserved,
                                         PIP_ADAPTER_ADDRESSES addresses,
                                         PULONG size);
bool is_game_socket(SOCKET socket);
const sockaddr* virtualize_game_destination(const sockaddr* address, int length,
                                             sockaddr_in* replacement);
void virtualize_game_source(sockaddr* address, int length);
void trace_udp(const char* operation, SOCKET socket, const sockaddr* endpoint,
               int endpoint_length, const char* buffer, int length,
               int result, int error);

bool remember_pending_receive(const PendingReceive& pending) {
    if (!pending.overlapped) return false;
    bool stored = false;
    AcquireSRWLockExclusive(&pending_receive_lock);
    PendingReceive* available = nullptr;
    for (auto& candidate : pending_receives) {
        if (candidate.overlapped == pending.overlapped) {
            available = &candidate;
            break;
        }
        if (!candidate.overlapped && !available) available = &candidate;
    }
    if (available) {
        *available = pending;
        stored = true;
    }
    ReleaseSRWLockExclusive(&pending_receive_lock);
    return stored;
}

bool take_pending_receive(LPWSAOVERLAPPED overlapped, PendingReceive* output) {
    if (!overlapped || !output) return false;
    bool found = false;
    AcquireSRWLockExclusive(&pending_receive_lock);
    for (auto& candidate : pending_receives) {
        if (candidate.overlapped == overlapped) {
            *output = candidate;
            candidate = {};
            found = true;
            break;
        }
    }
    ReleaseSRWLockExclusive(&pending_receive_lock);
    return found;
}

void write_absolute_jump(std::uint8_t* destination, const void* target) {
    destination[0] = 0xff;
    destination[1] = 0x25;
    std::memset(destination + 2, 0, 4);
    std::memcpy(destination + 6, &target, sizeof(target));
}

bool install_export_detour(const char* name, void* export_address,
                           void* replacement, const std::uint8_t* expected,
                           std::size_t copied_size, void** trampoline_out) {
    auto* entry = static_cast<std::uint8_t*>(export_address);
    if (!entry || copied_size < 14 || std::memcmp(entry, expected, copied_size) != 0) {
        log_message("ws2_32 %s prologue is unsupported; using pointer hooks only\r\n",
                    name);
        return false;
    }

    constexpr std::size_t jump_size = 14;
    void* trampoline_memory = VirtualAlloc(nullptr, copied_size + jump_size,
                                           MEM_COMMIT | MEM_RESERVE,
                                           PAGE_EXECUTE_READWRITE);
    if (!trampoline_memory) {
        log_message("VirtualAlloc for %s trampoline failed (Win32 %lu)\r\n",
                    name, GetLastError());
        return false;
    }
    auto* trampoline = static_cast<std::uint8_t*>(trampoline_memory);
    std::memcpy(trampoline, entry, copied_size);
    write_absolute_jump(trampoline + copied_size, entry + copied_size);

    DWORD old_protection = 0;
    if (!VirtualProtect(entry, copied_size, PAGE_EXECUTE_READWRITE,
                        &old_protection)) {
        log_message("VirtualProtect for %s detour failed (Win32 %lu)\r\n",
                    name, GetLastError());
        VirtualFree(trampoline_memory, 0, MEM_RELEASE);
        return false;
    }
    write_absolute_jump(entry, replacement);
    std::memset(entry + jump_size, 0x90, copied_size - jump_size);
    FlushInstructionCache(GetCurrentProcess(), entry, copied_size);
    DWORD ignored = 0;
    VirtualProtect(entry, copied_size, old_protection, &ignored);
    *trampoline_out = trampoline_memory;
    log_message("installed ws2_32 %s detour\r\n", name);
    return true;
}

bool install_bind_detour() {
    static constexpr std::uint8_t expected[] = {
        0x48, 0x89, 0x5c, 0x24, 0x08,
        0x48, 0x89, 0x6c, 0x24, 0x10,
        0x48, 0x89, 0x74, 0x24, 0x18,
    };
    if (!install_export_detour("bind", function_cast<void*>(bind_export),
                               function_cast<void*>(shim_bind), expected,
                               sizeof(expected), &bind_trampoline)) return false;
    real_bind = function_cast<BindProc>(bind_trampoline);
    return true;
}

void install_udp_trace_detours() {
    static constexpr std::uint8_t sendto_expected[] = {
        0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x08, 0x48,
        0x89, 0x70, 0x10, 0x48, 0x89, 0x78, 0x18,
    };
    static constexpr std::uint8_t recvfrom_expected[] = {
        0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x08, 0x48,
        0x89, 0x70, 0x10, 0x44, 0x89, 0x48, 0x20,
    };
    static constexpr std::uint8_t wsa_expected[] = {
        0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x08, 0x48,
        0x89, 0x68, 0x10, 0x48, 0x89, 0x70, 0x18,
    };
    static constexpr std::uint8_t send_expected[] = {
        0x48, 0x89, 0x5c, 0x24, 0x08,
        0x48, 0x89, 0x6c, 0x24, 0x10,
        0x48, 0x89, 0x74, 0x24, 0x18,
    };
    static constexpr std::uint8_t recv_expected[] = {
        0x48, 0x89, 0x5c, 0x24, 0x08,
        0x48, 0x89, 0x74, 0x24, 0x10,
        0x44, 0x89, 0x4c, 0x24, 0x20,
    };
    if (install_export_detour("sendto", function_cast<void*>(sendto_export),
                              function_cast<void*>(shim_sendto), sendto_expected,
                              sizeof(sendto_expected), &sendto_trampoline)) {
        real_sendto = function_cast<SendToProc>(sendto_trampoline);
    }
    if (install_export_detour("recvfrom", function_cast<void*>(recvfrom_export),
                              function_cast<void*>(shim_recvfrom), recvfrom_expected,
                              sizeof(recvfrom_expected), &recvfrom_trampoline)) {
        real_recvfrom = function_cast<RecvFromProc>(recvfrom_trampoline);
    }
    if (install_export_detour("send", function_cast<void*>(send_export),
                              function_cast<void*>(shim_send), send_expected,
                              sizeof(send_expected), &send_trampoline)) {
        real_send = function_cast<SendProc>(send_trampoline);
    }
    if (install_export_detour("recv", function_cast<void*>(recv_export),
                              function_cast<void*>(shim_recv), recv_expected,
                              sizeof(recv_expected), &recv_trampoline)) {
        real_recv = function_cast<RecvProc>(recv_trampoline);
    }
    if (install_export_detour("WSASendTo", function_cast<void*>(wsa_sendto_export),
                              function_cast<void*>(shim_wsa_sendto), wsa_expected,
                              sizeof(wsa_expected), &wsa_sendto_trampoline)) {
        real_wsa_sendto = function_cast<WsaSendToProc>(wsa_sendto_trampoline);
    }
    if (install_export_detour("WSARecvFrom", function_cast<void*>(wsa_recvfrom_export),
                              function_cast<void*>(shim_wsa_recvfrom), wsa_expected,
                              sizeof(wsa_expected), &wsa_recvfrom_trampoline)) {
        real_wsa_recvfrom = function_cast<WsaRecvFromProc>(wsa_recvfrom_trampoline);
    }
}

std::wstring environment(const wchar_t* name) {
    const DWORD size = GetEnvironmentVariableW(name, nullptr, 0);
    if (!size) return {};
    std::wstring value(size, L'\0');
    const DWORD copied = GetEnvironmentVariableW(name, value.data(), size);
    if (!copied || copied >= size) return {};
    value.resize(copied);
    return value;
}

std::string narrow(std::wstring_view value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                         value.data(), static_cast<int>(value.size()),
                                         nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                        static_cast<int>(value.size()), result.data(), size,
                        nullptr, nullptr);
    return result;
}

bool is_lsx_endpoint(const sockaddr* address, int length) {
    if (!address || address->sa_family != AF_INET ||
        length < static_cast<int>(sizeof(sockaddr_in))) {
        return false;
    }
    const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
    const std::uint16_t port = ntohs(ipv4->sin_port);
    // OriginSDK opens the logical LSX endpoint on 6176.  CLoader normally
    // translates that to the ZI-facing endpoint on 8216.  Depending on which
    // module owns the call site patched below, the shim can observe either
    // side of that translation.
    return port == 6176 || port == 8216;
}

sockaddr_in redirected_endpoint() {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(local_lsx_port.load(std::memory_order_acquire));
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return address;
}

int WSAAPI shim_connect(SOCKET socket, const sockaddr* address, int length) {
    if (!is_lsx_endpoint(address, length)) {
        const bool trace = is_game_socket(socket);
        sockaddr_in routed{};
        const sockaddr* endpoint = trace
            ? virtualize_game_destination(address, length, &routed)
            : address;
        const int result = real_connect(socket, endpoint, length);
        const int error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
        if (trace) trace_udp("connect", socket, endpoint, length, nullptr, 0,
                             result, error);
        if (result == SOCKET_ERROR) WSASetLastError(error);
        return result;
    }
    const auto* original = reinterpret_cast<const sockaddr_in*>(address);
    char host[INET_ADDRSTRLEN]{};
    InetNtopA(AF_INET, const_cast<IN_ADDR*>(&original->sin_addr), host,
              static_cast<DWORD>(sizeof(host)));
    const sockaddr_in local = redirected_endpoint();
    log_message("connect intercepted %s:%u -> 127.0.0.1:%u\r\n", host,
                ntohs(original->sin_port), ntohs(local.sin_port));
    const int result = real_connect(
        socket, reinterpret_cast<const sockaddr*>(&local), sizeof(local));
    log_message("connect result %d, WSA error %d\r\n", result,
                result == SOCKET_ERROR ? WSAGetLastError() : 0);
    return result;
}

int WSAAPI shim_wsa_connect(SOCKET socket, const sockaddr* address, int length,
                            LPWSABUF caller, LPWSABUF callee, LPQOS send_qos,
                            LPQOS receive_qos) {
    if (!is_lsx_endpoint(address, length)) {
        const bool trace = is_game_socket(socket);
        sockaddr_in routed{};
        const sockaddr* endpoint = trace
            ? virtualize_game_destination(address, length, &routed)
            : address;
        const int result = real_wsa_connect(socket, endpoint, length, caller, callee,
                                            send_qos, receive_qos);
        const int error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
        if (trace) trace_udp("WSAConnect", socket, endpoint, length, nullptr, 0,
                             result, error);
        if (result == SOCKET_ERROR) WSASetLastError(error);
        return result;
    }
    const auto* original = reinterpret_cast<const sockaddr_in*>(address);
    const sockaddr_in local = redirected_endpoint();
    log_message("WSAConnect intercepted port %u -> 127.0.0.1:%u\r\n",
                ntohs(original->sin_port), ntohs(local.sin_port));
    const int result = real_wsa_connect(
        socket, reinterpret_cast<const sockaddr*>(&local), sizeof(local),
        caller, callee, send_qos, receive_qos);
    log_message("WSAConnect result %d, WSA error %d\r\n", result,
                result == SOCKET_ERROR ? WSAGetLastError() : 0);
    return result;
}

int WSAAPI shim_bind(SOCKET socket, const sockaddr* address, int length) {
    if (!address || address->sa_family != AF_INET ||
        length < static_cast<int>(sizeof(sockaddr_in))) {
        return real_bind(socket, address, length);
    }
    const auto* original = reinterpret_cast<const sockaddr_in*>(address);
    int socket_type = 0;
    int option_size = sizeof(socket_type);
    const std::uint16_t requested_port = ntohs(original->sin_port);
    const std::uint16_t replacement_port =
        local_game_port.load(std::memory_order_acquire);
    if (requested_port != 3659 || replacement_port == 0 ||
        getsockopt(socket, SOL_SOCKET, SO_TYPE,
                   reinterpret_cast<char*>(&socket_type), &option_size) == SOCKET_ERROR ||
        socket_type != SOCK_DGRAM) {
        return real_bind(socket, address, length);
    }

    sockaddr_in replacement = *original;
    replacement.sin_port = htons(replacement_port);
    const std::uint32_t replacement_address =
        local_game_address.load(std::memory_order_acquire);
    if (replacement_address != 0) {
        replacement.sin_addr.s_addr = replacement_address;
    }
    char original_host[INET_ADDRSTRLEN]{};
    char replacement_host[INET_ADDRSTRLEN]{};
    InetNtopA(AF_INET, const_cast<IN_ADDR*>(&original->sin_addr), original_host,
              static_cast<DWORD>(sizeof(original_host)));
    InetNtopA(AF_INET, &replacement.sin_addr, replacement_host,
              static_cast<DWORD>(sizeof(replacement_host)));
    const int result = real_bind(
        socket, reinterpret_cast<const sockaddr*>(&replacement), sizeof(replacement));
    log_message("UDP bind intercepted %s:%u -> %s:%u, result %d, WSA error %d\r\n",
                original_host, requested_port, replacement_host, replacement_port, result,
                result == SOCKET_ERROR ? WSAGetLastError() : 0);
    return result;
}

bool is_game_socket(SOCKET socket) {
    sockaddr_in local{};
    int length = sizeof(local);
    return getsockname(socket, reinterpret_cast<sockaddr*>(&local), &length) == 0 &&
           local.sin_family == AF_INET &&
           ntohs(local.sin_port) == local_game_port.load(std::memory_order_acquire);
}

const sockaddr* virtualize_game_destination(const sockaddr* address, int length,
                                             sockaddr_in* replacement) {
    if (!address || !replacement || address->sa_family != AF_INET ||
        length < static_cast<int>(sizeof(sockaddr_in))) {
        return address;
    }
    const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
    const std::uint16_t port = ntohs(ipv4->sin_port);
    if (port < 20000 || port >= 60000) {
        return address;
    }
    const std::uint32_t host_address = ntohl(ipv4->sin_addr.s_addr);
    const std::uint32_t virtual_address = 0xc6120000u | port;
    if (host_address != virtual_address && host_address != INADDR_LOOPBACK) {
        return address;
    }
    *replacement = *ipv4;
    replacement->sin_addr.s_addr = htonl(0x7f000000u | port);
    return reinterpret_cast<const sockaddr*>(replacement);
}

void virtualize_game_source(sockaddr* address, int length) {
    if (!address || address->sa_family != AF_INET ||
        length < static_cast<int>(sizeof(sockaddr_in))) {
        return;
    }
    auto* ipv4 = reinterpret_cast<sockaddr_in*>(address);
    const std::uint16_t port = ntohs(ipv4->sin_port);
    const std::uint32_t host_address = ntohl(ipv4->sin_addr.s_addr);
    if ((host_address & 0xff000000u) == 0x7f000000u &&
        port >= 20000 && port < 60000) {
        ipv4->sin_addr.s_addr = htonl(0xc6120000u | port);
    }
}

void trace_udp(const char* operation, SOCKET socket, const sockaddr* endpoint,
               int endpoint_length, const char* buffer, int length,
               int result, int error) {
    if (udp_trace_count.fetch_add(1, std::memory_order_relaxed) >= 16384) return;
    char host[INET_ADDRSTRLEN] = "?";
    unsigned port = 0;
    if (endpoint && endpoint->sa_family == AF_INET &&
        endpoint_length >= static_cast<int>(sizeof(sockaddr_in))) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(endpoint);
        InetNtopA(AF_INET, const_cast<IN_ADDR*>(&ipv4->sin_addr), host,
                  static_cast<DWORD>(sizeof(host)));
        port = ntohs(ipv4->sin_port);
    }
    char prefix[33]{};
    static constexpr char hex[] = "0123456789abcdef";
    const int prefix_length = buffer && length > 0 ? std::min(length, 16) : 0;
    for (int index = 0; index < prefix_length; ++index) {
        const auto value = static_cast<unsigned char>(buffer[index]);
        prefix[index * 2] = hex[value >> 4];
        prefix[index * 2 + 1] = hex[value & 15];
    }
    log_message("UDP %s socket=%llu peer=%s:%u bytes=%d result=%d error=%d data=%s\r\n",
                operation, static_cast<unsigned long long>(socket), host, port,
                length, result, error, prefix);
}

int WSAAPI shim_sendto(SOCKET socket, const char* buffer, int length, int flags,
                       const sockaddr* destination, int destination_length) {
    const bool trace = is_game_socket(socket);
    sockaddr_in routed{};
    const sockaddr* endpoint = trace
        ? virtualize_game_destination(destination, destination_length, &routed)
        : destination;
    const int result = real_sendto(socket, buffer, length, flags,
                                   endpoint, destination_length);
    const int error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (trace) {
        trace_udp("sendto", socket, endpoint, destination_length,
                  buffer, length, result, error);
    }
    if (result == SOCKET_ERROR) WSASetLastError(error);
    return result;
}

int WSAAPI shim_recvfrom(SOCKET socket, char* buffer, int length, int flags,
                         sockaddr* source, int* source_length) {
    const bool trace = is_game_socket(socket);
    const int result = real_recvfrom(socket, buffer, length, flags, source, source_length);
    const int error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (trace && result >= 0) {
        virtualize_game_source(source, source_length ? *source_length : 0);
    }
    if (trace && (result >= 0 || error != WSAEWOULDBLOCK)) {
        trace_udp("recvfrom", socket, source,
                  source_length ? *source_length : 0, buffer,
                  result >= 0 ? result : 0, result, error);
    }
    if (result == SOCKET_ERROR) WSASetLastError(error);
    return result;
}

int WSAAPI shim_send(SOCKET socket, const char* buffer, int length, int flags) {
    const bool trace = is_game_socket(socket);
    sockaddr_storage peer{};
    int peer_length = sizeof(peer);
    if (trace) getpeername(socket, reinterpret_cast<sockaddr*>(&peer), &peer_length);
    const int result = real_send(socket, buffer, length, flags);
    const int error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (trace) {
        trace_udp("send", socket, reinterpret_cast<sockaddr*>(&peer), peer_length,
                  buffer, length, result, error);
    }
    if (result == SOCKET_ERROR) WSASetLastError(error);
    return result;
}

int WSAAPI shim_recv(SOCKET socket, char* buffer, int length, int flags) {
    const bool trace = is_game_socket(socket);
    sockaddr_storage peer{};
    int peer_length = sizeof(peer);
    if (trace) getpeername(socket, reinterpret_cast<sockaddr*>(&peer), &peer_length);
    const int result = real_recv(socket, buffer, length, flags);
    const int error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (trace && (result >= 0 || error != WSAEWOULDBLOCK)) {
        trace_udp("recv", socket, reinterpret_cast<sockaddr*>(&peer), peer_length,
                  buffer, result >= 0 ? result : 0, result, error);
    }
    if (result == SOCKET_ERROR) WSASetLastError(error);
    return result;
}

int WSAAPI shim_wsa_sendto(SOCKET socket, LPWSABUF buffers, DWORD count,
                           LPDWORD sent, DWORD flags, const sockaddr* destination,
                           int destination_length, LPWSAOVERLAPPED overlapped,
                           LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    const bool trace = is_game_socket(socket);
    sockaddr_in routed{};
    const sockaddr* endpoint = trace
        ? virtualize_game_destination(destination, destination_length, &routed)
        : destination;
    const int result = real_wsa_sendto(socket, buffers, count, sent, flags,
                                       endpoint, destination_length,
                                       overlapped, completion);
    const int error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (trace) {
        int length = 0;
        for (DWORD index = 0; index < count; ++index) {
            length += static_cast<int>(buffers[index].len);
        }
        trace_udp("WSASendTo", socket, endpoint, destination_length,
                  count ? buffers[0].buf : nullptr, count ? buffers[0].len : 0,
                  result, error);
        if (length != (count ? static_cast<int>(buffers[0].len) : 0)) {
            log_message("UDP WSASendTo socket=%llu aggregate_bytes=%d\r\n",
                        static_cast<unsigned long long>(socket), length);
        }
    }
    if (result == SOCKET_ERROR) WSASetLastError(error);
    return result;
}

void complete_pending_receive(PendingReceive& pending, DWORD error,
                              DWORD transferred, const char* operation) {
    if (error == 0) {
        virtualize_game_source(
            pending.source,
            pending.source_length ? *pending.source_length : 0);
    }
    trace_udp(operation, pending.socket, pending.source,
              pending.source_length ? *pending.source_length : 0,
              pending.first_buffer,
              pending.first_buffer
                  ? std::min<int>(static_cast<int>(transferred),
                                  static_cast<int>(pending.first_buffer_length))
                  : 0,
              error == 0 ? 0 : SOCKET_ERROR, static_cast<int>(error));
}

void CALLBACK shim_wsa_recv_completion(DWORD error, DWORD transferred,
                                       LPWSAOVERLAPPED overlapped, DWORD flags) {
    PendingReceive pending{};
    if (!take_pending_receive(overlapped, &pending)) return;
    complete_pending_receive(pending, error, transferred,
                             "WSARecvFrom-complete");
    if (pending.completion) {
        pending.completion(error, transferred, overlapped, flags);
    }
}

int WSAAPI shim_wsa_recvfrom(SOCKET socket, LPWSABUF buffers, DWORD count,
                             LPDWORD received, LPDWORD flags, sockaddr* source,
                             LPINT source_length, LPWSAOVERLAPPED overlapped,
                             LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    const bool trace = is_game_socket(socket);
    bool pending_stored = false;
    if (trace && overlapped) {
        pending_stored = remember_pending_receive({
            overlapped, source, source_length,
            count ? buffers[0].buf : nullptr,
            count ? buffers[0].len : 0,
            socket, completion});
        if (!pending_stored &&
            !pending_receive_overflow_logged.exchange(true,
                                                       std::memory_order_relaxed)) {
            log_message("pending UDP receive table is full; source virtualization may be incomplete\r\n");
        }
    }
    const int result = real_wsa_recvfrom(socket, buffers, count, received, flags,
                                         source, source_length, overlapped,
                                         pending_stored && completion
                                             ? shim_wsa_recv_completion
                                             : completion);
    const int error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
    if (trace && result == 0) {
        if (pending_stored && !completion) {
            PendingReceive ignored{};
            take_pending_receive(overlapped, &ignored);
        }
        virtualize_game_source(source, source_length ? *source_length : 0);
        const int bytes = received ? static_cast<int>(*received) : 0;
        trace_udp("WSARecvFrom", socket, source,
                  source_length ? *source_length : 0,
                  count ? buffers[0].buf : nullptr,
                  std::min(bytes, count ? static_cast<int>(buffers[0].len) : 0),
                  result, error);
    }
    if (pending_stored && result == SOCKET_ERROR && error != WSA_IO_PENDING) {
        PendingReceive ignored{};
        take_pending_receive(overlapped, &ignored);
    }
    if (result == SOCKET_ERROR) WSASetLastError(error);
    return result;
}

BOOL WSAAPI shim_wsa_get_overlapped_result(SOCKET socket,
                                            LPWSAOVERLAPPED overlapped,
                                            LPDWORD transferred, BOOL wait,
                                            LPDWORD flags) {
    const BOOL result = real_wsa_get_overlapped_result(
        socket, overlapped, transferred, wait, flags);
    const int error = result ? 0 : WSAGetLastError();
    if (result) {
        PendingReceive pending{};
        if (take_pending_receive(overlapped, &pending)) {
            complete_pending_receive(pending, 0, transferred ? *transferred : 0,
                                     "WSAGetOverlappedResult");
        }
    } else if (error != WSA_IO_INCOMPLETE) {
        PendingReceive ignored{};
        take_pending_receive(overlapped, &ignored);
    }
    if (!result) WSASetLastError(error);
    return result;
}

ULONG WINAPI shim_get_adapters_addresses(ULONG family, ULONG flags,
                                         PVOID reserved,
                                         PIP_ADAPTER_ADDRESSES addresses,
                                         PULONG size) {
    const ULONG result = real_get_adapters_addresses(
        family, flags, reserved, addresses, size);
    if (result != NO_ERROR || !addresses ||
        !virtualize_machine_identity.load(std::memory_order_acquire)) {
        return result;
    }

    unsigned changed = 0;
    unsigned traversed = 0;
    for (auto* adapter = addresses; adapter && traversed < 256;
         adapter = adapter->Next, ++traversed) {
        if (adapter->PhysicalAddressLength < local_machine_address.size()) {
            continue;
        }
        std::fill(std::begin(adapter->PhysicalAddress),
                  std::end(adapter->PhysicalAddress), 0);
        std::copy(local_machine_address.begin(), local_machine_address.end(),
                  adapter->PhysicalAddress);
        ++changed;
    }

    const unsigned trace = machine_identity_trace_count.fetch_add(
        1, std::memory_order_relaxed);
    if (trace < 8) {
        log_message(
            "GetAdaptersAddresses virtualized %u adapter(s) as "
            "%02x:%02x:%02x:%02x:%02x:%02x\r\n",
            changed, local_machine_address[0], local_machine_address[1],
            local_machine_address[2], local_machine_address[3],
            local_machine_address[4], local_machine_address[5]);
    }
    return result;
}

FARPROC WINAPI shim_get_proc_address(HMODULE module, LPCSTR name) {
    FARPROC result = real_get_proc_address(module, name);
    if (!name || reinterpret_cast<std::uintptr_t>(name) <= 0xffff) {
        return result;
    }
    if (std::strcmp(name, "GetAdaptersAddresses") == 0 &&
        (module == iphlpapi_module ||
         result == function_cast<FARPROC>(get_adapters_addresses_export))) {
        return function_cast<FARPROC>(shim_get_adapters_addresses);
    }
    if (!network_hooks_enabled.load(std::memory_order_acquire)) return result;
    if (module != winsock_module) return result;
    if (std::strcmp(name, "connect") == 0) {
        return function_cast<FARPROC>(shim_connect);
    }
    if (std::strcmp(name, "WSAConnect") == 0) {
        return function_cast<FARPROC>(shim_wsa_connect);
    }
    if (std::strcmp(name, "bind") == 0) {
        return function_cast<FARPROC>(shim_bind);
    }
    if (std::strcmp(name, "sendto") == 0) {
        return function_cast<FARPROC>(shim_sendto);
    }
    if (std::strcmp(name, "recvfrom") == 0) {
        return function_cast<FARPROC>(shim_recvfrom);
    }
    if (std::strcmp(name, "send") == 0) {
        return function_cast<FARPROC>(shim_send);
    }
    if (std::strcmp(name, "recv") == 0) {
        return function_cast<FARPROC>(shim_recv);
    }
    if (std::strcmp(name, "WSASendTo") == 0) {
        return function_cast<FARPROC>(shim_wsa_sendto);
    }
    if (std::strcmp(name, "WSARecvFrom") == 0) {
        return function_cast<FARPROC>(shim_wsa_recvfrom);
    }
    if (std::strcmp(name, "WSAGetOverlappedResult") == 0) {
        return function_cast<FARPROC>(shim_wsa_get_overlapped_result);
    }
    return result;
}

bool readable(const void* address, void* output, std::size_t size) {
    SIZE_T copied = 0;
    return ReadProcessMemory(GetCurrentProcess(), address, output, size, &copied) &&
           copied == size;
}

void* replacement_for(void* value) {
    if (value == reinterpret_cast<void*>(get_adapters_addresses_export)) {
        return reinterpret_cast<void*>(shim_get_adapters_addresses);
    }
    if (value == reinterpret_cast<void*>(real_get_proc_address)) {
        return reinterpret_cast<void*>(shim_get_proc_address);
    }
    if (!network_hooks_enabled.load(std::memory_order_acquire)) return nullptr;
    if (value == reinterpret_cast<void*>(real_connect)) {
        return reinterpret_cast<void*>(shim_connect);
    }
    if (value == reinterpret_cast<void*>(real_wsa_connect)) {
        return reinterpret_cast<void*>(shim_wsa_connect);
    }
    if (value == reinterpret_cast<void*>(bind_export)) {
        return reinterpret_cast<void*>(shim_bind);
    }
    if (value == reinterpret_cast<void*>(sendto_export)) {
        return reinterpret_cast<void*>(shim_sendto);
    }
    if (value == reinterpret_cast<void*>(recvfrom_export)) {
        return reinterpret_cast<void*>(shim_recvfrom);
    }
    if (value == reinterpret_cast<void*>(send_export)) {
        return reinterpret_cast<void*>(shim_send);
    }
    if (value == reinterpret_cast<void*>(recv_export)) {
        return reinterpret_cast<void*>(shim_recv);
    }
    if (value == reinterpret_cast<void*>(wsa_sendto_export)) {
        return reinterpret_cast<void*>(shim_wsa_sendto);
    }
    if (value == reinterpret_cast<void*>(wsa_recvfrom_export)) {
        return reinterpret_cast<void*>(shim_wsa_recvfrom);
    }
    if (value == reinterpret_cast<void*>(wsa_get_overlapped_result_export)) {
        return reinterpret_cast<void*>(shim_wsa_get_overlapped_result);
    }
    return nullptr;
}

bool replace_pointer(void** slot, void* expected, void* replacement) {
    DWORD old_protection = 0;
    if (!VirtualProtect(slot, sizeof(*slot), PAGE_READWRITE, &old_protection)) {
        return false;
    }
    void* previous = InterlockedCompareExchangePointer(slot, replacement, expected);
    DWORD ignored = 0;
    VirtualProtect(slot, sizeof(*slot), old_protection, &ignored);
    return previous == expected;
}

unsigned patch_image(std::uintptr_t base) {
    IMAGE_DOS_HEADER dos{};
    if (!readable(reinterpret_cast<void*>(base), &dos, sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0) {
        return 0;
    }
    IMAGE_NT_HEADERS64 nt{};
    if (!readable(reinterpret_cast<void*>(base + dos.e_lfanew), &nt, sizeof(nt)) ||
        nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return 0;
    }

    unsigned patched = 0;
    const auto import_directory =
        nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_directory.VirtualAddress) {
        for (std::size_t i = 0;; ++i) {
            IMAGE_IMPORT_DESCRIPTOR descriptor{};
            if (!readable(reinterpret_cast<void*>(
                    base + import_directory.VirtualAddress + i * sizeof(descriptor)),
                    &descriptor, sizeof(descriptor)) || !descriptor.Name) {
                break;
            }
            for (std::size_t j = 0;; ++j) {
                auto** slot = reinterpret_cast<void**>(
                    base + descriptor.FirstThunk + j * sizeof(void*));
                void* value = nullptr;
                if (!readable(slot, &value, sizeof(value)) || !value) break;
                void* replacement = replacement_for(value);
                if (replacement && replace_pointer(slot, value, replacement)) ++patched;
            }
        }
    }

    const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        base + dos.e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
        nt.FileHeader.SizeOfOptionalHeader);
    for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER section{};
        if (!readable(sections + i, &section, sizeof(section))) break;
        if (!(section.Characteristics & IMAGE_SCN_MEM_WRITE) || !section.VirtualAddress) {
            continue;
        }
        const std::size_t size = std::max<std::size_t>(
            section.Misc.VirtualSize, section.SizeOfRawData);
        const std::uintptr_t start = base + section.VirtualAddress;
        const std::uintptr_t end = start + size;
        for (std::uintptr_t cursor = (start + sizeof(void*) - 1) & ~(sizeof(void*) - 1);
             cursor + sizeof(void*) <= end; cursor += sizeof(void*)) {
            auto** slot = reinterpret_cast<void**>(cursor);
            void* value = nullptr;
            if (!readable(slot, &value, sizeof(value))) continue;
            void* replacement = replacement_for(value);
            if (replacement && replace_pointer(slot, value, replacement)) ++patched;
        }
    }
    return patched;
}

unsigned patch_loaded_images() {
    MEMORY_BASIC_INFORMATION memory{};
    std::uintptr_t cursor = 0;
    std::set<std::uintptr_t> visited;
    unsigned patched = 0;
    while (VirtualQuery(reinterpret_cast<void*>(cursor), &memory, sizeof(memory))) {
        const auto base = reinterpret_cast<std::uintptr_t>(memory.AllocationBase);
        const auto next = reinterpret_cast<std::uintptr_t>(memory.BaseAddress) +
                          memory.RegionSize;
        if (memory.State == MEM_COMMIT && base &&
            base != reinterpret_cast<std::uintptr_t>(shim_module) &&
            visited.insert(base).second) {
            patched += patch_image(base);
        }
        if (next <= cursor) break;
        cursor = next;
    }
    return patched;
}

void signal_ready() {
    const std::wstring name = L"Local\\ZClient_LsxShimReady_" +
                              std::to_wstring(GetCurrentProcessId());
    HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, name.c_str());
    if (event) {
        SetEvent(event);
        CloseHandle(event);
    }
}

void publish_port(std::uint16_t port) {
    const std::wstring name = L"Local\\ZClient_LsxShimPort_" +
                              std::to_wstring(GetCurrentProcessId());
    port_mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr,
                                      PAGE_READWRITE, 0, sizeof(port), name.c_str());
    if (!port_mapping) throw std::runtime_error("Could not create LSX port mapping");
    port_view = MapViewOfFile(port_mapping, FILE_MAP_WRITE, 0, 0, sizeof(port));
    if (!port_view) throw std::runtime_error("Could not map LSX port mapping");
    std::memcpy(port_view, &port, sizeof(port));
    FlushViewOfFile(port_view, sizeof(port));
}

DWORD WINAPI worker(void*) {
    try {
        if (environment(L"ZCLIENT_LSX_LOG") != L"0") initialize_log();
        winsock_module = GetModuleHandleW(L"ws2_32.dll");
        if (!winsock_module) winsock_module = LoadLibraryW(L"ws2_32.dll");
        iphlpapi_module = GetModuleHandleW(L"iphlpapi.dll");
        if (!iphlpapi_module) iphlpapi_module = LoadLibraryW(L"iphlpapi.dll");
        HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
        real_get_proc_address = function_cast<GetProcAddressProc>(
            GetProcAddress(kernel, "GetProcAddress"));
        real_connect = function_cast<ConnectProc>(
            real_get_proc_address(winsock_module, "connect"));
        real_wsa_connect = function_cast<WsaConnectProc>(
            real_get_proc_address(winsock_module, "WSAConnect"));
        bind_export = function_cast<BindProc>(
            real_get_proc_address(winsock_module, "bind"));
        sendto_export = function_cast<SendToProc>(
            real_get_proc_address(winsock_module, "sendto"));
        recvfrom_export = function_cast<RecvFromProc>(
            real_get_proc_address(winsock_module, "recvfrom"));
        send_export = function_cast<SendProc>(
            real_get_proc_address(winsock_module, "send"));
        recv_export = function_cast<RecvProc>(
            real_get_proc_address(winsock_module, "recv"));
        wsa_sendto_export = function_cast<WsaSendToProc>(
            real_get_proc_address(winsock_module, "WSASendTo"));
        wsa_recvfrom_export = function_cast<WsaRecvFromProc>(
            real_get_proc_address(winsock_module, "WSARecvFrom"));
        wsa_get_overlapped_result_export = function_cast<WsaGetOverlappedResultProc>(
            real_get_proc_address(winsock_module, "WSAGetOverlappedResult"));
        get_adapters_addresses_export = function_cast<GetAdaptersAddressesProc>(
            real_get_proc_address(iphlpapi_module, "GetAdaptersAddresses"));
        real_bind = bind_export;
        real_sendto = sendto_export;
        real_recvfrom = recvfrom_export;
        real_send = send_export;
        real_recv = recv_export;
        real_wsa_sendto = wsa_sendto_export;
        real_wsa_recvfrom = wsa_recvfrom_export;
        real_wsa_get_overlapped_result = wsa_get_overlapped_result_export;
        real_get_adapters_addresses = get_adapters_addresses_export;
        if (!real_connect || !real_wsa_connect || !bind_export ||
            !sendto_export || !recvfrom_export || !send_export || !recv_export ||
            !wsa_sendto_export ||
            !wsa_recvfrom_export || !wsa_get_overlapped_result_export ||
            !get_adapters_addresses_export || !real_get_proc_address) {
            throw std::runtime_error("Could not resolve network entry points");
        }

        const std::wstring eaid = environment(L"EALaunchEAID");
        const std::wstring content_id = environment(L"ContentId");
        const std::string auth_token = narrow(environment(L"EALaunchUserAuthToken"));
        const std::string game_title = narrow(environment(L"ZCLIENT_GAME_TITLE"));
        const std::wstring account_text = environment(L"ZCLIENT_LSX_ACCOUNT_ID");
        wchar_t* account_end = nullptr;
        const std::uint64_t account_id = account_text.empty()
            ? 2
            : _wcstoui64(account_text.c_str(), &account_end, 10);
        if (eaid.empty() || content_id.empty() || auth_token.empty() || game_title.empty() ||
            (!account_text.empty() && (!account_end || *account_end))) {
            throw std::runtime_error("LSX shim environment is incomplete");
        }

        std::uint32_t identity_hash = 2166136261u;
        for (const unsigned char value : narrow(eaid)) {
            identity_hash ^= value;
            identity_hash *= 16777619u;
        }
        const std::uint32_t identity_id =
            (identity_hash & 0x3fffffffu) + 0x1000u;
        constexpr std::uint16_t game_port_base = 20000;
        constexpr std::uint32_t game_port_count = 40000;
        const auto game_port = static_cast<std::uint16_t>(
            game_port_base + identity_id % game_port_count);
        local_game_port.store(game_port, std::memory_order_release);
        const bool isolate_local_network =
            environment(L"ZCLIENT_LOCAL_GAME_NETWORK") == L"1";
        if (isolate_local_network) {
            const std::uint32_t loopback =
                0x7f000000u | game_port;
            local_game_address.store(htonl(loopback), std::memory_order_release);
            local_machine_address = {
                0x02, 0x5a,
                static_cast<unsigned char>(identity_id >> 24),
                static_cast<unsigned char>(identity_id >> 16),
                static_cast<unsigned char>(identity_id >> 8),
                static_cast<unsigned char>(identity_id),
            };
            virtualize_machine_identity.store(true, std::memory_order_release);
            log_message(
                "virtual machine address %02x:%02x:%02x:%02x:%02x:%02x\r\n",
                local_machine_address[0], local_machine_address[1],
                local_machine_address[2], local_machine_address[3],
                local_machine_address[4], local_machine_address[5]);
        }

        server = std::make_unique<LsxServer>(
            "127.0.0.1", 0, eaid, content_id, auth_token, game_title, account_id);
        local_lsx_port.store(server->port(), std::memory_order_release);
        publish_port(server->port());
        const unsigned initial_patches = patch_loaded_images();
        in_addr game_address{};
        game_address.s_addr = local_game_address.load(std::memory_order_acquire);
        char game_host[INET_ADDRSTRLEN] = "0.0.0.0";
        if (game_address.s_addr != 0) {
            InetNtopA(AF_INET, &game_address, game_host,
                      static_cast<DWORD>(sizeof(game_host)));
        }
        log_message("listener 127.0.0.1:%u; game endpoint %s:%u; installed %u early hooks\r\n",
                    server->port(), game_host, game_port, initial_patches);

        const std::wstring process_suffix = std::to_wstring(GetCurrentProcessId());
        const std::wstring enable_name =
            L"Local\\ZClient_LsxShimEnableNetwork_" + process_suffix;
        const std::wstring network_ready_name =
            L"Local\\ZClient_LsxShimNetworkReady_" + process_suffix;
        HANDLE enable_event = CreateEventW(nullptr, TRUE, FALSE,
                                           enable_name.c_str());
        HANDLE network_ready_event = CreateEventW(nullptr, TRUE, FALSE,
                                                  network_ready_name.c_str());
        if (!enable_event || !network_ready_event) {
            if (enable_event) CloseHandle(enable_event);
            if (network_ready_event) CloseHandle(network_ready_event);
            throw std::runtime_error("Could not create LSX shim network events");
        }
        signal_ready();

        bool network_active = false;
        for (;;) {
            if (!network_active &&
                WaitForSingleObject(enable_event, 0) == WAIT_OBJECT_0) {
                install_bind_detour();
                install_udp_trace_detours();
                network_hooks_enabled.store(true, std::memory_order_release);
                const unsigned patches = patch_loaded_images();
                log_message("network hooks enabled; installed %u late hooks\r\n",
                            patches);
                if (!SetEvent(network_ready_event)) {
                    throw std::runtime_error(
                        "Could not signal LSX shim network readiness");
                }
                network_active = true;
            }
            Sleep(50);
            const unsigned patches = patch_loaded_images();
            if (patches) log_message("installed %u additional hooks\r\n", patches);
        }
    } catch (const std::exception& error) {
        log_message("fatal: %s\r\n", error.what());
        const std::string message = std::string("ZClient LSX shim failed: ") +
                                    error.what() + "\n";
        OutputDebugStringA(message.c_str());
    }
    return 0;
}

} // namespace

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        shim_module = module;
        DisableThreadLibraryCalls(module);
        HANDLE thread = CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
        if (!thread) return FALSE;
        CloseHandle(thread);
    }
    return TRUE;
}
