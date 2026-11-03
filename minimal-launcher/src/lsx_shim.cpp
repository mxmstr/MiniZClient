#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <shellapi.h>
#include <intrin.h>

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
#include <filesystem>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::string narrow(std::wstring_view value);

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
using CertGetCertificateChainProc = BOOL (WINAPI*)(
    HCERTCHAINENGINE, PCCERT_CONTEXT, LPFILETIME, HCERTSTORE,
    PCERT_CHAIN_PARA, DWORD, LPVOID, PCCERT_CHAIN_CONTEXT*);
using CertVerifyCertificateChainPolicyProc = BOOL (WINAPI*)(
    LPCSTR, PCCERT_CHAIN_CONTEXT, PCERT_CHAIN_POLICY_PARA,
    PCERT_CHAIN_POLICY_STATUS);
using CertAddEncodedCertificateToStoreProc = BOOL (WINAPI*)(
    HCERTSTORE, DWORD, const BYTE*, DWORD, DWORD, PCCERT_CONTEXT*);
using CertEnumCertificatesInStoreProc = PCCERT_CONTEXT (WINAPI*)(
    HCERTSTORE, PCCERT_CONTEXT);
using CertGetIssuerCertificateFromStoreProc = PCCERT_CONTEXT (WINAPI*)(
    HCERTSTORE, PCCERT_CONTEXT, PCCERT_CONTEXT, DWORD*);
using CertFindCertificateInStoreProc = PCCERT_CONTEXT (WINAPI*)(
    HCERTSTORE, DWORD, DWORD, DWORD, const void*, PCCERT_CONTEXT);
using CryptStringToBinaryAProc = BOOL (WINAPI*)(
    LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);
using BCryptVerifySignatureProc = NTSTATUS (WINAPI*)(
    BCRYPT_KEY_HANDLE, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
using GetProcAddressProc = FARPROC (WINAPI*)(HMODULE, LPCSTR);
using CreateProcessWProc = BOOL (WINAPI*)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL,
    DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
using ShellExecuteExWProc = BOOL (WINAPI*)(SHELLEXECUTEINFOW*);

ConnectProc real_connect = nullptr;
ConnectProc connect_export = nullptr;
WsaConnectProc real_wsa_connect = nullptr;
WsaConnectProc wsa_connect_export = nullptr;
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
CertGetCertificateChainProc real_cert_get_certificate_chain = nullptr;
CertGetCertificateChainProc cert_get_certificate_chain_export = nullptr;
CertVerifyCertificateChainPolicyProc real_cert_verify_certificate_chain_policy = nullptr;
CertVerifyCertificateChainPolicyProc cert_verify_certificate_chain_policy_export = nullptr;
CertAddEncodedCertificateToStoreProc real_cert_add_encoded_certificate_to_store = nullptr;
CertAddEncodedCertificateToStoreProc cert_add_encoded_certificate_to_store_export = nullptr;
CertEnumCertificatesInStoreProc real_cert_enum_certificates_in_store = nullptr;
CertEnumCertificatesInStoreProc cert_enum_certificates_in_store_export = nullptr;
CertGetIssuerCertificateFromStoreProc real_cert_get_issuer_certificate_from_store = nullptr;
CertGetIssuerCertificateFromStoreProc cert_get_issuer_certificate_from_store_export = nullptr;
CertFindCertificateInStoreProc real_cert_find_certificate_in_store = nullptr;
CertFindCertificateInStoreProc cert_find_certificate_in_store_export = nullptr;
CryptStringToBinaryAProc crypt_string_to_binary_a = nullptr;
BCryptVerifySignatureProc bcrypt_verify_signature_export = nullptr;
GetProcAddressProc real_get_proc_address = nullptr;
CreateProcessWProc real_create_process_w = nullptr;
ShellExecuteExWProc real_shell_execute_ex_w = nullptr;
HMODULE winsock_module = nullptr;
HMODULE iphlpapi_module = nullptr;
HMODULE crypt32_module = nullptr;
HMODULE bcrypt_module = nullptr;
HMODULE kernel32_module = nullptr;
HMODULE shell32_module = nullptr;
std::atomic<std::uint16_t> local_lsx_port{0};
std::atomic<std::uint16_t> local_game_port{0};
std::atomic<std::uint32_t> local_game_address{0};
std::atomic<std::uint32_t> service_address{0};
std::atomic<bool> translate_rivals_ports{false};
std::atomic<bool> suppress_ea_client_launch{false};
std::wstring ea_client_stub_executable;
std::array<unsigned char, 6> local_machine_address{};
std::atomic<bool> virtualize_machine_identity{false};
std::atomic<bool> network_hooks_enabled{false};
std::atomic<bool> certificate_hooks_enabled{false};
std::atomic<bool> signature_hooks_enabled{false};
std::atomic<bool> redirect_dynamic_loopback_lsx{false};
std::atomic<unsigned> machine_identity_trace_count{0};
std::atomic<unsigned> tcp_connect_trace_count{0};
std::vector<BYTE> zlo_root_der;
std::unique_ptr<LsxServer> server;
HMODULE shim_module = nullptr;
SRWLOCK log_lock = SRWLOCK_INIT;
std::wstring log_path;
HANDLE port_mapping = nullptr;
void* port_view = nullptr;
void* connect_trampoline = nullptr;
void* wsa_connect_trampoline = nullptr;
void* cert_get_certificate_chain_trampoline = nullptr;
void* cert_verify_certificate_chain_policy_trampoline = nullptr;
void* bcrypt_verify_signature_trampoline = nullptr;
std::atomic<unsigned> bcrypt_verify_signature_trace_count{0};
std::atomic<bool> dirtyssl_probe_complete{false};
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

    char debug_message[1100] = "[ZClient.LsxShim] ";
    const std::size_t prefix = std::strlen(debug_message);
    const std::size_t copy = std::min<std::size_t>(
        static_cast<std::size_t>(length),
        sizeof(debug_message) - prefix - 1);
    std::memcpy(debug_message + prefix, message, copy);
    debug_message[prefix + copy] = '\0';
    OutputDebugStringA(debug_message);

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

int WSAAPI shim_connect(SOCKET socket, const sockaddr* address, int length);
int WSAAPI shim_wsa_connect(SOCKET socket, const sockaddr* address, int length,
                            LPWSABUF caller, LPWSABUF callee, LPQOS send_qos,
                            LPQOS receive_qos);
BOOL WINAPI shim_create_process_w(
    LPCWSTR application_name, LPWSTR command_line,
    LPSECURITY_ATTRIBUTES process_attributes,
    LPSECURITY_ATTRIBUTES thread_attributes, BOOL inherit_handles,
    DWORD creation_flags, LPVOID environment_block,
    LPCWSTR current_directory, LPSTARTUPINFOW startup,
    LPPROCESS_INFORMATION process_information);
BOOL WINAPI shim_shell_execute_ex_w(SHELLEXECUTEINFOW* info);
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
BOOL WINAPI shim_cert_get_certificate_chain(
    HCERTCHAINENGINE engine, PCCERT_CONTEXT certificate, LPFILETIME time,
    HCERTSTORE additional_store, PCERT_CHAIN_PARA parameters, DWORD flags,
    LPVOID reserved, PCCERT_CHAIN_CONTEXT* chain_context);
BOOL WINAPI shim_cert_verify_certificate_chain_policy(
    LPCSTR policy, PCCERT_CHAIN_CONTEXT chain_context,
    PCERT_CHAIN_POLICY_PARA parameters, PCERT_CHAIN_POLICY_STATUS status);
NTSTATUS WINAPI shim_bcrypt_verify_signature(
    BCRYPT_KEY_HANDLE key, VOID* padding, PUCHAR hash, ULONG hash_size,
    PUCHAR signature, ULONG signature_size, ULONG flags);
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
void probe_rivals_dirtyssl();

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
        log_message("system export %s prologue is unsupported; using pointer hooks only\r\n",
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
    log_message("installed system export %s detour\r\n", name);
    return true;
}

void install_certificate_detours() {
    static constexpr std::uint8_t get_chain_expected[] = {
        0x48, 0x8b, 0xc4,
        0x48, 0x89, 0x58, 0x10,
        0x4c, 0x89, 0x40, 0x18,
        0x55, 0x56, 0x57,
    };
    static constexpr std::uint8_t verify_policy_expected[] = {
        0x4c, 0x8b, 0xdc,
        0x49, 0x89, 0x5b, 0x08,
        0x49, 0x89, 0x6b, 0x10,
        0x49, 0x89, 0x73, 0x18,
    };
    if (install_export_detour(
            "crypt32!CertGetCertificateChain",
            function_cast<void*>(cert_get_certificate_chain_export),
            function_cast<void*>(shim_cert_get_certificate_chain),
            get_chain_expected, sizeof(get_chain_expected),
            &cert_get_certificate_chain_trampoline)) {
        real_cert_get_certificate_chain =
            function_cast<CertGetCertificateChainProc>(
                cert_get_certificate_chain_trampoline);
    }
    if (install_export_detour(
            "crypt32!CertVerifyCertificateChainPolicy",
            function_cast<void*>(cert_verify_certificate_chain_policy_export),
            function_cast<void*>(shim_cert_verify_certificate_chain_policy),
            verify_policy_expected, sizeof(verify_policy_expected),
            &cert_verify_certificate_chain_policy_trampoline)) {
        real_cert_verify_certificate_chain_policy =
            function_cast<CertVerifyCertificateChainPolicyProc>(
                cert_verify_certificate_chain_policy_trampoline);
    }
}

void install_signature_detour() {
#ifdef _WIN64
    // Windows 10/11 x64 bcrypt starts BCryptVerifySignature with this
    // relocation-free 16-byte sequence. CMain replaces the function with
    // `xor eax,eax; ret`; keep the same behavior scoped to standalone Rivals.
    static constexpr std::uint8_t expected[] = {
        0x40, 0x55,
        0x41, 0x54,
        0x41, 0x55,
        0x41, 0x56,
        0x41, 0x57,
        0x48, 0x81, 0xec, 0x80, 0x00, 0x00,
    };
    (void)install_export_detour(
        "bcrypt!BCryptVerifySignature",
        function_cast<void*>(bcrypt_verify_signature_export),
        function_cast<void*>(shim_bcrypt_verify_signature),
        expected, sizeof(expected), &bcrypt_verify_signature_trampoline);
#endif
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

void install_tcp_connect_detours() {
    // Windows 10/11 ws2_32 connect and WSAConnect currently share this
    // relocation-free entry sequence. Detouring the exports complements the
    // import/data-pointer patcher for protected titles which resolve Winsock
    // internally and do not retain a discoverable function pointer.
    static constexpr std::uint8_t expected[] = {
        0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x08, 0x48,
        0x89, 0x68, 0x10, 0x48, 0x89, 0x70, 0x18,
    };
    if (install_export_detour("connect", function_cast<void*>(connect_export),
                              function_cast<void*>(shim_connect), expected,
                              sizeof(expected), &connect_trampoline)) {
        real_connect = function_cast<ConnectProc>(connect_trampoline);
    }
    if (install_export_detour("WSAConnect",
                              function_cast<void*>(wsa_connect_export),
                              function_cast<void*>(shim_wsa_connect), expected,
                              sizeof(expected), &wsa_connect_trampoline)) {
        real_wsa_connect = function_cast<WsaConnectProc>(wsa_connect_trampoline);
    }
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

std::string caller_location(void* address) {
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(address), &module) ||
        !module) {
        return "unknown";
    }
    std::array<wchar_t, 32768> path{};
    const DWORD length = GetModuleFileNameW(module, path.data(),
                                            static_cast<DWORD>(path.size()));
    std::string name = length
        ? narrow(std::filesystem::path(
              std::wstring_view(path.data(), length)).filename().wstring())
        : "unknown";
    char result[512]{};
    std::snprintf(result, sizeof(result), "%s+0x%llx", name.c_str(),
                  static_cast<unsigned long long>(
                      reinterpret_cast<std::uintptr_t>(address) -
                      reinterpret_cast<std::uintptr_t>(module)));
    return result;
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

bool is_dynamic_ea_loopback_endpoint(const sockaddr* address, int length) {
    if (!address || address->sa_family != AF_INET ||
        length < static_cast<int>(sizeof(sockaddr_in))) {
        return false;
    }
    const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
    const std::uint16_t port = ntohs(ipv4->sin_port);
    const std::uint32_t host = ntohl(ipv4->sin_addr.s_addr);
    return redirect_dynamic_loopback_lsx.load(std::memory_order_acquire) &&
           (host >> 24) == 127 && port >= 1024 &&
           port != local_lsx_port.load(std::memory_order_acquire) &&
           port != 3216 && port != 6176 && port != 8216;
}

bool is_lsx_endpoint(const sockaddr* address, int length) {
    if (!address || address->sa_family != AF_INET ||
        length < static_cast<int>(sizeof(sockaddr_in))) {
        return false;
    }
    const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
    const std::uint16_t port = ntohs(ipv4->sin_port);
    // OriginSDK uses 3216 for LSX. CMain's recovered routing table maps that
    // logical port to the per-instance endpoint, while its diagnostic hook
    // observes the translated connection on 8216. Keep 6176 for older titles
    // already supported by the standalone shim.
    return port == 3216 || port == 6176 || port == 8216;
}

bool caller_is_zupdater(const std::string& location) {
    return location.starts_with("ZUpdaterx64.dll+") ||
           location.starts_with("ZUpdaterx86.dll+") ||
           location.starts_with("ZUpdater.dll+");
}

bool contains_case_insensitive(std::wstring_view value,
                               std::wstring_view needle) {
    if (needle.empty() || value.size() < needle.size()) return false;
    for (std::size_t offset = 0; offset + needle.size() <= value.size();
         ++offset) {
        if (_wcsnicmp(value.data() + offset, needle.data(), needle.size()) == 0) {
            return true;
        }
    }
    return false;
}

const char* ea_client_target(std::wstring_view value) {
    if (contains_case_insensitive(value, L"eadesktop.exe")) return "EADesktop.exe";
    if (contains_case_insensitive(value, L"ealauncher.exe")) return "EALauncher.exe";
    if (contains_case_insensitive(value, L"origin.exe")) return "Origin.exe";
    if (contains_case_insensitive(value, L"origin://")) return "origin URI";
    if (contains_case_insensitive(value, L"origin2://")) return "origin2 URI";
    if (contains_case_insensitive(value, L"link2ea://")) return "link2ea URI";
    if (contains_case_insensitive(value, L"ea://launchgame/")) return "EA launch URI";
    return nullptr;
}

const char* ea_client_target(const wchar_t* application,
                             const wchar_t* arguments) {
    if (application) {
        if (const char* target = ea_client_target(std::wstring_view(application))) {
            return target;
        }
    }
    return arguments ? ea_client_target(std::wstring_view(arguments)) : nullptr;
}

BOOL WINAPI shim_create_process_w(
    LPCWSTR application_name, LPWSTR command_line,
    LPSECURITY_ATTRIBUTES process_attributes,
    LPSECURITY_ATTRIBUTES thread_attributes, BOOL inherit_handles,
    DWORD creation_flags, LPVOID environment_block,
    LPCWSTR current_directory, LPSTARTUPINFOW startup,
    LPPROCESS_INFORMATION process_information) {
    const char* target = suppress_ea_client_launch.load(std::memory_order_acquire)
        ? ea_client_target(application_name, command_line) : nullptr;
    if (target) {
        if (!process_information || ea_client_stub_executable.empty()) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        std::wstring stub_command = L"\"" + ea_client_stub_executable +
                                    L"\" --ea-client-stub";
        std::vector<wchar_t> mutable_command(stub_command.begin(),
                                             stub_command.end());
        mutable_command.push_back(L'\0');
        DWORD stub_flags = CREATE_NO_WINDOW;
        if (creation_flags & CREATE_SUSPENDED) stub_flags |= CREATE_SUSPENDED;
        if (creation_flags & CREATE_UNICODE_ENVIRONMENT) {
            stub_flags |= CREATE_UNICODE_ENVIRONMENT;
        }
        const BOOL created = real_create_process_w(
            ea_client_stub_executable.c_str(), mutable_command.data(),
            process_attributes, thread_attributes, inherit_handles, stub_flags,
            environment_block, current_directory, startup,
            process_information);
        const DWORD error = created ? ERROR_SUCCESS : GetLastError();
        log_message(created
            ? "redirected CreateProcessW EA client launch (%s) to surrogate process %lu\r\n"
            : "EA client surrogate CreateProcessW failed (%s), error %lu\r\n",
            target, created ? process_information->dwProcessId : error);
        SetLastError(error);
        return created;
    }
    return real_create_process_w(
        application_name, command_line, process_attributes, thread_attributes,
        inherit_handles, creation_flags, environment_block, current_directory,
        startup, process_information);
}

BOOL WINAPI shim_shell_execute_ex_w(SHELLEXECUTEINFOW* info) {
    const char* target = suppress_ea_client_launch.load(std::memory_order_acquire) &&
                         info
        ? ea_client_target(info->lpFile, info->lpParameters) : nullptr;
    if (target) {
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process{};
        std::wstring stub_command = L"\"" + ea_client_stub_executable +
                                    L"\" --ea-client-stub";
        std::vector<wchar_t> mutable_command(stub_command.begin(),
                                             stub_command.end());
        mutable_command.push_back(L'\0');
        const BOOL created = !ea_client_stub_executable.empty() &&
            real_create_process_w(
                ea_client_stub_executable.c_str(), mutable_command.data(),
                nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr,
                &startup, &process);
        if (!created) {
            log_message("EA client surrogate ShellExecuteExW failed (%s), error %lu\r\n",
                        target, GetLastError());
            return FALSE;
        }
        CloseHandle(process.hThread);
        info->hInstApp = reinterpret_cast<HINSTANCE>(33);
        if (info->fMask & SEE_MASK_NOCLOSEPROCESS) {
            info->hProcess = process.hProcess;
        } else {
            CloseHandle(process.hProcess);
            info->hProcess = nullptr;
        }
        log_message(
            "redirected ShellExecuteExW EA client launch (%s) to surrogate process %lu\r\n",
            target, process.dwProcessId);
        SetLastError(ERROR_SUCCESS);
        return TRUE;
    }
    return real_shell_execute_ex_w(info);
}

sockaddr_in redirected_endpoint() {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(local_lsx_port.load(std::memory_order_acquire));
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return address;
}

const sockaddr* route_rivals_service(const sockaddr* address, int length,
                                     sockaddr_in* replacement,
                                     const std::string& caller) {
    if (!translate_rivals_ports.load(std::memory_order_acquire) ||
        !address || !replacement || address->sa_family != AF_INET ||
        length < static_cast<int>(sizeof(sockaddr_in))) {
        return address;
    }

    const auto* original = reinterpret_cast<const sockaddr_in*>(address);
    const std::uint32_t configured_address =
        service_address.load(std::memory_order_acquire);
    if (configured_address == 0 ||
        original->sin_addr.s_addr != configured_address ||
        ntohs(original->sin_port) != 42127) {
        return address;
    }

    // CMain applies its per-instance base-port offset to Rivals' logical
    // redirector port. The standalone path has no CMain, so reproduce the
    // title's only required TCP translation here: 42127 + 5000 = 47127.
    *replacement = *original;
    replacement->sin_port = htons(47127);

    probe_rivals_dirtyssl();

    char host[INET_ADDRSTRLEN]{};
    InetNtopA(AF_INET, &replacement->sin_addr, host,
              static_cast<DWORD>(sizeof(host)));
    log_message(
        "Rivals redirector intercepted %s:42127 -> %s:47127 caller=%s\r\n",
        host, host, caller.c_str());
    return reinterpret_cast<const sockaddr*>(replacement);
}

int WSAAPI shim_connect(SOCKET socket, const sockaddr* address, int length) {
    void* const return_site = _ReturnAddress();
    const std::string caller = caller_location(return_site);
    sockaddr_in service_route{};
    const sockaddr* service_endpoint = route_rivals_service(
        address, length, &service_route, caller);
    if (service_endpoint != address) {
        const int result = real_connect(
            socket, service_endpoint, sizeof(service_route));
        const int error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
        if (result == SOCKET_ERROR && error == WSAEWOULDBLOCK) {
            log_message("Rivals redirector connect pending (nonblocking socket)\r\n");
        } else {
            log_message("Rivals redirector connect result %d, WSA error %d\r\n",
                        result, error);
        }
        if (result == SOCKET_ERROR) WSASetLastError(error);
        return result;
    }
    const bool redirect = is_lsx_endpoint(address, length) ||
        (is_dynamic_ea_loopback_endpoint(address, length) &&
         !caller_is_zupdater(caller));
    if (!redirect) {
        if (address && address->sa_family == AF_INET &&
            length >= static_cast<int>(sizeof(sockaddr_in))) {
            const unsigned trace = tcp_connect_trace_count.fetch_add(
                1, std::memory_order_relaxed);
            if (trace < 64) {
                const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
                char host[INET_ADDRSTRLEN]{};
                InetNtopA(AF_INET, const_cast<IN_ADDR*>(&ipv4->sin_addr), host,
                          static_cast<DWORD>(sizeof(host)));
                log_message("connect observed %s:%u (not LSX) caller=%s\r\n", host,
                            ntohs(ipv4->sin_port), caller.c_str());
            }
        }
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
    log_message("connect intercepted %s:%u -> 127.0.0.1:%u caller=%s\r\n", host,
                ntohs(original->sin_port), ntohs(local.sin_port),
                caller.c_str());
    const int result = real_connect(
        socket, reinterpret_cast<const sockaddr*>(&local), sizeof(local));
    log_message("connect result %d, WSA error %d\r\n", result,
                result == SOCKET_ERROR ? WSAGetLastError() : 0);
    return result;
}

int WSAAPI shim_wsa_connect(SOCKET socket, const sockaddr* address, int length,
                            LPWSABUF caller, LPWSABUF callee, LPQOS send_qos,
                            LPQOS receive_qos) {
    void* const return_site = _ReturnAddress();
    const std::string return_location = caller_location(return_site);
    sockaddr_in service_route{};
    const sockaddr* service_endpoint = route_rivals_service(
        address, length, &service_route, return_location);
    if (service_endpoint != address) {
        const int result = real_wsa_connect(
            socket, service_endpoint, sizeof(service_route), caller, callee,
            send_qos, receive_qos);
        const int error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
        if (result == SOCKET_ERROR && error == WSAEWOULDBLOCK) {
            log_message("Rivals redirector WSAConnect pending (nonblocking socket)\r\n");
        } else {
            log_message("Rivals redirector WSAConnect result %d, WSA error %d\r\n",
                        result, error);
        }
        if (result == SOCKET_ERROR) WSASetLastError(error);
        return result;
    }
    const bool redirect = is_lsx_endpoint(address, length) ||
        (is_dynamic_ea_loopback_endpoint(address, length) &&
         !caller_is_zupdater(return_location));
    if (!redirect) {
        if (address && address->sa_family == AF_INET &&
            length >= static_cast<int>(sizeof(sockaddr_in))) {
            const unsigned trace = tcp_connect_trace_count.fetch_add(
                1, std::memory_order_relaxed);
            if (trace < 64) {
                const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
                char host[INET_ADDRSTRLEN]{};
                InetNtopA(AF_INET, const_cast<IN_ADDR*>(&ipv4->sin_addr), host,
                          static_cast<DWORD>(sizeof(host)));
                log_message("WSAConnect observed %s:%u (not LSX) caller=%s\r\n", host,
                            ntohs(ipv4->sin_port), return_location.c_str());
            }
        }
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
    log_message("WSAConnect intercepted port %u -> 127.0.0.1:%u caller=%s\r\n",
                ntohs(original->sin_port), ntohs(local.sin_port),
                return_location.c_str());
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

bool certificate_contains(PCCERT_CONTEXT certificate,
                          std::string_view marker) {
    if (!certificate || !certificate->pbCertEncoded ||
        certificate->cbCertEncoded < marker.size()) {
        return false;
    }
    const auto* begin = certificate->pbCertEncoded;
    const auto* end = begin + certificate->cbCertEncoded;
    return std::search(begin, end, marker.begin(), marker.end(),
                       [](unsigned char encoded, char expected) {
                           return encoded == static_cast<unsigned char>(expected);
                       }) != end;
}

bool encoded_certificate_contains(const BYTE* encoded, DWORD size,
                                  std::string_view marker) {
    if (!encoded || size < marker.size()) return false;
    const auto* end = encoded + size;
    return std::search(encoded, end, marker.begin(), marker.end(),
                       [](BYTE value, char expected) {
                           return value == static_cast<BYTE>(expected);
                       }) != end;
}

bool initialize_zlo_root_der() {
    static constexpr char base64[] =
        "MIIDYTCCAkmgAwIBAgIBATANBgkqhkiG9w0BAQUFADBqMQswCQYDVQQGEwJSVTEN"
        "MAsGA1UECBMESGVycDENMAsGA1UEBxMERGVycDEMMAoGA1UEChMDWkxPMQwwCgYD"
        "VQQLEwNaTE8xITAfBgkqhkiG9w0BCQEWEmFkbWluQHpsb2Zlbml4Lm9yZzAgFw0x"
        "NTA1MDkxMDI1MDBaGA8yMTE1MDUwOTEwMjUwMFowajELMAkGA1UEBhMCUlUxDTAL"
        "BgNVBAgTBEhlcnAxDTALBgNVBAcTBERlcnAxDDAKBgNVBAoTA1pMTzEMMAoGA1UE"
        "CxMDWkxPMSEwHwYJKoZIhvcNAQkBFhJhZG1pbkB6bG9mZW5peC5vcmcwggEiMA0G"
        "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCygj4lsFADrkmEIer9s/m0/3JbL7GQ"
        "kkHPxUfDusOXvLGUQNnnoOUhy5kUCw8otiXIcqB+jpuB6+n1lGW38sxLsxV6OaU9"
        "MGP6i/3c2WFGzhQg5FL9LyMcbRreJOAT59FYke0eElJf9WIl4IJXwts6rbDUfpQb"
        "PWK6knyuFHviCpSfrzMo0cd87ty3CYFBSrEFfJepoaCkGXfk/fefVYTRCrxB+4P0"
        "STcoYMW+fUznK4Tc3KXu5YBstZoyDxTBqcvF2zgRk9q7RBH/RxIqdohf9mJRiF5c"
        "RqGTJn976MGHX+N7rGXsxeHl6JDaK1RAbqijgkF3J5jOXQt9F9JbgIMrAgMBAAGj"
        "EDAOMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFSRVpe1AV7GGZLv"
        "CY0O1daiJpxrTfP7vS3LUfiyrgcrEwECneUCe4wokyzGzgdXATQSnySn9Upazjdi"
        "b/i/BuRDyMRpC1W6aqzNVbrSOCyFdI+e3RmFb409OWt2aSj453GHXa6Lke/HgtQx"
        "QmQ6wpU3vqyB4fiEtvMQInQHIE3fG/HKuBlwP+kLDLIo1NGOfQFmvHDRLRijVjf2"
        "+KsYCF2YELjZunVcKlz555IPaBwatqOo8qxov6DF5K83ArUAxg9sKUurCOSbselF"
        "2DGntj5ygmnkPjViVewjBpxTJwSijxg/uAhRjkxwkGJVU5WMCI23J6WkhdIjUm3h"
        "n4wkndQ=";
    if (!crypt_string_to_binary_a) return false;
    DWORD size = 0;
    if (!crypt_string_to_binary_a(base64, 0, CRYPT_STRING_BASE64,
                                  nullptr, &size, nullptr, nullptr) ||
        size != 0x365) {
        return false;
    }
    zlo_root_der.resize(size);
    return crypt_string_to_binary_a(base64, 0, CRYPT_STRING_BASE64,
                                    zlo_root_der.data(), &size,
                                    nullptr, nullptr) != FALSE;
}

bool add_zlo_root_to_store(HCERTSTORE store) {
    if (!store || zlo_root_der.empty() ||
        !real_cert_add_encoded_certificate_to_store) {
        return false;
    }
    const BOOL result = real_cert_add_encoded_certificate_to_store(
        store, X509_ASN_ENCODING, zlo_root_der.data(),
        static_cast<DWORD>(zlo_root_der.size()),
        CERT_STORE_ADD_USE_EXISTING, nullptr);
    if (result) {
        log_message("made embedded ZLO root available to the game certificate store\r\n");
    }
    return result != FALSE;
}

BOOL WINAPI shim_cert_add_encoded_certificate_to_store(
    HCERTSTORE store, DWORD encoding, const BYTE* encoded, DWORD size,
    DWORD disposition, PCCERT_CONTEXT* context) {
    const bool zlo_certificate =
        encoding == X509_ASN_ENCODING &&
        (encoded_certificate_contains(encoded, size, "admin@zlofenix.org") ||
         encoded_certificate_contains(encoded, size, "gosredirector"));
    if (zlo_certificate) add_zlo_root_to_store(store);
    const BOOL result = real_cert_add_encoded_certificate_to_store(
        store, encoding, encoded, size, disposition, context);
    if (zlo_certificate) {
        log_message("CertAddEncodedCertificateToStore observed ZLO certificate result=%d\r\n",
                    result);
    }
    return result;
}

PCCERT_CONTEXT WINAPI shim_cert_enum_certificates_in_store(
    HCERTSTORE store, PCCERT_CONTEXT previous) {
    const bool local_zlo = previous &&
        (certificate_contains(previous, "admin@zlofenix.org") ||
         certificate_contains(previous, "gosredirector"));
    if (local_zlo) {
        add_zlo_root_to_store(store);
    }
    PCCERT_CONTEXT result = real_cert_enum_certificates_in_store(store, previous);
    if (local_zlo)
        log_message("CertEnumCertificatesInStore continued local ZLO store result=%p\r\n",
                    result);
    return result;
}

PCCERT_CONTEXT WINAPI shim_cert_get_issuer_certificate_from_store(
    HCERTSTORE store, PCCERT_CONTEXT subject, PCCERT_CONTEXT previous,
    DWORD* flags) {
    PCCERT_CONTEXT result = real_cert_get_issuer_certificate_from_store(
        store, subject, previous, flags);
    if (!result && subject &&
        certificate_contains(subject, "admin@zlofenix.org")) {
        add_zlo_root_to_store(store);
        if (flags) {
            *flags &= ~(CERT_STORE_SIGNATURE_FLAG |
                        CERT_STORE_TIME_VALIDITY_FLAG |
                        CERT_STORE_REVOCATION_FLAG);
        }
        result = real_cert_get_issuer_certificate_from_store(
            store, subject, nullptr, flags);
        log_message("CertGetIssuerCertificateFromStore retried ZLO issuer result=%p flags=%#lx\r\n",
                    result, flags ? *flags : 0ul);
    }
    return result;
}

PCCERT_CONTEXT WINAPI shim_cert_find_certificate_in_store(
    HCERTSTORE store, DWORD encoding, DWORD find_flags, DWORD find_type,
    const void* find_parameter, PCCERT_CONTEXT previous) {
    const bool local_zlo = previous &&
        (certificate_contains(previous, "admin@zlofenix.org") ||
         certificate_contains(previous, "gosredirector"));
    if (local_zlo) {
        add_zlo_root_to_store(store);
    }
    PCCERT_CONTEXT result = real_cert_find_certificate_in_store(
        store, encoding, find_flags, find_type, find_parameter, previous);
    if (local_zlo)
        log_message("CertFindCertificateInStore continued local ZLO store result=%p\r\n",
                    result);
    return result;
}

bool is_zlo_redirector_chain(PCCERT_CHAIN_CONTEXT chain_context) {
    if (!chain_context) return false;
    for (DWORD chain_index = 0; chain_index < chain_context->cChain;
         ++chain_index) {
        const PCERT_SIMPLE_CHAIN chain = chain_context->rgpChain[chain_index];
        if (!chain) continue;
        for (DWORD element_index = 0; element_index < chain->cElement;
             ++element_index) {
            const PCERT_CHAIN_ELEMENT element = chain->rgpElement[element_index];
            const PCCERT_CONTEXT certificate = element
                ? element->pCertContext : nullptr;
            const bool zlo_issuer =
                certificate_contains(certificate, "ZCertMaker") ||
                certificate_contains(certificate, "admin@zlofenix.org");
            if (zlo_issuer &&
                certificate_contains(certificate, "gosredirector")) {
                return true;
            }
        }
    }
    return false;
}

DWORD clear_zlo_chain_errors(PCCERT_CHAIN_CONTEXT chain_context) {
    auto* mutable_context = const_cast<PCERT_CHAIN_CONTEXT>(chain_context);
    const DWORD original = mutable_context->TrustStatus.dwErrorStatus;
    mutable_context->TrustStatus = {};
    for (DWORD chain_index = 0; chain_index < mutable_context->cChain;
         ++chain_index) {
        PCERT_SIMPLE_CHAIN chain = mutable_context->rgpChain[chain_index];
        if (!chain) continue;
        chain->TrustStatus = {};
        for (DWORD element_index = 0; element_index < chain->cElement;
             ++element_index) {
            PCERT_CHAIN_ELEMENT element = chain->rgpElement[element_index];
            if (element) element->TrustStatus = {};
        }
    }
    return original;
}

BOOL WINAPI shim_cert_get_certificate_chain(
    HCERTCHAINENGINE engine, PCCERT_CONTEXT certificate, LPFILETIME time,
    HCERTSTORE additional_store, PCERT_CHAIN_PARA parameters, DWORD flags,
    LPVOID reserved, PCCERT_CHAIN_CONTEXT* chain_context) {
    const BOOL result = real_cert_get_certificate_chain(
        engine, certificate, time, additional_store, parameters, flags,
        reserved, chain_context);
    const DWORD error = GetLastError();
    if (result && chain_context && *chain_context &&
        is_zlo_redirector_chain(*chain_context)) {
        const DWORD trust_error = clear_zlo_chain_errors(*chain_context);
        log_message(
            "trusted local ZLO redirector certificate chain (error %#lx cleared)\r\n",
            trust_error);
    }
    SetLastError(error);
    return result;
}

BOOL WINAPI shim_cert_verify_certificate_chain_policy(
    LPCSTR policy, PCCERT_CHAIN_CONTEXT chain_context,
    PCERT_CHAIN_POLICY_PARA parameters, PCERT_CHAIN_POLICY_STATUS status) {
    const BOOL result = real_cert_verify_certificate_chain_policy(
        policy, chain_context, parameters, status);
    const DWORD error = GetLastError();
    if (result && policy == CERT_CHAIN_POLICY_SSL && status &&
        status->dwError && is_zlo_redirector_chain(chain_context)) {
        const DWORD policy_error = status->dwError;
        status->dwError = 0;
        status->lChainIndex = -1;
        status->lElementIndex = -1;
        log_message(
            "accepted local ZLO redirector certificate policy (error %#lx cleared)\r\n",
            policy_error);
    }
    SetLastError(error);
    return result;
}

NTSTATUS WINAPI shim_bcrypt_verify_signature(
    BCRYPT_KEY_HANDLE, VOID*, PUCHAR, ULONG hash_size,
    PUCHAR, ULONG signature_size, ULONG flags) {
    const unsigned trace = bcrypt_verify_signature_trace_count.fetch_add(
        1, std::memory_order_relaxed);
    if (trace < 16) {
        log_message(
            "accepted BCrypt signature hash=%lu signature=%lu flags=%#lx caller=%s\r\n",
            hash_size, signature_size, flags,
            caller_location(_ReturnAddress()).c_str());
    }
    // STATUS_SUCCESS. This is the exact CMain callback used for
    // BCryptVerifySignature and is enabled only by the standalone Rivals
    // profile; it allows DirtySSL to accept the local ZLO redirector leaf.
    return 0;
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
    if (certificate_hooks_enabled.load(std::memory_order_acquire) &&
        module == crypt32_module) {
        if (std::strcmp(name, "CertAddEncodedCertificateToStore") == 0) {
            return function_cast<FARPROC>(
                shim_cert_add_encoded_certificate_to_store);
        }
        if (std::strcmp(name, "CertGetCertificateChain") == 0) {
            return function_cast<FARPROC>(shim_cert_get_certificate_chain);
        }
        if (std::strcmp(name, "CertVerifyCertificateChainPolicy") == 0) {
            return function_cast<FARPROC>(
                shim_cert_verify_certificate_chain_policy);
        }
        if (std::strcmp(name, "CertEnumCertificatesInStore") == 0) {
            return function_cast<FARPROC>(shim_cert_enum_certificates_in_store);
        }
        if (std::strcmp(name, "CertGetIssuerCertificateFromStore") == 0) {
            return function_cast<FARPROC>(
                shim_cert_get_issuer_certificate_from_store);
        }
        if (std::strcmp(name, "CertFindCertificateInStore") == 0) {
            return function_cast<FARPROC>(shim_cert_find_certificate_in_store);
        }
    }
    if (signature_hooks_enabled.load(std::memory_order_acquire) &&
        module == bcrypt_module &&
        std::strcmp(name, "BCryptVerifySignature") == 0) {
        return function_cast<FARPROC>(shim_bcrypt_verify_signature);
    }
    if (suppress_ea_client_launch.load(std::memory_order_acquire)) {
        if (std::strcmp(name, "CreateProcessW") == 0 &&
            result == function_cast<FARPROC>(real_create_process_w)) {
            return function_cast<FARPROC>(shim_create_process_w);
        }
        if (std::strcmp(name, "ShellExecuteExW") == 0 &&
            result == function_cast<FARPROC>(real_shell_execute_ex_w)) {
            return function_cast<FARPROC>(shim_shell_execute_ex_w);
        }
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

void probe_rivals_dirtyssl() {
    bool expected = false;
    if (!dirtyssl_probe_complete.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
        return;
    }

    HMODULE image = GetModuleHandleW(nullptr);
    const auto base = reinterpret_cast<std::uintptr_t>(image);
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (!base || !readable(reinterpret_cast<void*>(base), &dos, sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
        !readable(reinterpret_cast<void*>(base + dos.e_lfanew), &nt, sizeof(nt)) ||
        nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        log_message("DirtySSL probe could not read the main image headers\r\n");
        return;
    }

    const std::uintptr_t image_end = base + nt.OptionalHeader.SizeOfImage;
    // DirtySDK's ProtoSSLControl compares the selector against the C
    // multi-character constant 'ncrt' (0x6e637274 on the target build).
    static constexpr std::array<std::uint8_t, 4> selector = {
        0x74, 0x72, 0x63, 0x6e,
    };
    static constexpr std::array<std::uint8_t, 4> reversed_selector = {
        0x6e, 0x63, 0x72, 0x74,
    };
    unsigned hits = 0;
    unsigned recognized_controls = 0;
    std::vector<std::uintptr_t> verifier_branches;
    MEMORY_BASIC_INFORMATION memory{};
    for (std::uintptr_t cursor = base;
         cursor < image_end &&
         VirtualQuery(reinterpret_cast<void*>(cursor), &memory, sizeof(memory));) {
        const std::uintptr_t region_base = std::max<std::uintptr_t>(
            cursor, reinterpret_cast<std::uintptr_t>(memory.BaseAddress));
        const std::uintptr_t region_end = std::min<std::uintptr_t>(
            image_end,
            reinterpret_cast<std::uintptr_t>(memory.BaseAddress) + memory.RegionSize);
        const DWORD protection = memory.Protect & 0xff;
        const bool executable =
            protection == PAGE_EXECUTE ||
            protection == PAGE_EXECUTE_READ ||
            protection == PAGE_EXECUTE_READWRITE ||
            protection == PAGE_EXECUTE_WRITECOPY;
        if (memory.State == MEM_COMMIT && executable &&
            !(memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
            region_end > region_base) {
            std::vector<std::uint8_t> bytes(region_end - region_base);
            SIZE_T copied = 0;
            if (ReadProcessMemory(GetCurrentProcess(),
                                  reinterpret_cast<void*>(region_base),
                                  bytes.data(), bytes.size(), &copied) &&
                copied == bytes.size()) {
                for (std::size_t offset = 0;
                     offset + selector.size() <= bytes.size(); ++offset) {
                    const bool normal = std::memcmp(
                        bytes.data() + offset, selector.data(), selector.size()) == 0;
                    const bool reversed = !normal && std::memcmp(
                        bytes.data() + offset, reversed_selector.data(),
                        reversed_selector.size()) == 0;
                    if ((!normal && !reversed) || hits >= 32) continue;

                    const std::size_t window_begin = offset > 64 ? offset - 64 : 0;
                    const std::size_t window_end = std::min<std::size_t>(
                        bytes.size(), offset + selector.size() + 96);
                    char dump[768]{};
                    std::size_t used = 0;
                    for (std::size_t index = window_begin;
                         index < window_end && used + 4 < sizeof(dump); ++index) {
                        used += static_cast<std::size_t>(std::snprintf(
                            dump + used, sizeof(dump) - used,
                            "%02x", bytes[index]));
                    }
                    const auto hit = region_base + offset;
                    static constexpr std::uint8_t control_signature[] = {
                        0x81, 0xfa, 0x74, 0x72, 0x63, 0x6e,
                        0x75, 0x0f, 0x44, 0x88, 0x81,
                        0x20, 0x03, 0x00, 0x00,
                    };
                    if (normal && offset >= 2 &&
                        offset - 2 + sizeof(control_signature) <= bytes.size() &&
                        std::memcmp(bytes.data() + offset - 2,
                                    control_signature,
                                    sizeof(control_signature)) == 0) {
                        ++recognized_controls;
                    }
                    log_message(
                        "DirtySSL selector candidate NFS14.exe+0x%llx order=%s "
                        "window_rva=0x%llx bytes=%s\r\n",
                        static_cast<unsigned long long>(hit - base),
                        normal ? "ncrt" : "reversed",
                        static_cast<unsigned long long>(
                            region_base + window_begin - base),
                        dump);
                    ++hits;
                }

                // The same build accesses bAllowAnyCert at +0x320 in its
                // server-certificate handler as:
                //   cmp byte ptr [state+0x320], 0
                //   jne accepted
                // Capture only that direct, displacement-qualified form. The
                // branch is patched only when both the control signature and
                // verifier use are unique in the executable image.
                for (std::size_t offset = 0; offset + 9 <= bytes.size(); ++offset) {
                    const auto* candidate = bytes.data() + offset;
                    const bool compare_allow_any =
                        candidate[0] == 0x80 &&
                        candidate[1] >= 0xb8 && candidate[1] <= 0xbf &&
                        candidate[2] == 0x20 && candidate[3] == 0x03 &&
                        candidate[4] == 0x00 && candidate[5] == 0x00 &&
                        candidate[6] == 0x00;
                    if (!compare_allow_any) continue;
                    const bool short_not_equal = candidate[7] == 0x75;
                    const bool near_not_equal =
                        candidate[7] == 0x0f && candidate[8] == 0x85;
                    if (!short_not_equal && !near_not_equal) continue;
                    const auto branch = region_base + offset + 7;
                    verifier_branches.push_back(branch);
                    log_message(
                        "DirtySSL allow-any verifier branch NFS14.exe+0x%llx "
                        "form=%s state_register=%u\r\n",
                        static_cast<unsigned long long>(branch - base),
                        short_not_equal ? "short" : "near",
                        static_cast<unsigned>(candidate[1] & 7));
                }
            }
        }
        if (region_end <= cursor) break;
        cursor = region_end;
    }
    log_message("DirtySSL selector probe found %u executable candidate(s)\r\n",
                hits);
    if (recognized_controls != 1 || verifier_branches.size() != 1) {
        log_message(
            "DirtySSL trust patch not applied: controls=%u verifier_branches=%zu\r\n",
            recognized_controls, verifier_branches.size());
        return;
    }

    auto* branch = reinterpret_cast<std::uint8_t*>(verifier_branches.front());
    const bool short_not_equal = branch[0] == 0x75;
    const std::size_t patch_size = short_not_equal ? 1 : 2;
    DWORD old_protection = 0;
    if (!VirtualProtect(branch, patch_size, PAGE_EXECUTE_READWRITE,
                        &old_protection)) {
        log_message("DirtySSL trust patch VirtualProtect failed (Win32 %lu)\r\n",
                    GetLastError());
        return;
    }
    if (short_not_equal) {
        branch[0] = 0xeb; // JNE rel8 -> JMP rel8
    } else {
        branch[0] = 0x90; // JNE rel32 -> NOP; JMP rel32
        branch[1] = 0xe9;
    }
    FlushInstructionCache(GetCurrentProcess(), branch, patch_size);
    DWORD ignored = 0;
    VirtualProtect(branch, patch_size, old_protection, &ignored);
    log_message(
        "patched DirtySSL allow-any-certificate branch at NFS14.exe+0x%llx\r\n",
        static_cast<unsigned long long>(
            verifier_branches.front() - base));
}

void* replacement_for(void* value) {
    if (value == reinterpret_cast<void*>(get_adapters_addresses_export)) {
        return reinterpret_cast<void*>(shim_get_adapters_addresses);
    }
    if (value == reinterpret_cast<void*>(real_get_proc_address)) {
        return reinterpret_cast<void*>(shim_get_proc_address);
    }
    if (certificate_hooks_enabled.load(std::memory_order_acquire)) {
        if (value == reinterpret_cast<void*>(
                cert_add_encoded_certificate_to_store_export)) {
            return reinterpret_cast<void*>(
                shim_cert_add_encoded_certificate_to_store);
        }
        if (value == reinterpret_cast<void*>(cert_get_certificate_chain_export)) {
            return reinterpret_cast<void*>(shim_cert_get_certificate_chain);
        }
        if (value == reinterpret_cast<void*>(
                cert_verify_certificate_chain_policy_export)) {
            return reinterpret_cast<void*>(
                shim_cert_verify_certificate_chain_policy);
        }
        if (value == reinterpret_cast<void*>(
                cert_enum_certificates_in_store_export)) {
            return reinterpret_cast<void*>(shim_cert_enum_certificates_in_store);
        }
        if (value == reinterpret_cast<void*>(
                cert_get_issuer_certificate_from_store_export)) {
            return reinterpret_cast<void*>(
                shim_cert_get_issuer_certificate_from_store);
        }
        if (value == reinterpret_cast<void*>(
                cert_find_certificate_in_store_export)) {
            return reinterpret_cast<void*>(shim_cert_find_certificate_in_store);
        }
    }
    if (signature_hooks_enabled.load(std::memory_order_acquire) &&
        value == reinterpret_cast<void*>(bcrypt_verify_signature_export)) {
        return reinterpret_cast<void*>(shim_bcrypt_verify_signature);
    }
    if (suppress_ea_client_launch.load(std::memory_order_acquire)) {
        if (value == reinterpret_cast<void*>(real_create_process_w)) {
            return reinterpret_cast<void*>(shim_create_process_w);
        }
        if (value == reinterpret_cast<void*>(real_shell_execute_ex_w)) {
            return reinterpret_cast<void*>(shim_shell_execute_ex_w);
        }
    }
    if (!network_hooks_enabled.load(std::memory_order_acquire)) return nullptr;
    if (value == reinterpret_cast<void*>(connect_export)) {
        return reinterpret_cast<void*>(shim_connect);
    }
    if (value == reinterpret_cast<void*>(wsa_connect_export)) {
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

using LdrDllNotification = void (CALLBACK*)(ULONG, const void*, void*);
using LdrRegisterDllNotificationProc = LONG (NTAPI*)(
    ULONG, LdrDllNotification, void*, void**);
void* dll_notification_cookie = nullptr;

// LDR_DLL_NOTIFICATION_DATA begins with Flags followed by the full/base-name
// UNICODE_STRING pointers, DllBase, and SizeOfImage. We only need DllBase and
// keep a local layout to remain compatible with SDKs that omit the declaration.
struct LoadedDllNotificationData {
    ULONG flags;
    const void* full_name;
    const void* base_name;
    void* dll_base;
    ULONG size_of_image;
};

void CALLBACK on_dll_notification(ULONG reason, const void* raw, void*) {
    constexpr ULONG loaded = 1;
    if (reason != loaded || !raw) return;
    const auto* data = static_cast<const LoadedDllNotificationData*>(raw);
    if (!data->dll_base || data->dll_base == shim_module) return;
    // The callback runs before the new DLL's entry point. patch_image performs
    // no module loads and only validates/updates this image's resolved pointer
    // slots, closing the OriginSDK startup race without modifying ws2_32 code.
    (void)patch_image(reinterpret_cast<std::uintptr_t>(data->dll_base));
}

void register_dll_notifications() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto procedure = ntdll
        ? GetProcAddress(ntdll, "LdrRegisterDllNotification") : nullptr;
    if (!procedure) {
        log_message("LdrRegisterDllNotification is unavailable; using image polling\r\n");
        return;
    }
    const auto register_notification =
        function_cast<LdrRegisterDllNotificationProc>(procedure);
    const LONG status = register_notification(
        0, on_dll_notification, nullptr, &dll_notification_cookie);
    log_message(status >= 0
        ? "registered DLL-load import patching\r\n"
        : "LdrRegisterDllNotification failed (NTSTATUS %08lx)\r\n",
        status);
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
        crypt32_module = GetModuleHandleW(L"crypt32.dll");
        if (!crypt32_module) crypt32_module = LoadLibraryW(L"crypt32.dll");
        bcrypt_module = GetModuleHandleW(L"bcrypt.dll");
        if (!bcrypt_module) bcrypt_module = LoadLibraryW(L"bcrypt.dll");
        kernel32_module = GetModuleHandleW(L"kernel32.dll");
        shell32_module = GetModuleHandleW(L"shell32.dll");
        if (!shell32_module) shell32_module = LoadLibraryW(L"shell32.dll");
        real_get_proc_address = function_cast<GetProcAddressProc>(
            GetProcAddress(kernel32_module, "GetProcAddress"));
        real_create_process_w = function_cast<CreateProcessWProc>(
            real_get_proc_address(kernel32_module, "CreateProcessW"));
        real_shell_execute_ex_w = function_cast<ShellExecuteExWProc>(
            real_get_proc_address(shell32_module, "ShellExecuteExW"));
        connect_export = function_cast<ConnectProc>(
            real_get_proc_address(winsock_module, "connect"));
        wsa_connect_export = function_cast<WsaConnectProc>(
            real_get_proc_address(winsock_module, "WSAConnect"));
        real_connect = connect_export;
        real_wsa_connect = wsa_connect_export;
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
        cert_get_certificate_chain_export =
            function_cast<CertGetCertificateChainProc>(
                real_get_proc_address(crypt32_module,
                                      "CertGetCertificateChain"));
        cert_verify_certificate_chain_policy_export =
            function_cast<CertVerifyCertificateChainPolicyProc>(
                real_get_proc_address(crypt32_module,
                                      "CertVerifyCertificateChainPolicy"));
        cert_add_encoded_certificate_to_store_export =
            function_cast<CertAddEncodedCertificateToStoreProc>(
                real_get_proc_address(crypt32_module,
                                      "CertAddEncodedCertificateToStore"));
        cert_enum_certificates_in_store_export =
            function_cast<CertEnumCertificatesInStoreProc>(
                real_get_proc_address(crypt32_module,
                                      "CertEnumCertificatesInStore"));
        cert_get_issuer_certificate_from_store_export =
            function_cast<CertGetIssuerCertificateFromStoreProc>(
                real_get_proc_address(crypt32_module,
                                      "CertGetIssuerCertificateFromStore"));
        cert_find_certificate_in_store_export =
            function_cast<CertFindCertificateInStoreProc>(
                real_get_proc_address(crypt32_module,
                                      "CertFindCertificateInStore"));
        crypt_string_to_binary_a = function_cast<CryptStringToBinaryAProc>(
            real_get_proc_address(crypt32_module, "CryptStringToBinaryA"));
        bcrypt_verify_signature_export =
            function_cast<BCryptVerifySignatureProc>(
                real_get_proc_address(bcrypt_module, "BCryptVerifySignature"));
        real_bind = bind_export;
        real_sendto = sendto_export;
        real_recvfrom = recvfrom_export;
        real_send = send_export;
        real_recv = recv_export;
        real_wsa_sendto = wsa_sendto_export;
        real_wsa_recvfrom = wsa_recvfrom_export;
        real_wsa_get_overlapped_result = wsa_get_overlapped_result_export;
        real_get_adapters_addresses = get_adapters_addresses_export;
        real_cert_get_certificate_chain = cert_get_certificate_chain_export;
        real_cert_verify_certificate_chain_policy =
            cert_verify_certificate_chain_policy_export;
        real_cert_add_encoded_certificate_to_store =
            cert_add_encoded_certificate_to_store_export;
        real_cert_enum_certificates_in_store =
            cert_enum_certificates_in_store_export;
        real_cert_get_issuer_certificate_from_store =
            cert_get_issuer_certificate_from_store_export;
        real_cert_find_certificate_in_store =
            cert_find_certificate_in_store_export;
        if (!connect_export || !wsa_connect_export || !bind_export ||
            !sendto_export || !recvfrom_export || !send_export || !recv_export ||
            !wsa_sendto_export ||
            !wsa_recvfrom_export || !wsa_get_overlapped_result_export ||
            !get_adapters_addresses_export ||
            !cert_get_certificate_chain_export ||
            !cert_verify_certificate_chain_policy_export ||
            !cert_add_encoded_certificate_to_store_export ||
            !cert_enum_certificates_in_store_export ||
            !cert_get_issuer_certificate_from_store_export ||
            !cert_find_certificate_in_store_export ||
            !crypt_string_to_binary_a ||
            !bcrypt_verify_signature_export ||
            !real_get_proc_address ||
            !real_create_process_w || !real_shell_execute_ex_w) {
            throw std::runtime_error("Could not resolve network entry points");
        }

        const std::wstring eaid = environment(L"EALaunchEAID");
        const std::wstring content_id = environment(L"ContentId");
        const std::string auth_token = narrow(environment(L"EALaunchUserAuthToken"));
        const std::string game_title = narrow(environment(L"ZCLIENT_GAME_TITLE"));
        const std::string configured_service_host =
            narrow(environment(L"ZCLIENT_SERVICE_HOST"));
        const std::wstring configured_stub_executable =
            environment(L"ZCLIENT_LAUNCHER_EXECUTABLE");
        const std::wstring account_text = environment(L"ZCLIENT_LSX_ACCOUNT_ID");
        const std::wstring client_token_text = environment(L"ZCLIENT_CLIENT_TOKEN");
        wchar_t* account_end = nullptr;
        const std::uint64_t account_id = account_text.empty()
            ? 2
            : _wcstoui64(account_text.c_str(), &account_end, 10);
        wchar_t* client_token_end = nullptr;
        const std::uint32_t client_token = client_token_text.empty()
            ? 0xa0000009u
            : static_cast<std::uint32_t>(_wcstoui64(
                  client_token_text.c_str(), &client_token_end, 10));
        if (eaid.empty() || content_id.empty() || auth_token.empty() || game_title.empty() ||
            (!account_text.empty() && (!account_end || *account_end)) ||
            (!client_token_text.empty() &&
             (!client_token_end || *client_token_end))) {
            throw std::runtime_error("LSX shim environment is incomplete");
        }

        const bool rivals = content_id == L"1013163";
        const bool standalone =
            environment(L"ZCLIENT_LSX_STANDALONE") == L"1";
        if (rivals) {
            in_addr parsed_service_address{};
            if (InetPtonA(AF_INET, configured_service_host.c_str(),
                          &parsed_service_address) != 1) {
                throw std::runtime_error(
                    "LSX shim service host is not an IPv4 address");
            }
            service_address.store(parsed_service_address.s_addr,
                                  std::memory_order_release);
        }
        translate_rivals_ports.store(rivals, std::memory_order_release);
        if (rivals && standalone && configured_stub_executable.empty()) {
            throw std::runtime_error("EA client surrogate executable is missing");
        }
        ea_client_stub_executable = configured_stub_executable;
        suppress_ea_client_launch.store(rivals && standalone,
                                        std::memory_order_release);
        certificate_hooks_enabled.store(rivals && standalone,
                                        std::memory_order_release);
        signature_hooks_enabled.store(rivals && standalone,
                                      std::memory_order_release);
        if (rivals && standalone) {
            if (!initialize_zlo_root_der()) {
                throw std::runtime_error("Could not decode embedded ZLO root certificate");
            }
            log_message("embedded ZLO root prepared (%zu DER bytes)\r\n",
                        zlo_root_der.size());
            log_message("Rivals EA client launch suppression enabled\r\n");
            install_certificate_detours();
            install_signature_detour();
        }

        const std::string eaid_utf8 = narrow(eaid);
        log_message("launch identity EAID=%s account=%llu\r\n",
                    eaid_utf8.c_str(),
                    static_cast<unsigned long long>(account_id));
        std::uint32_t identity_hash = 2166136261u;
        for (const unsigned char value : eaid_utf8) {
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

        // Prefer OriginSDK's historical discovery endpoint for the first
        // instance. Later local instances cannot share 127.0.0.1:3216, so
        // fall back to a per-process ephemeral listener. Each process has its
        // own connect hooks and local_lsx_port, which route that instance's
        // 3216/6176/8216 probes to the correct listener.
        constexpr std::uint16_t origin_sdk_discovery_port = 3216;
        const auto create_lsx_server = [&](std::uint16_t port) {
            return std::make_unique<LsxServer>(
                "127.0.0.1", port, eaid, content_id, auth_token, game_title,
                account_id, client_token);
        };
        try {
            server = create_lsx_server(origin_sdk_discovery_port);
        } catch (const std::runtime_error& error) {
            constexpr std::string_view address_in_use =
                "bind(LSX) failed (Winsock 10048)";
            if (std::string_view(error.what()).find(address_in_use) ==
                std::string_view::npos) {
                throw;
            }
            log_message(
                "LSX discovery port 3216 is occupied; using a per-instance listener\r\n");
            server = create_lsx_server(0);
        }
        local_lsx_port.store(server->port(), std::memory_order_release);
        publish_port(server->port());
        register_dll_notifications();
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
        redirect_dynamic_loopback_lsx.store(standalone,
                                             std::memory_order_release);
        if (standalone && !SetEvent(enable_event)) {
            throw std::runtime_error(
                "Could not enable standalone LSX shim networking");
        }
        for (;;) {
            if (!network_active &&
                WaitForSingleObject(enable_event, 0) == WAIT_OBJECT_0) {
                install_tcp_connect_detours();
                install_bind_detour();
                install_udp_trace_detours();
                network_hooks_enabled.store(true, std::memory_order_release);
                const unsigned patches = patch_loaded_images();
                log_message("network hooks enabled%s; installed %u late hooks\r\n",
                            standalone ? " (standalone)" : "", patches);
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
