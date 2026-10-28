#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

template <typename To, typename From>
To function_cast(From value) {
    static_assert(sizeof(To) == sizeof(From));
    To result{};
    std::memcpy(&result, &value, sizeof(result));
    return result;
}

using GetAdaptersAddressesProc = ULONG (WINAPI*)(
    ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);
GetAdaptersAddressesProc cached_get_adapters_addresses = &GetAdaptersAddresses;

bool verify_redirect(std::uint16_t port) {
    SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET) return false;

    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(port);
    InetPtonA(AF_INET, "203.0.113.1", &destination.sin_addr);
    if (connect(client, reinterpret_cast<const sockaddr*>(&destination),
                sizeof(destination)) == SOCKET_ERROR) {
        std::cerr << "connect to logical LSX port " << port
                  << " failed: " << WSAGetLastError() << '\n';
        closesocket(client);
        return false;
    }

    char buffer[1024]{};
    const int received = recv(client, buffer, sizeof(buffer), 0);
    closesocket(client);
    if (received <= 0) return false;
    const std::string challenge(buffer, static_cast<std::size_t>(received));
    return challenge.find("<Challenge key=") != std::string::npos;
}

std::uint32_t identity_id_for(std::string_view name) {
    std::uint32_t hash = 2166136261u;
    for (const unsigned char value : name) {
        hash ^= value;
        hash *= 16777619u;
    }
    return (hash & 0x3fffffffu) + 0x1000u;
}

std::uint16_t game_port_for(std::string_view name) {
    const std::uint32_t identity_id = identity_id_for(name);
    return static_cast<std::uint16_t>(20000u + identity_id % 40000u);
}

std::array<unsigned char, 6> machine_address_for(std::string_view name) {
    const std::uint32_t identity_id = identity_id_for(name);
    return {
        0x02, 0x5a,
        static_cast<unsigned char>(identity_id >> 24),
        static_cast<unsigned char>(identity_id >> 16),
        static_cast<unsigned char>(identity_id >> 8),
        static_cast<unsigned char>(identity_id),
    };
}

bool verify_machine_identity_with(GetAdaptersAddressesProc get_adapters,
                                  const char* source) {
    if (!get_adapters) return false;

    ULONG size = 0;
    ULONG result = get_adapters(AF_UNSPEC, 0, nullptr, nullptr, &size);
    if (result != ERROR_BUFFER_OVERFLOW || size == 0) return false;
    std::vector<unsigned char> storage(size);
    auto* addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(storage.data());
    result = get_adapters(AF_UNSPEC, 0, nullptr, addresses, &size);
    if (result != NO_ERROR) return false;

    const auto expected = machine_address_for("shim-test");
    unsigned checked = 0;
    for (auto* adapter = addresses; adapter; adapter = adapter->Next) {
        if (adapter->PhysicalAddressLength < expected.size()) continue;
        if (std::memcmp(adapter->PhysicalAddress, expected.data(),
                        expected.size()) != 0) {
            std::cerr << source
                      << " adapter physical address was not virtualized\n";
            return false;
        }
        ++checked;
    }
    return checked != 0;
}

bool verify_machine_identity() {
    HMODULE iphlpapi = LoadLibraryW(L"iphlpapi.dll");
    if (!iphlpapi) return false;
    const auto dynamically_resolved = function_cast<GetAdaptersAddressesProc>(
        GetProcAddress(iphlpapi, "GetAdaptersAddresses"));
    return verify_machine_identity_with(dynamically_resolved, "dynamic") &&
           verify_machine_identity_with(&GetAdaptersAddresses, "import") &&
           verify_machine_identity_with(cached_get_adapters_addresses, "cached");
}

bool verify_game_bind() {
    SOCKET game = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (game == INVALID_SOCKET) return false;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(3659);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(game, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) ==
        SOCKET_ERROR) {
        std::cerr << "game bind failed: " << WSAGetLastError() << '\n';
        closesocket(game);
        return false;
    }
    int length = sizeof(address);
    const std::uint32_t expected_ip =
        htonl(0x7f000000u | game_port_for("shim-test"));
    bool ok = getsockname(game, reinterpret_cast<sockaddr*>(&address), &length) == 0 &&
              ntohs(address.sin_port) == game_port_for("shim-test") &&
              address.sin_addr.s_addr == expected_ip;
    if (!ok) {
        std::cerr << "game bind used port " << ntohs(address.sin_port)
                  << " instead of " << game_port_for("shim-test") << '\n';
    }

    SOCKET peer = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in peer_address{};
    peer_address.sin_family = AF_INET;
    peer_address.sin_port = htons(21000);
    peer_address.sin_addr.s_addr = htonl(INADDR_ANY);
    int timeout = 1000;
    setsockopt(game, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    int peer_length = sizeof(peer_address);
    if (peer == INVALID_SOCKET ||
        bind(peer, reinterpret_cast<const sockaddr*>(&peer_address),
             sizeof(peer_address)) == SOCKET_ERROR ||
        getsockname(peer, reinterpret_cast<sockaddr*>(&peer_address),
                    &peer_length) == SOCKET_ERROR) {
        ok = false;
    } else {
        peer_address.sin_addr.s_addr = htonl(0xc6120000u | 21000u);
        static constexpr char ping[] = "ping";
        char buffer[16]{};
        sockaddr_in source{};
        int source_length = sizeof(source);
        ok = ok && sendto(game, ping, sizeof(ping), 0,
                          reinterpret_cast<const sockaddr*>(&peer_address),
                          sizeof(peer_address)) == sizeof(ping) &&
             recvfrom(peer, buffer, sizeof(buffer), 0,
                      reinterpret_cast<sockaddr*>(&source), &source_length) == sizeof(ping) &&
             source.sin_addr.s_addr == expected_ip &&
             sendto(peer, ping, sizeof(ping), 0,
                    reinterpret_cast<const sockaddr*>(&source), source_length) == sizeof(ping) &&
             recvfrom(game, buffer, sizeof(buffer), 0,
                      reinterpret_cast<sockaddr*>(&source), &source_length) == sizeof(ping) &&
             source.sin_addr.s_addr == htonl(0xc6120000u | 21000u);

        WSAOVERLAPPED overlapped{};
        overlapped.hEvent = WSACreateEvent();
        WSABUF receive_buffer{sizeof(buffer), buffer};
        DWORD received = 0;
        DWORD receive_flags = 0;
        source = {};
        source_length = sizeof(source);
        const int receive_result = WSARecvFrom(
            game, &receive_buffer, 1, &received, &receive_flags,
            reinterpret_cast<sockaddr*>(&source), &source_length,
            &overlapped, nullptr);
        const bool receive_pending = receive_result == SOCKET_ERROR &&
                                     WSAGetLastError() == WSA_IO_PENDING;
        ok = ok && overlapped.hEvent != WSA_INVALID_EVENT && receive_pending &&
             sendto(peer, ping, sizeof(ping), 0,
                    reinterpret_cast<const sockaddr*>(&address), sizeof(address)) ==
                 sizeof(ping) &&
             WSAWaitForMultipleEvents(1, &overlapped.hEvent, TRUE, 1000, FALSE) ==
                 WSA_WAIT_EVENT_0 &&
             WSAGetOverlappedResult(game, &overlapped, &received, TRUE,
                                    &receive_flags) &&
             received == sizeof(ping) &&
             source.sin_addr.s_addr == htonl(0xc6120000u | 21000u);
        if (overlapped.hEvent != WSA_INVALID_EVENT) {
            WSACloseEvent(overlapped.hEvent);
        }
    }
    if (peer != INVALID_SOCKET) closesocket(peer);
    closesocket(game);
    return ok;
}

int wmain() {
    SetEnvironmentVariableW(L"EALaunchEAID", L"shim-test");
    SetEnvironmentVariableW(L"ContentId", L"test-content");
    SetEnvironmentVariableW(L"ZCLIENT_GAME_TITLE", L"Shim Test Game");
    SetEnvironmentVariableW(L"EALaunchUserAuthToken", L"ZLOCAL1:7368696d2d74657374");
    SetEnvironmentVariableW(L"ZCLIENT_LSX_ACCOUNT_ID", L"42");
    SetEnvironmentVariableW(L"ZCLIENT_LOCAL_GAME_NETWORK", L"1");
    SetEnvironmentVariableW(L"ZCLIENT_LSX_LOG", L"0");

    const std::wstring ready_name = L"Local\\ZClient_LsxShimReady_" +
                                    std::to_wstring(GetCurrentProcessId());
    HANDLE ready = CreateEventW(nullptr, TRUE, FALSE, ready_name.c_str());
    if (!ready) return 1;

    HMODULE winsock = GetModuleHandleW(L"ws2_32.dll");
    const FARPROC connect_before_shim =
        winsock ? GetProcAddress(winsock, "connect") : nullptr;
    if (!connect_before_shim) return 2;

    wchar_t executable[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, executable, MAX_PATH)) return 3;
    const fs::path shim = fs::path(executable).parent_path() /
                          L"ZClient.LsxShim64.dll";
    const fs::path unexpected_log = fs::path(executable).parent_path() /
        (L"ZClient.LsxShim-" + std::to_wstring(GetCurrentProcessId()) + L".log");
    HMODULE module = LoadLibraryW(shim.c_str());
    if (!module) return 4;
    if (WaitForSingleObject(ready, 10000) != WAIT_OBJECT_0) return 5;
    if (fs::exists(unexpected_log)) return 9;
    CloseHandle(ready);

    // The early phase must virtualize machine identity before CLoader/ZLO run,
    // while leaving the Winsock hooks disabled until the launcher explicitly
    // activates them after ZLO.
    const bool virtual_machine_identity = verify_machine_identity();
    const bool winsock_still_original =
        GetProcAddress(winsock, "connect") == connect_before_shim;
    const std::wstring process_suffix = std::to_wstring(GetCurrentProcessId());
    const std::wstring enable_name =
        L"Local\\ZClient_LsxShimEnableNetwork_" + process_suffix;
    const std::wstring network_ready_name =
        L"Local\\ZClient_LsxShimNetworkReady_" + process_suffix;
    HANDLE enable_network = OpenEventW(EVENT_MODIFY_STATE, FALSE,
                                       enable_name.c_str());
    HANDLE network_ready = OpenEventW(SYNCHRONIZE, FALSE,
                                      network_ready_name.c_str());
    if (!virtual_machine_identity || !winsock_still_original ||
        !enable_network || !network_ready ||
        !SetEvent(enable_network) ||
        WaitForSingleObject(network_ready, 10000) != WAIT_OBJECT_0) {
        if (enable_network) CloseHandle(enable_network);
        if (network_ready) CloseHandle(network_ready);
        return 6;
    }
    const bool winsock_was_activated =
        GetProcAddress(winsock, "connect") != connect_before_shim;
    CloseHandle(enable_network);
    CloseHandle(network_ready);

    WSADATA data{};
    if (!winsock_was_activated || WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        return 7;
    }
    const bool redirected_6176 = verify_redirect(6176);
    const bool redirected_8216 = verify_redirect(8216);
    const bool redirected_game_port = verify_game_bind();
    WSACleanup();
    if (!redirected_6176 || !redirected_8216 || !redirected_game_port ||
        !virtual_machine_identity) return 8;
    std::cout << "LSX shim redirected LSX, isolated UDP, and virtualized the machine identity\n";
    return 0;
}
