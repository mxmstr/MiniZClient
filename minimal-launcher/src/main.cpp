#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <iterator>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "common.h"
#include "config.h"
#include "lsx_server.h"
#include "license_server.h"
#include "manual_map.h"
#include "pe_architecture.h"
#include "zbackend_client.h"

namespace fs = std::filesystem;

constexpr DWORD kZClientCreationFlags =
    CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT;

bool environment_key_is(std::wstring_view entry, std::wstring_view key) 
{
    return entry.size() > key.size() && entry[key.size()] == L'=' &&
           _wcsnicmp(entry.data(), key.data(), key.size()) == 0;
}

std::uint32_t make_rtp_launch_code() 
{
    SYSTEMTIME utc{};
    GetSystemTime(&utc);

    std::uint32_t value = 350377u * utc.wDay;
    value ^= 224737u * utc.wMonth;
    value ^= 104729u * utc.wYear;

    return ((value << 16) | (value >> 16)) ^ value;
}

std::vector<wchar_t> build_environment(std::wstring_view content_id,
                                       std::uint32_t game_id,
                                       std::wstring_view game_title,
                                       std::wstring_view eaid,
                                       std::wstring_view auth_token,
                                       std::uint64_t lsx_account_id,
                                       bool local_game_network,
                                       bool lsx_log,
                                       std::uint32_t* rtp_launch_code) 
{
    LPWCH raw = GetEnvironmentStringsW();
    if (!raw) fail(L"GetEnvironmentStringsW failed");

    constexpr std::wstring_view kOverriddenKeys[] = {
        L"ContentId",
        L"EAConnectionId",
        L"EALicenseToken",
        L"EALaunchEAID",
        L"EARtPLaunchCode",
        L"EALaunchUserAuthToken",
        L"EAGenericAuthToken",
        L"EALaunchCode",
        L"EAFreeTrialGame",
        L"EALaunchOfflineMode",
        L"EAGameLocale",
        L"EALaunchEnv",
        L"ZLSX",
        L"ZCLIENT_LSX_ACCOUNT_ID",
        L"ZCLIENT_GAME_TITLE",
        L"ZCLIENT_LOCAL_GAME_NETWORK",
        L"ZCLIENT_LSX_LOG",
    };

    std::vector<std::wstring> entries;
    for (const wchar_t* entry = raw; *entry; entry += wcslen(entry) + 1) 
    {
        // The recovered ZClient payload intentionally removes this compatibility shim.
        if (environment_key_is(entry, L"__COMPAT_LAYER") ||
            std::any_of(std::begin(kOverriddenKeys), std::end(kOverriddenKeys),
                        [entry](std::wstring_view key) { return environment_key_is(entry, key); })) 
        {
            continue;
        }

        entries.emplace_back(entry);
    }

    FreeEnvironmentStringsW(raw);

    const std::wstring game_id_string = std::to_wstring(game_id);
    const std::uint32_t launch_code = make_rtp_launch_code();
    if (rtp_launch_code) *rtp_launch_code = launch_code;
    entries.emplace_back(L"ContentId=" + std::wstring(content_id));
    entries.emplace_back(L"EAConnectionId=Z.GAME." + game_id_string);
    entries.emplace_back(L"EALicenseToken=" + std::wstring(auth_token) + L",Z.GAME." + game_id_string);
    entries.emplace_back(L"EALaunchEAID=" + std::wstring(eaid));
    entries.emplace_back(L"EARtPLaunchCode=" + std::to_wstring(launch_code));
    entries.emplace_back(L"EALaunchUserAuthToken=" + std::wstring(auth_token));
    entries.emplace_back(L"EAGenericAuthToken=" + std::wstring(auth_token));
    entries.emplace_back(L"EALaunchCode=HURRDURRHERPDERPZDRM");
    entries.emplace_back(L"EAFreeTrialGame=false");
    entries.emplace_back(L"EALaunchOfflineMode=false");
    entries.emplace_back(L"EAGameLocale=");
    entries.emplace_back(L"EALaunchEnv=production");
    entries.emplace_back(L"ZLSX=1");
    entries.emplace_back(L"ZCLIENT_LSX_ACCOUNT_ID=" +
                         std::to_wstring(lsx_account_id));
    entries.emplace_back(L"ZCLIENT_GAME_TITLE=" + std::wstring(game_title));
    if (local_game_network) entries.emplace_back(L"ZCLIENT_LOCAL_GAME_NETWORK=1");
    entries.emplace_back(lsx_log ? L"ZCLIENT_LSX_LOG=1" : L"ZCLIENT_LSX_LOG=0");

    // CreateProcess requires a case-insensitively sorted Unicode environment block.
    std::sort(entries.begin(), entries.end(), [](const std::wstring& left, const std::wstring& right) {
        return CompareStringOrdinal(left.c_str(), -1, right.c_str(), -1, TRUE) == CSTR_LESS_THAN;
    });

    std::vector<wchar_t> result;
    for (const std::wstring& entry : entries) 
    {
        result.insert(result.end(), entry.begin(), entry.end());
        result.push_back(L'\0');
    }

    result.push_back(L'\0');

    return result;
}

std::uint32_t derive_local_account_id(std::wstring_view eaid) 
{
    // Keep LSX's UserId/PersonaId stable for each local display name.
    std::uint32_t hash = 2166136261u;

    for (const unsigned char value : encode_utf8(eaid)) 
    {
        hash ^= value;
        hash *= 16777619u;
    }

    return (hash & 0x3fffffffu) + 0x1000u;
}

std::string make_local_auth_token(std::wstring_view eaid) 
{
    static constexpr char hex[] = "0123456789abcdef";

    const std::string utf8 = encode_utf8(eaid);
    std::string token = "ZLOCAL1:";

    token.reserve(token.size() + utf8.size() * 2);

    for (const unsigned char value : utf8) 
    {
        token.push_back(hex[value >> 4]);
        token.push_back(hex[value & 15]);
    }

    return token;
}

std::string make_instance_lsx_host(DWORD process_id)
{
    // Windows routes the complete 127.0.0.0/8 range to loopback without an
    // adapter alias. Using the launcher's PID keeps port 8216 (which CMain
    // expects) while giving every concurrently running launcher an exclusive
    // local address and therefore an independent LSX identity.
    const std::uint32_t value = static_cast<std::uint32_t>(process_id);
    return "127." + std::to_string((value >> 16) & 0xffu) + "." +
           std::to_string((value >> 8) & 0xffu) + "." +
           std::to_string(value & 0xffu);
}

void inject_library(HANDLE process, DWORD process_id, const fs::path& dll_path) 
{
    if (!fs::is_regular_file(dll_path))
        throw std::runtime_error("Game trace DLL does not exist: " + dll_path.string());

    const HMODULE local_kernel = GetModuleHandleW(L"kernel32.dll");
    const FARPROC local_load_library = GetProcAddress(local_kernel, "LoadLibraryW");
    if (!local_kernel || !local_load_library)
        fail(L"Could not resolve LoadLibraryW for game tracing");

    std::uintptr_t remote_kernel = 0;
    const ULONGLONG module_deadline = GetTickCount64() + 5000;

    while (!remote_kernel && GetTickCount64() < module_deadline) 
    {
        Handle snapshot(CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id));
        MODULEENTRY32W entry{};
        entry.dwSize = sizeof(entry);

        if (snapshot && Module32FirstW(snapshot.get(), &entry)) 
        {
            do {
                if (_wcsicmp(entry.szModule, L"KERNEL32.DLL") == 0) {
                    remote_kernel = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
                    break;
                }
            } while (Module32NextW(snapshot.get(), &entry));
        }

        if (!remote_kernel) 
        {
            if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) break;
            Sleep(10);
        }
    }

    if (!remote_kernel)
        fail(L"Could not locate remote kernel32.dll for game tracing");

    const std::wstring path = fs::absolute(dll_path).wstring();
    const SIZE_T size = (path.size() + 1) * sizeof(wchar_t);
    void* remote_path = VirtualAllocEx(process, nullptr, size,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remote_path) fail(L"VirtualAllocEx(game trace path) failed");

    struct FreeRemote 
    {
        HANDLE process;
        void* address;
        ~FreeRemote() { if (address) VirtualFreeEx(process, address, 0, MEM_RELEASE); }
    } free_remote{process, remote_path};

    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote_path, path.c_str(), size, &written) || written != size)
        fail(L"WriteProcessMemory(game trace path) failed");

    const auto remote_load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        remote_kernel + reinterpret_cast<std::uintptr_t>(local_load_library) -
        reinterpret_cast<std::uintptr_t>(local_kernel));
    Handle thread(CreateRemoteThread(process, nullptr, 0, remote_load_library,
                                     remote_path, 0, nullptr));

    if (!thread) fail(L"CreateRemoteThread(game trace) failed");

    if (WaitForSingleObject(thread.get(), 15000) != WAIT_OBJECT_0) {
        throw std::runtime_error("Timed out injecting the game trace DLL.");
    }

    DWORD result = 0;
    if (!GetExitCodeThread(thread.get(), &result) || !result) {
        throw std::runtime_error("LoadLibraryW rejected the game trace DLL.");
    }

    std::wcout << L"Injected game tracer: " << path << L"\n";
}

std::wstring quote_argument(std::wstring_view argument) 
{
    std::wstring result = L"\"";
    std::size_t slashes = 0;

    for (const wchar_t ch : argument) 
    {
        if (ch == L'\\') 
        {
            ++slashes;
            continue;
        }

        if (ch == L'\"') 
        {
            result.append(slashes * 2 + 1, L'\\');
            result.push_back(ch);
            slashes = 0;
            continue;
        }

        result.append(slashes, L'\\');
        slashes = 0;
        result.push_back(ch);
    }

    result.append(slashes * 2, L'\\');
    result.push_back(L'\"');
    return result;
}

void run_x86_injector(const fs::path& injector, const fs::path& working_directory,
                      DWORD process_id, DWORD thread_id,
                      const fs::path& bootstrap, const std::string& service_host,
                      const std::string& lsx_host,
                      const std::string& instance_name)
{
    std::wstring command_line = quote_argument(fs::absolute(injector).wstring());
    const auto append = [&command_line](std::wstring_view value)
    {
        command_line.push_back(L' ');
        command_line += quote_argument(value);
    };
    append(std::to_wstring(process_id));
    append(std::to_wstring(thread_id));
    append(fs::absolute(bootstrap).wstring());
    append(std::wstring(service_host.begin(), service_host.end()));
    append(std::wstring(lsx_host.begin(), lsx_host.end()));
    append(std::wstring(instance_name.begin(), instance_name.end()));

    std::vector<wchar_t> mutable_command(command_line.begin(), command_line.end());
    mutable_command.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION info{};
    const std::wstring directory = working_directory.wstring();
    if (!CreateProcessW(fs::absolute(injector).c_str(), mutable_command.data(),
                        nullptr, nullptr, FALSE, CREATE_UNICODE_ENVIRONMENT,
                        nullptr, directory.c_str(), &startup, &info))
    {
        fail(L"CreateProcessW(zclient_injector32) failed");
    }
    Handle helper_process(info.hProcess);
    Handle helper_thread(info.hThread);
    const DWORD wait = WaitForSingleObject(helper_process.get(), 120000);
    if (wait != WAIT_OBJECT_0)
    {
        if (wait == WAIT_TIMEOUT)
        {
            TerminateProcess(helper_process.get(), 1);
            throw std::runtime_error("Timed out waiting for zclient_injector32.");
        }
        fail(L"WaitForSingleObject(zclient_injector32) failed");
    }
    DWORD exit_code = 1;
    if (!GetExitCodeProcess(helper_process.get(), &exit_code))
    {
        fail(L"GetExitCodeProcess(zclient_injector32) failed");
    }
    if (exit_code != 0)
    {
        throw std::runtime_error(
            "zclient_injector32 failed with exit code " +
            std::to_string(exit_code) + ".");
    }
}

void launch_x86_activation_monitor(const fs::path& injector,
                                   const fs::path& working_directory,
                                   DWORD process_id)
{
    const std::wstring ready_event_name =
        L"Local\\ZClientActivationReady_" + std::to_wstring(GetCurrentProcessId()) +
        L"_" + std::to_wstring(process_id);
    Handle ready_event(CreateEventW(nullptr, TRUE, FALSE,
                                    ready_event_name.c_str()));
    if (!ready_event)
    {
        fail(L"CreateEventW(activation monitor ready event) failed");
    }

    std::wstring command_line = quote_argument(fs::absolute(injector).wstring());
    command_line += L" --monitor-activation ";
    command_line += quote_argument(std::to_wstring(process_id));
    command_line.push_back(L' ');
    command_line += quote_argument(ready_event_name);

    std::vector<wchar_t> mutable_command(command_line.begin(), command_line.end());
    mutable_command.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION info{};
    const std::wstring directory = working_directory.wstring();
    if (!CreateProcessW(fs::absolute(injector).c_str(), mutable_command.data(),
                        nullptr, nullptr, FALSE, CREATE_UNICODE_ENVIRONMENT,
                        nullptr, directory.c_str(), &startup, &info))
    {
        fail(L"CreateProcessW(activation monitor) failed");
    }
    Handle helper_process(info.hProcess);
    Handle helper_thread(info.hThread);
    std::cout << "[activation-patch] launched child monitor for process "
              << process_id << '\n';

    const HANDLE waits[] = {ready_event.get(), helper_process.get()};
    const DWORD wait = WaitForMultipleObjects(
        static_cast<DWORD>(std::size(waits)), waits, FALSE, 10000);
    if (wait == WAIT_OBJECT_0)
    {
        std::cout << "[activation-patch] child monitor attached to process "
                  << process_id << '\n';
        return;
    }
    if (wait == WAIT_OBJECT_0 + 1)
    {
        DWORD exit_code = 1;
        GetExitCodeProcess(helper_process.get(), &exit_code);
        throw std::runtime_error(
            "activation monitor exited before attaching (exit code " +
            std::to_string(exit_code) + ").");
    }
    if (wait == WAIT_TIMEOUT)
    {
        throw std::runtime_error(
            "timed out waiting for the activation monitor to attach.");
    }
    fail(L"WaitForMultipleObjects(activation monitor) failed");
}

int wmain(int argc, wchar_t** argv) 
{
    try 
    {
        const Options options = parse_options(argc, argv);
        if (!fs::is_regular_file(options.game))
            throw std::runtime_error("Game executable does not exist: " + options.game.string());
        const PeArchitecture game_architecture = inspect_pe_architecture(options.game);
        std::cout << "Game architecture: "
                  << pe_architecture_name(game_architecture) << '\n';
        if (!fs::is_regular_file(options.bootstrap_x86))
            throw std::runtime_error("CLoaderx32.dll does not exist; pass --bootstrap-x86 <path>.");
        if (!fs::is_regular_file(options.bootstrap))
            throw std::runtime_error("CLoaderx64.dll does not exist; pass --bootstrap <path>.");
        if (inspect_pe_architecture(options.bootstrap_x86) != PeArchitecture::i386)
            throw std::runtime_error("--bootstrap-x86 must name an I386 PE32 image.");
        if (inspect_pe_architecture(options.bootstrap) != PeArchitecture::amd64)
            throw std::runtime_error("--bootstrap must name an AMD64 PE32+ image.");
        if (game_architecture == PeArchitecture::i386 &&
            !fs::is_regular_file(options.injector_x86))
            throw std::runtime_error(
                "32-bit initial games require zclient_injector32.exe; pass --injector-x86 <path>.");
        if (game_architecture == PeArchitecture::i386 &&
            inspect_pe_architecture(options.injector_x86) != PeArchitecture::i386)
            throw std::runtime_error("--injector-x86 must name an I386 PE32 executable.");
        if (game_architecture == PeArchitecture::amd64 &&
            !fs::is_regular_file(options.lsx_shim))
            throw std::runtime_error("ZClient.LsxShim64.dll does not exist; pass --lsx-shim <path>.");
        if (game_architecture == PeArchitecture::i386 &&
            !options.trace_game_dll.empty())
            throw std::runtime_error(
                "The configured game tracer is x64-only and cannot be injected into a 32-bit game.");

        std::unique_ptr<ZBackendClient> backend;
        std::wstring effective_eaid = options.eaid;

        if (!options.zbackend_endpoint.empty()) 
        {
            backend = std::make_unique<ZBackendClient>(
                options.zbackend_endpoint, options.eaid, options.zbackend_digest);
            effective_eaid = backend->display_name();
        }

        const std::uint64_t lsx_account_id = options.account_id != 0
            ? options.account_id
            : derive_local_account_id(effective_eaid);
        const std::string auth_token = make_local_auth_token(effective_eaid);
        const std::wstring auth_token_wide(auth_token.begin(), auth_token.end());

        constexpr char kBase36[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        std::uint32_t instance_value = GetCurrentProcessId();
        std::string instance_name(7, '0');

        for (auto cursor = instance_name.rbegin(); cursor != instance_name.rend(); ++cursor) 
        {
            *cursor = kBase36[instance_value % 36];
            instance_value /= 36;
        }

        const std::wstring instance_name_w(instance_name.begin(), instance_name.end());
        const std::wstring pipe_name = L"\\\\.\\pipe\\" + instance_name_w;
        // The game and every CLoader-created child stay in the same Windows
        // session, so session-local mappings are sufficient and do not require
        // SeCreateGlobalPrivilege. The extra leading zero preserves the byte
        // length of CLoader's original Global\\ZClient_* literals.
        const std::wstring x86_mapping_name = L"Local\\0" + instance_name_w + L"_CLoaderx32";
        const std::wstring x64_mapping_name = L"Local\\0" + instance_name_w + L"_CLoaderx64";
        
        std::wcout << L"Launch namespace: " << instance_name_w << L'\n';

        std::unique_ptr<LsxServer> x86_lsx_server;
        std::unique_ptr<LicenseReplayServer> license_server;
        std::string x86_lsx_host = options.lsx_host;
        if (game_architecture == PeArchitecture::i386)
        {
            x86_lsx_host = make_instance_lsx_host(GetCurrentProcessId());
            // CMainx32 is redirected to the legacy LSX port by the Win32
            // injector. A per-launcher loopback address lets multiple games
            // retain distinct EA identities while all continue using 8216.
            x86_lsx_server = std::make_unique<LsxServer>(
                x86_lsx_host, 8216, effective_eaid, options.content_id,
                auth_token, encode_utf8(options.game_title), lsx_account_id);
        }
        if (!options.license_response.empty())
        {
            if (!fs::is_regular_file(options.license_response))
                throw std::runtime_error(
                    "Activation license response does not exist: " +
                    options.license_response.string());
            license_server = std::make_unique<LicenseReplayServer>(
                options.license_response, options.license_signature);
        }

        std::function<void(DWORD)> activation_process_callback;
        if (game_architecture == PeArchitecture::i386)
        {
            activation_process_callback = [&](DWORD process_id)
            {
                launch_x86_activation_monitor(
                    options.injector_x86, options.game.parent_path(), process_id);
            };
        }

        ZClientPipeHost pipe_host(options.client_token, pipe_name,
                                  options.game_executable, options.module_id,
                                  options.game_module_id, options.activation_executable,
                                  options.activation_module_id,
                                  std::move(activation_process_callback));
        pipe_host.start();


        // Some games start an x86 activation child. CLoader expects its raw PE
        // image in this shared, length-prefixed mapping before it can inject it.
        const auto x86_loader_image = prepare_zclient_loader_names_only(
            options.bootstrap_x86, instance_name);
        SharedImageMapping x86_loader_map(x86_mapping_name.c_str(),
                                          x86_loader_image);
        std::wcout << L"Published x86 child bootstrap: "
                   << fs::absolute(options.bootstrap_x86).wstring() 
                   << L"\n";


        // CLoader's process-creation hooks use the shared x64 image for later
        // x64 children. The initial game bootstrap is mapped directly below.
        const auto x64_loader_image = prepare_zclient_loader_image(
            options.bootstrap, options.service_host, instance_name);
        SharedImageMapping x64_loader_map(x64_mapping_name.c_str(),
                                          x64_loader_image);
        std::wcout << L"Published x64 child bootstrap: "
                   << fs::absolute(options.bootstrap).wstring() 
                   << L"\n";


        // CMain does not enable its LSX socket send/receive hooks from ZLSX alone.
        // It also checks for this marker beside the game executable during ZLO
        // initialization. Without it the game reaches its window/message loop but
        // never exchanges the Origin LSX handshake and remains on a black screen.
        ScopedMarkerFile lsx_marker(options.game.parent_path() / L"z1.dev");
        std::wcout << L"CMain LSX marker "
                   << (lsx_marker.created() ? L"created: " : L"already present: ")
                   << (options.game.parent_path() / L"z1.dev").wstring() 
                   << L"\n";


        std::wstring command_line = quote_argument(options.game.wstring());
        if (!options.data_path.empty()) 
        {
            command_line += L" -dataPath ";
            command_line += quote_argument(options.data_path.wstring());
            std::wcout << L"Frosty data path: " << options.data_path.wstring() << L'\n';
        }
        
        const std::vector<std::wstring> bf3_arguments =
            make_bf3_launch_arguments(options.bf3_launch, lsx_account_id);
        if (!bf3_arguments.empty())
        {
            std::wcout << L"BF3 Battlelog launch: "
                       << (options.bf3_launch.mode == Bf3LaunchMode::singleplayer
                               ? L"singleplayer"
                               : L"multiplayer server " + options.bf3_launch.server_id)
                       << L", persona " << lsx_account_id << L'\n';
        }

        for (const std::wstring& argument : bf3_arguments)
        {
            command_line.push_back(L' ');
            command_line += quote_argument(argument);
        }

        for (const std::wstring& argument : options.game_arguments)
        {
            command_line.push_back(L' ');
            command_line += quote_argument(argument);
        }
        
        std::vector<wchar_t> mutable_command(command_line.begin(), command_line.end());
        mutable_command.push_back(L'\0');
        std::uint32_t rtp_launch_code = 0;
        std::vector<wchar_t> environment = build_environment(
            options.content_id, options.game_id, options.game_title,
            effective_eaid, auth_token_wide,
            lsx_account_id, options.local_game_network, options.lsx_log,
            &rtp_launch_code);
        std::wcout << L"EA launch environment: ContentId " << options.content_id
                   << L", game " << options.game_id << L", EAID " << effective_eaid
                   << L", account " << lsx_account_id
                   << L", RtP code " << rtp_launch_code 
                   << L"\n";
        
        if (options.local_game_network) 
            std::wcout << L"Local multi-instance game network isolation enabled\n";

        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION info{};
        DWORD flags = kZClientCreationFlags;
        if (options.breakaway) flags |= CREATE_BREAKAWAY_FROM_JOB;

        const std::wstring working_directory = options.game.parent_path().wstring();
        if (!CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr, FALSE, flags,
                            environment.data(), working_directory.c_str(), &startup, &info)) 
        {
            fail(L"CreateProcessW failed");
        }


        Handle process(info.hProcess);
        Handle primary_thread(info.hThread);
        bool resumed = false;

        struct KillOnFailure 
        {
            HANDLE process;
            bool* resumed;
            ~KillOnFailure() 
            {
                if (!*resumed) TerminateProcess(process, 1);
            }
        } kill_on_failure{process.get(), &resumed};

        Handle job(CreateJobObjectW(nullptr, nullptr));
        if (!job) fail(L"CreateJobObjectW failed");

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
            fail(L"SetInformationJobObject failed");
        if (!AssignProcessToJobObject(job.get(), process.get()))
            fail(L"AssignProcessToJobObject failed");

        std::wcout << L"Created suspended process " << info.dwProcessId << L"\n";
        if (game_architecture == PeArchitecture::i386)
        {
            std::wcout << L"Mapping CLoaderx32 with the native Win32 injector...\n";
            run_x86_injector(
                options.injector_x86, options.game.parent_path(),
                info.dwProcessId, info.dwThreadId, options.bootstrap_x86,
                options.service_host, x86_lsx_host, instance_name);
        }
        else
        {
            std::wcout << L"Mapping CLoaderx64 into the suspended game...\n";
            (void)manual_map_zclient_loader(
                process.get(), primary_thread.get(), info.dwProcessId,
                options.bootstrap, options.service_host, options.lsx_host,
                instance_name, options.lsx_shim);
        }

        // sleep for 10 seconds
        //std::this_thread::sleep_for(std::chrono::seconds(10));

        resumed = true;
        std::wcout << L"Resumed " << options.game.filename().wstring() << L'\n';
        // A CREATE_SUSPENDED process has not run LdrInitializeThunk yet, so
        // kernel32.dll is not guaranteed to be present for LoadLibrary-based
        // injection. CLoader returns immediately after releasing its entry
        // gate; inject here, before the later Origin LSX/Blaze initialization.
        if (!options.trace_game_dll.empty())
            inject_library(process.get(), info.dwProcessId, options.trace_game_dll);

        // Keep the job handle and the launcher-owned loader context alive until
        // the game exits, matching ZClient's ownership model.
        for (;;) 
        {
            const DWORD wait = WaitForSingleObject(process.get(), 1);
            if (wait == WAIT_OBJECT_0) break;
            if (wait == WAIT_FAILED) fail(L"WaitForSingleObject(game) failed");
        }
        DWORD exit_code = 0;
        GetExitCodeProcess(process.get(), &exit_code);

        std::wcout << options.game.filename().wstring() 
                   << L" exited with code "
                   << exit_code 
                   << L"\n";

        return static_cast<int>(exit_code);
    } 
    catch (const std::exception& error) 
    {
        std::cerr << "launcher: " << error.what() << '\n';
        return 1;
    }
}
