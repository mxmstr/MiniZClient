#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "common.h"

#ifdef _WIN64
#error zclient_injector32 must be compiled as a native Win32 executable
#endif

namespace {

namespace fs = std::filesystem;

struct Arguments {
    bool monitor_activation = false;
    DWORD process_id = 0;
    DWORD thread_id = 0;
    fs::path bootstrap;
    std::string service_host;
    std::string lsx_host;
    std::string instance_name;
    std::wstring ready_event_name;
};

std::uint32_t parse_u32(std::wstring_view value, const char* name) {
    std::size_t consumed = 0;
    const unsigned long parsed = std::stoul(std::wstring(value), &consumed, 0);
    if (consumed != value.size() || !parsed || parsed > UINT32_MAX) {
        throw std::runtime_error(std::string(name) + " must be a nonzero uint32 value.");
    }
    return static_cast<std::uint32_t>(parsed);
}

Arguments parse_arguments(int argc, wchar_t** argv) {
    if (argc == 4 && std::wstring_view(argv[1]) == L"--monitor-activation") {
        Arguments result;
        result.monitor_activation = true;
        result.process_id = parse_u32(argv[2], "pid");
        result.ready_event_name = argv[3];
        return result;
    }
    if (argc != 7) {
        throw std::runtime_error(
            "Usage: zclient_injector32 <pid> <tid> <CLoaderx32.dll> "
            "<service IPv4> <LSX IPv4> <seven-character namespace>\n"
            "   or: zclient_injector32 --monitor-activation <pid> <ready-event>");
    }

    Arguments result;
    result.process_id = parse_u32(argv[1], "pid");
    result.thread_id = parse_u32(argv[2], "tid");
    result.bootstrap = fs::absolute(argv[3]);
    result.service_host = encode_utf8(argv[4]);
    result.lsx_host = encode_utf8(argv[5]);
    result.instance_name = encode_utf8(argv[6]);
    if (result.instance_name.size() != 7) {
        throw std::runtime_error("The CLoader namespace must contain seven characters.");
    }
    return result;
}

std::vector<std::uint8_t> read_file(const fs::path& path) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) {
        throw std::runtime_error("Could not open x86 bootstrap image: " + path.string());
    }
    const std::streamoff end = stream.tellg();
    if (end <= 0 || static_cast<std::uintmax_t>(end) >
                        std::numeric_limits<std::size_t>::max()) {
        throw std::runtime_error("x86 bootstrap image has an invalid size.");
    }
    std::vector<std::uint8_t> result(static_cast<std::size_t>(end));
    stream.seekg(0);
    if (!stream.read(reinterpret_cast<char*>(result.data()),
                     static_cast<std::streamsize>(result.size()))) {
        throw std::runtime_error("Could not read x86 bootstrap image.");
    }
    return result;
}

template <typename T>
T* at(std::vector<std::uint8_t>& image, std::size_t offset) {
    if (offset > image.size() || sizeof(T) > image.size() - offset) {
        throw std::runtime_error("Malformed x86 bootstrap: RVA is out of range.");
    }
    return reinterpret_cast<T*>(image.data() + offset);
}

void patch_loader_instance_names(std::vector<std::uint8_t>& image,
                                 const std::string& instance_name) {
    const std::array<std::pair<std::string_view, std::string>, 3> replacements{{
        {"\\\\.\\pipe\\ZClient", "\\\\.\\pipe\\" + instance_name},
        {"Global\\ZClient_CLoaderx64", "Local\\0" + instance_name + "_CLoaderx64"},
        {"Global\\ZClient_CLoaderx32", "Local\\0" + instance_name + "_CLoaderx32"},
    }};

    for (const auto& [original, replacement] : replacements) {
        if (replacement.size() != original.size()) {
            throw std::runtime_error("Internal CLoader namespace size mismatch.");
        }

        bool found = false;
        for (auto cursor = image.begin(); cursor != image.end();) {
            cursor = std::search(cursor, image.end(), original.begin(), original.end());
            if (cursor == image.end()) break;
            std::copy(replacement.begin(), replacement.end(), cursor);
            cursor += replacement.size();
            found = true;
        }

        std::vector<std::uint8_t> original_wide;
        std::vector<std::uint8_t> replacement_wide;
        for (const unsigned char ch : original) {
            original_wide.push_back(ch);
            original_wide.push_back(0);
        }
        for (const unsigned char ch : replacement) {
            replacement_wide.push_back(ch);
            replacement_wide.push_back(0);
        }
        for (auto cursor = image.begin(); cursor != image.end();) {
            cursor = std::search(cursor, image.end(), original_wide.begin(),
                                 original_wide.end());
            if (cursor == image.end()) break;
            std::copy(replacement_wide.begin(), replacement_wide.end(), cursor);
            cursor += replacement_wide.size();
            found = true;
        }
        if (!found) {
            throw std::runtime_error("CLoader namespace signature was not found.");
        }
    }
}

void patch_loader_connect_redirect(std::vector<std::uint8_t>& image,
                                   const std::string& service_host) {
    in_addr address{};
    if (InetPtonA(AF_INET, service_host.c_str(), &address) != 1) {
        throw std::runtime_error("Service host must be an IPv4 address.");
    }

    // Both recovered CLoaderx32 revisions keep the WSAConnect/connect hooks in
    // this RVA window. Each hook contains seven loopback address constants.
    // Validate the complete count before changing any byte so an updated loader
    // fails explicitly instead of receiving a partial network patch.
    constexpr std::size_t kHookBegin = 0x12000;
    constexpr std::size_t kHookEnd = 0x15000;
    constexpr std::array<std::uint8_t, 4> kLoopback{0x7F, 0x00, 0x00, 0x01};
    if (image.size() < kHookEnd) {
        throw std::runtime_error("CLoaderx32 socket-hook range is outside the image.");
    }

    std::array<std::uint8_t, 4> replacement{};
    std::memcpy(replacement.data(), &address, replacement.size());
    std::vector<std::size_t> matches;
    for (std::size_t offset = kHookBegin;
         offset + kLoopback.size() <= kHookEnd; ++offset) {
        if (std::equal(kLoopback.begin(), kLoopback.end(), image.begin() + offset)) {
            matches.push_back(offset);
            offset += kLoopback.size() - 1;
        }
    }
    if (matches.size() != 14) {
        throw std::runtime_error(
            "CLoaderx32 connect redirect signature count was " +
            std::to_string(matches.size()) + ", expected 14.");
    }
    for (const std::size_t offset : matches) {
        std::copy(replacement.begin(), replacement.end(), image.begin() + offset);
    }
    std::cout << "Patched 14 x86 CLoader connect redirect constants to "
              << service_host << '\n';
}

std::uintptr_t remote_module_base(DWORD process_id,
                                  std::wstring_view module_name) {
    Handle snapshot;
    for (unsigned attempt = 0; attempt != 50; ++attempt) {
        snapshot.reset(CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id));
        if (snapshot) break;
        const DWORD error = GetLastError();
        if (error == ERROR_PARTIAL_COPY) return 0;
        if (error != ERROR_BAD_LENGTH) {
            fail("CreateToolhelp32Snapshot(x86 target) failed", error);
        }
        Sleep(2);
    }
    if (!snapshot) return 0;

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot.get(), &entry)) {
        fail("Module32FirstW(x86 target) failed");
    }
    do {
        if (_wcsicmp(entry.szModule, std::wstring(module_name).c_str()) == 0) {
            return reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
        }
    } while (Module32NextW(snapshot.get(), &entry));
    return 0;
}

struct EntryGate {
    std::uint8_t* remote = nullptr;
    std::uint32_t original_entry = 0;
};

EntryGate start_entry_gate(HANDLE process, HANDLE primary_thread,
                           DWORD process_id) {
    CONTEXT context{};
    context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
    if (!GetThreadContext(primary_thread, &context)) {
        fail("GetThreadContext(x86 initial thread) failed");
    }

    // On an initially suspended Win32 process RtlUserThreadStart receives the
    // executable entry point in EAX. Let the loader initialize, then hold the
    // process in this gate until CLoader mapping and ZLO initialization finish.
    std::array<std::uint8_t, 25> gate{
        0xC6, 0x05, 0, 0, 0, 0, 0x01, // mov byte [reached], 1
        0x80, 0x3D, 0, 0, 0, 0, 0x00, // cmp byte [release], 0
        0x74, 0xF7,                   // je wait
        0xB8, 0, 0, 0, 0,            // mov eax, original entry
        0xFF, 0xE0,                   // jmp eax
        0x00,                         // release
        0x00,                         // reached
    };

    auto* remote = static_cast<std::uint8_t*>(VirtualAllocEx(
        process, nullptr, gate.size(), MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
    if (!remote) fail("VirtualAllocEx(x86 entry gate) failed");

    const std::uint32_t remote_address =
        reinterpret_cast<std::uint32_t>(remote);
    const std::uint32_t release_address = remote_address + 23;
    const std::uint32_t reached_address = remote_address + 24;
    const std::uint32_t original_entry = context.Eax;
    std::memcpy(gate.data() + 2, &reached_address, sizeof(reached_address));
    std::memcpy(gate.data() + 9, &release_address, sizeof(release_address));
    std::memcpy(gate.data() + 17, &original_entry, sizeof(original_entry));

    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote, gate.data(), gate.size(), &written) ||
        written != gate.size()) {
        fail("WriteProcessMemory(x86 entry gate) failed");
    }
    FlushInstructionCache(process, remote, gate.size());
    context.Eax = remote_address;
    if (!SetThreadContext(primary_thread, &context)) {
        fail("SetThreadContext(x86 entry gate) failed");
    }
    if (ResumeThread(primary_thread) == static_cast<DWORD>(-1)) {
        fail("ResumeThread(x86 entry gate) failed");
    }

    const ULONGLONG deadline = GetTickCount64() + 30000;
    for (;;) {
        std::uint8_t reached = 0;
        ReadProcessMemory(process, remote + 24, &reached, sizeof(reached), nullptr);
        if (reached && remote_module_base(process_id, L"kernel32.dll") &&
            remote_module_base(process_id, L"kernelbase.dll")) {
            return {remote, original_entry};
        }
        if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) {
            throw std::runtime_error("The x86 target exited during loader initialization.");
        }
        if (GetTickCount64() >= deadline) {
            throw std::runtime_error(
                "Timed out waiting for the x86 target loader to reach its entry point.");
        }
        Sleep(1);
    }
}

void release_entry_gate(HANDLE process, const EntryGate& gate) {
    const std::uint8_t release = 1;
    SIZE_T written = 0;
    if (!WriteProcessMemory(process, gate.remote + 23, &release,
                            sizeof(release), &written) ||
        written != sizeof(release)) {
        fail("WriteProcessMemory(release x86 entry gate) failed");
    }
    FlushInstructionCache(process, gate.remote, 25);
}

std::wstring module_basename(HMODULE module) {
    std::array<wchar_t, 32768> path{};
    const DWORD length = GetModuleFileNameW(
        module, path.data(), static_cast<DWORD>(path.size()));
    if (!length || length == path.size()) {
        fail("GetModuleFileNameW(x86 import owner) failed");
    }
    return fs::path(std::wstring(path.data(), length)).filename().wstring();
}

std::uint32_t remote_address_for_local(DWORD process_id, FARPROC procedure) {
    const std::uintptr_t address = std::bit_cast<std::uintptr_t>(procedure);
    HMODULE owner = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(address), &owner)) {
        fail("GetModuleHandleExW(x86 import owner) failed");
    }
    const std::wstring name = module_basename(owner);
    const std::uintptr_t remote_base = remote_module_base(process_id, name);
    if (!remote_base) {
        throw std::runtime_error(
            "Required x86 module is not loaded in the target: " +
            std::string(name.begin(), name.end()));
    }
    return static_cast<std::uint32_t>(
        remote_base + address - reinterpret_cast<std::uintptr_t>(owner));
}

#pragma pack(push, 1)
struct RemoteCallData32 {
    std::uint32_t function;
    std::uint32_t arg1;
    std::uint32_t arg2;
    std::uint32_t arg3;
    std::uint32_t result;
    std::uint8_t done;
    std::uint32_t saved_esp;
};
#pragma pack(pop)
static_assert(sizeof(RemoteCallData32) == 25);

DWORD remote_call3(HANDLE process, HANDLE primary_thread,
                   std::uint32_t function, std::uint32_t arg1,
                   std::uint32_t arg2, std::uint32_t arg3) {
    std::array<std::uint8_t, 38> code{
        0xB8, 0, 0, 0, 0,       // mov eax, data
        0x89, 0x60, 0x15,        // mov [eax+15h], esp
        0xFF, 0x70, 0x0C,        // push [eax+0ch]
        0xFF, 0x70, 0x08,        // push [eax+08h]
        0xFF, 0x70, 0x04,        // push [eax+04h]
        0xFF, 0x10,              // call [eax]
        0xB9, 0, 0, 0, 0,       // mov ecx, data
        0x8B, 0x61, 0x15,        // mov esp, [ecx+15h]
        0x89, 0x41, 0x10,        // mov [ecx+10h], eax
        0xC6, 0x41, 0x14, 0x01,  // mov byte [ecx+14h], 1
        0xF3, 0x90,              // pause
        0xEB, 0xFC,              // jmp pause
    };
    const SIZE_T total = sizeof(RemoteCallData32) + code.size();
    auto* remote = static_cast<std::uint8_t*>(VirtualAllocEx(
        process, nullptr, total, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
    if (!remote) fail("VirtualAllocEx(x86 remote call) failed");
    struct FreeRemote {
        HANDLE process;
        void* address;
        ~FreeRemote() { VirtualFreeEx(process, address, 0, MEM_RELEASE); }
    } cleanup{process, remote};

    const std::uint32_t remote_data = reinterpret_cast<std::uint32_t>(remote);
    std::memcpy(code.data() + 1, &remote_data, sizeof(remote_data));
    std::memcpy(code.data() + 20, &remote_data, sizeof(remote_data));
    const RemoteCallData32 data{function, arg1, arg2, arg3, 0, 0, 0};
    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote, &data, sizeof(data), &written) ||
        written != sizeof(data) ||
        !WriteProcessMemory(process, remote + sizeof(data), code.data(),
                            code.size(), &written) ||
        written != code.size()) {
        fail("WriteProcessMemory(x86 remote call) failed");
    }
    FlushInstructionCache(process, remote, total);

    if (SuspendThread(primary_thread) == static_cast<DWORD>(-1)) {
        fail("SuspendThread(x86 remote call) failed");
    }
    CONTEXT saved{};
    saved.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(primary_thread, &saved)) {
        fail("GetThreadContext(x86 remote call) failed");
    }
    CONTEXT redirected = saved;
    redirected.Eip = reinterpret_cast<std::uint32_t>(remote + sizeof(data));
    if (!SetThreadContext(primary_thread, &redirected)) {
        fail("SetThreadContext(x86 remote call) failed");
    }
    if (ResumeThread(primary_thread) == static_cast<DWORD>(-1)) {
        fail("ResumeThread(x86 remote call) failed");
    }

    RemoteCallData32 returned{};
    const ULONGLONG deadline = GetTickCount64() + 30000;
    for (;;) {
        if (!ReadProcessMemory(process, remote, &returned, sizeof(returned), nullptr)) {
            fail("ReadProcessMemory(x86 remote call) failed");
        }
        if (returned.done) break;
        if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) {
            throw std::runtime_error("The x86 target exited during a bootstrap call.");
        }
        if (GetTickCount64() >= deadline) {
            throw std::runtime_error("Timed out in an x86 hijacked-thread bootstrap call.");
        }
        Sleep(1);
    }

    if (SuspendThread(primary_thread) == static_cast<DWORD>(-1)) {
        fail("SuspendThread(restore x86 call) failed");
    }
    if (!SetThreadContext(primary_thread, &saved)) {
        fail("SetThreadContext(restore x86 call) failed");
    }
    if (ResumeThread(primary_thread) == static_cast<DWORD>(-1)) {
        fail("ResumeThread(restore x86 call) failed");
    }
    return returned.result;
}

void remote_load_dependency(HANDLE process, HANDLE primary_thread,
                            DWORD process_id, const std::wstring& name) {
    const std::wstring basename = fs::path(name).filename().wstring();
    if (remote_module_base(process_id, basename)) return;

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC load_library = GetProcAddress(kernel32, "LoadLibraryW");
    if (!load_library) fail("GetProcAddress(x86 LoadLibraryW) failed");
    const std::uint32_t remote_load_library =
        remote_address_for_local(process_id, load_library);
    const SIZE_T bytes = (name.size() + 1) * sizeof(wchar_t);
    void* remote_name = VirtualAllocEx(process, nullptr, bytes,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_READWRITE);
    if (!remote_name) fail("VirtualAllocEx(x86 dependency name) failed");
    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote_name, name.c_str(), bytes, &written) ||
        written != bytes) {
        VirtualFreeEx(process, remote_name, 0, MEM_RELEASE);
        fail("WriteProcessMemory(x86 dependency name) failed");
    }
    const DWORD loaded = remote_call3(
        process, primary_thread, remote_load_library,
        reinterpret_cast<std::uint32_t>(remote_name), 0, 0);
    VirtualFreeEx(process, remote_name, 0, MEM_RELEASE);
    if (!loaded || !remote_module_base(process_id, basename)) {
        throw std::runtime_error(
            "The x86 target could not load dependency: " +
            std::string(name.begin(), name.end()));
    }
}

DWORD section_protection(DWORD characteristics) {
    const bool execute = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    const bool read = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    const bool write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    if (execute) {
        if (write) return PAGE_EXECUTE_READWRITE;
        if (read) return PAGE_EXECUTE_READ;
        return PAGE_EXECUTE;
    }
    if (write) return PAGE_READWRITE;
    if (read) return PAGE_READONLY;
    return PAGE_NOACCESS;
}

void patch_game_blaze_redirector(HANDLE process,
                                 const std::string& service_host) {
    constexpr std::array<std::string_view, 4> hostnames{
        "gosredirector.online.ea.com",
        "gosredirector.stest.ea.com",
        "gosredirector.scert.ea.com",
        "gosredirector.ea.com",
    };
    if (service_host.empty() || service_host.size() > hostnames.back().size()) {
        throw std::runtime_error("Service host is too long for the game's redirector slot.");
    }

    struct Match { std::uintptr_t address; std::size_t length; };
    std::vector<Match> matches;
    constexpr SIZE_T kChunkSize = 1u << 20;
    SYSTEM_INFO system_info{};
    GetSystemInfo(&system_info);
    std::uintptr_t cursor = reinterpret_cast<std::uintptr_t>(
        system_info.lpMinimumApplicationAddress);
    const std::uintptr_t maximum = reinterpret_cast<std::uintptr_t>(
        system_info.lpMaximumApplicationAddress);
    while (cursor < maximum) {
        MEMORY_BASIC_INFORMATION memory{};
        if (!VirtualQueryEx(process, reinterpret_cast<void*>(cursor),
                            &memory, sizeof(memory))) break;
        const std::uintptr_t base =
            reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
        const std::size_t region_size = memory.RegionSize;
        if (memory.State == MEM_COMMIT &&
            !(memory.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
            for (std::size_t offset = 0; offset < region_size;) {
                const SIZE_T request = std::min<SIZE_T>(
                    kChunkSize + hostnames.front().size(), region_size - offset);
                std::vector<std::uint8_t> bytes(request);
                SIZE_T bytes_read = 0;
                if (ReadProcessMemory(process,
                        reinterpret_cast<void*>(base + offset), bytes.data(),
                        request, &bytes_read)) {
                    const auto end = bytes.begin() +
                        static_cast<std::ptrdiff_t>(bytes_read);
                    for (const std::string_view hostname : hostnames) {
                        for (auto found = std::search(bytes.begin(), end,
                                                     hostname.begin(), hostname.end());
                             found != end;
                             found = std::search(found + 1, end,
                                                 hostname.begin(), hostname.end())) {
                            matches.push_back({
                                base + offset + static_cast<std::size_t>(
                                    found - bytes.begin()), hostname.size()});
                        }
                    }
                }
                offset += std::min<std::size_t>(kChunkSize, region_size - offset);
            }
        }
        if (!region_size || base + region_size <= cursor) break;
        cursor = base + region_size;
    }
    std::sort(matches.begin(), matches.end(),
              [](const Match& left, const Match& right) {
                  return left.address < right.address;
              });
    matches.erase(std::unique(matches.begin(), matches.end(),
                              [](const Match& left, const Match& right) {
                                  return left.address == right.address;
                              }), matches.end());
    if (matches.empty()) {
        std::cerr
            << "injector32: warning: Could not locate a Blaze redirector "
               "hostname in the x86 game; continuing without the optional "
               "game-side hostname patch.\n";
        return;
    }

    for (const Match match : matches) {
        std::vector<char> replacement(match.length, '\0');
        std::copy(service_host.begin(), service_host.end(), replacement.begin());
        auto* target = reinterpret_cast<void*>(match.address);
        DWORD old_protection = 0;
        if (!VirtualProtectEx(process, target, replacement.size(), PAGE_READWRITE,
                              &old_protection)) {
            fail("VirtualProtectEx(x86 Blaze redirector) failed");
        }
        SIZE_T written = 0;
        const bool patched = WriteProcessMemory(
            process, target, replacement.data(), replacement.size(), &written) &&
            written == replacement.size();
        const DWORD error = patched ? ERROR_SUCCESS : GetLastError();
        DWORD ignored = 0;
        VirtualProtectEx(process, target, replacement.size(), old_protection,
                         &ignored);
        if (!patched) fail("WriteProcessMemory(x86 Blaze redirector) failed", error);
    }
    std::cout << "Patched " << matches.size()
              << " x86 Blaze redirector hostname(s) to " << service_host << '\n';
}

template <std::size_t Size>
bool remote_bytes_equal(HANDLE process, std::uintptr_t address,
                        const std::array<std::uint8_t, Size>& expected) {
    std::array<std::uint8_t, Size> actual{};
    SIZE_T bytes_read = 0;
    return ReadProcessMemory(process, reinterpret_cast<const void*>(address),
                             actual.data(), actual.size(), &bytes_read) &&
        bytes_read == actual.size() && actual == expected;
}

struct ActivationRoutineDiscovery {
    std::uintptr_t address = 0;
};

std::optional<ActivationRoutineDiscovery> discover_cmain_activation_routine(
    HANDLE process, std::uintptr_t cmain_base) {
    constexpr std::array<std::uint8_t, 8> marker_low{
        0xC7, 0x44, 0x24, 0x44, 0x6D, 0x9D, 0x6F, 0x88,
    };
    constexpr std::array<std::uint8_t, 8> marker_high{
        0xC7, 0x44, 0x24, 0x48, 0xE7, 0x68, 0x45, 0x81,
    };

    struct AllocationRegion {
        std::uintptr_t base;
        std::uintptr_t allocation_base;
        std::vector<std::uint8_t> bytes;
    };
    std::vector<AllocationRegion> regions;
    std::uintptr_t cursor = cmain_base;
    for (;;) {
        MEMORY_BASIC_INFORMATION memory{};
        if (!VirtualQueryEx(process, reinterpret_cast<void*>(cursor), &memory,
                            sizeof(memory))) {
            break;
        }
        const std::uintptr_t allocation_base =
            reinterpret_cast<std::uintptr_t>(memory.AllocationBase);
        if (cmain_base && allocation_base != cmain_base) break;
        const std::uintptr_t base =
            reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
        const DWORD protection = memory.Protect & 0xFFu;
        const bool executable = protection == PAGE_EXECUTE ||
            protection == PAGE_EXECUTE_READ ||
            protection == PAGE_EXECUTE_READWRITE ||
            protection == PAGE_EXECUTE_WRITECOPY;
        if (memory.State == MEM_COMMIT && executable &&
            !(memory.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
            AllocationRegion region{base, allocation_base,
                std::vector<std::uint8_t>(memory.RegionSize)};
            SIZE_T bytes_read = 0;
            if (ReadProcessMemory(process, memory.BaseAddress,
                                  region.bytes.data(), region.bytes.size(),
                                  &bytes_read)) {
                region.bytes.resize(bytes_read);
                regions.push_back(std::move(region));
            }
        }
        if (!memory.RegionSize || base + memory.RegionSize <= cursor) break;
        cursor = base + memory.RegionSize;
    }

    const auto find_pattern = [&](const auto& pattern) {
        std::vector<std::uintptr_t> matches;
        for (const AllocationRegion& region : regions) {
            for (auto found = std::search(region.bytes.begin(), region.bytes.end(),
                                          pattern.begin(), pattern.end());
                 found != region.bytes.end();
                 found = std::search(found + 1, region.bytes.end(),
                                     pattern.begin(), pattern.end())) {
                matches.push_back(region.base + static_cast<std::uintptr_t>(
                    found - region.bytes.begin()));
            }
        }
        return matches;
    };

    const auto saved_flags = std::cout.flags();
    if (cmain_base) {
        std::cout << "[activation-patch] CMainx32 allocation base: 0x"
                  << std::hex << cmain_base << std::dec << '\n';
    }

    const std::vector<std::uintptr_t> low_matches = find_pattern(marker_low);
    std::size_t candidates = 0;
    std::uintptr_t discovered_scanner = 0;
    for (const std::uintptr_t low : low_matches) {
        // Both known implementations place the second half of the activation
        // marker 0x19 bytes after the first and begin the function 0x1f bytes
        // before it. Matching both stores makes this substantially less prone
        // to false positives than a version-specific function prologue.
        if (!remote_bytes_equal(process, low + 0x19, marker_high) ||
            low < 0x1F) {
            continue;
        }
        ++candidates;
        const std::uintptr_t scanner = low - 0x1F;
        discovered_scanner = scanner;
        std::uintptr_t scanner_allocation_base = cmain_base;
        if (!scanner_allocation_base) {
            const auto region = std::find_if(
                regions.begin(), regions.end(), [low](const AllocationRegion& item) {
                    return low >= item.base && low < item.base + item.bytes.size();
                });
            if (region != regions.end()) {
                scanner_allocation_base = region->allocation_base;
            }
        }
        std::cout << "[activation-patch] discovered CMainx32 allocation base 0x"
                  << std::hex << scanner_allocation_base
                  << ", activation routine RVA 0x"
                  << (scanner - scanner_allocation_base)
                  << " (VA 0x" << scanner << ')' << std::dec << '\n';
    }
    if (candidates != 1) {
        std::cout << "[activation-patch] WARNING: expected exactly one semantic "
                     "activation-routine signature, found " << candidates
                  << " (marker hits=" << low_matches.size() << ")\n";
    }
    std::cout.flags(saved_flags);
    if (candidates == 1) {
        return ActivationRoutineDiscovery{discovered_scanner};
    }
    return std::nullopt;
}

class ActivationPatchMonitor {
public:
    ActivationPatchMonitor(HANDLE process, DWORD process_id,
                           std::uintptr_t activation_routine_address)
        : process_(process), process_id_(process_id),
          activation_routine_address_(activation_routine_address) {
        if (activation_routine_address_ > UINT32_MAX) {
            throw std::runtime_error(
                "The x86 activation routine address is outside uint32 range.");
        }
        if (!DebugActiveProcess(process_id_)) {
            fail("DebugActiveProcess(activation patch monitor) failed");
        }
        attached_ = true;
        if (!DebugSetProcessKillOnExit(FALSE)) {
            const DWORD error = GetLastError();
            detach_noexcept();
            fail("DebugSetProcessKillOnExit(activation patch monitor) failed",
                 error);
        }
        std::cout << "[activation-patch] monitoring process " << process_id_
                  << " for Activation.dll\n";
    }

    ActivationPatchMonitor(const ActivationPatchMonitor&) = delete;
    ActivationPatchMonitor& operator=(const ActivationPatchMonitor&) = delete;

    ~ActivationPatchMonitor() {
        detach_noexcept();
    }

    void wait_for_hit() {
        wait_for_activation_patch();
    }


private:
    void wait_for_activation_patch() {
        constexpr DWORD kActivationLoadTimeoutMs = 30000;
        const ULONGLONG deadline =
            GetTickCount64() + kActivationLoadTimeoutMs;

        for (;;) {
            const ULONGLONG now = GetTickCount64();
            const DWORD timeout = now >= deadline
                ? 0
                : static_cast<DWORD>(deadline - now);
            DEBUG_EVENT event{};
            if (!WaitForDebugEvent(&event, timeout)) {
                const DWORD error = GetLastError();
                if (error == ERROR_SEM_TIMEOUT) {
                    std::cout << "[activation-patch] Activation.dll was not "
                                 "loaded within 30 seconds; detaching\n";
                    detach_noexcept();
                    return;
                }
                detach_noexcept();
                fail("WaitForDebugEvent(activation patch monitor) failed",
                     error);
            }

            DWORD continuation = DBG_CONTINUE;
            bool activation_loaded = false;
            bool patch_succeeded = false;
            bool process_exited = false;
            if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT &&
                is_activation_dll_load(event)) {
                const std::uintptr_t activation_base =
                    reinterpret_cast<std::uintptr_t>(event.u.LoadDll.lpBaseOfDll);
                const auto saved_flags = std::cout.flags();
                std::cout << "[activation-patch] Activation.dll loaded at 0x"
                          << std::hex << activation_base << std::dec << '\n';
                std::cout.flags(saved_flags);
                activation_loaded = true;
                patch_succeeded =
                    patch_activation_key_directly(activation_base);
            } else if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
                       event.u.Exception.ExceptionRecord.ExceptionCode !=
                           EXCEPTION_BREAKPOINT) {
                // This monitor does not diagnose or consume target exceptions.
                continuation = DBG_EXCEPTION_NOT_HANDLED;
            } else if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
                process_exited = true;
            }

            close_debug_event_handles(event);
            if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId,
                                    continuation)) {
                const DWORD error = GetLastError();
                detach_noexcept();
                fail("ContinueDebugEvent(activation patch monitor) failed",
                     error);
            }

            if (process_exited) {
                attached_ = false;
                std::cout << "[activation-patch] process exited before "
                             "Activation.dll was patched\n";
                return;
            }
            if (activation_loaded) {
                detach_noexcept();
                if (!patch_succeeded) {
                    throw std::runtime_error(
                        "could not apply CMain's Activation.dll patch");
                }
                std::cout << "[activation-patch] patch complete; debugger "
                             "detached\n";
                return;
            }
        }
    }


    bool patch_activation_key_directly(std::uintptr_t activation_base) {
        constexpr std::uintptr_t kDsaPublicKeyRva = 0xC75E0;
        constexpr std::size_t kDsaPublicKeySize = 0x80;
        constexpr std::size_t kScannerProbeSize = 0x240;
        constexpr std::array<std::uint8_t, 8> kOriginalPrefix{
            0x6D, 0x9D, 0x6F, 0x88, 0xE7, 0x68, 0x45, 0x81,
        };

        // CMain's activation routine begins by loading the embedded 128-byte replacement
        // into ESI, loading ECX with 0x20 dwords, and REP MOVSD-ing it to its
        // local buffer. Recover that relocated source pointer from:
        //   BE <source> B9 20 00 00 00
        std::array<std::uint8_t, kScannerProbeSize> scanner_code{};
        SIZE_T bytes_read = 0;
        if (!ReadProcessMemory(process_,
                               reinterpret_cast<const void*>(activation_routine_address_),
                               scanner_code.data(), scanner_code.size(),
                               &bytes_read) || bytes_read != scanner_code.size()) {
            std::cout << "[activation-patch] could not read CMain activation routine "
                         "(Win32 " << GetLastError() << ")\n";
            return false;
        }

        std::uintptr_t source = 0;
        for (std::size_t index = 0; index + 10 <= scanner_code.size(); ++index) {
            if (scanner_code[index] != 0xBE ||
                scanner_code[index + 5] != 0xB9 ||
                scanner_code[index + 6] != 0x20 ||
                scanner_code[index + 7] != 0 ||
                scanner_code[index + 8] != 0 ||
                scanner_code[index + 9] != 0) {
                continue;
            }
            std::uint32_t source32 = 0;
            std::memcpy(&source32, scanner_code.data() + index + 1,
                        sizeof(source32));
            source = source32;
            break;
        }
        if (!source) {
            std::cout << "[activation-patch] CMain DSA key source instruction was "
                         "not found in the activation routine prologue\n";
            return false;
        }

        // The original scanner marks its one-time Activation setup complete
        // after installing the ReadFile hook (interface+0x88) and before
        // committing the DSA-key replacement (interface+0xA0):
        //   FF 90 88 00 00 00        call [eax+88h]
        //   ...
        //   C6 05 <state> 01         mov byte ptr [state],1
        //   ...
        //   FF 90 A0 00 00 00        call [eax+0A0h]
        // Recover that relocated state address instead of relying on a CMain
        // RVA, which varies with the generated module.
        constexpr std::array<std::uint8_t, 6> kReadFileHookCall{
            0xFF, 0x90, 0x88, 0x00, 0x00, 0x00,
        };
        constexpr std::array<std::uint8_t, 6> kCommitCall{
            0xFF, 0x90, 0xA0, 0x00, 0x00, 0x00,
        };
        std::uintptr_t activation_state = 0;
        std::size_t state_candidates = 0;
        for (std::size_t hook = 0;
             hook + kReadFileHookCall.size() <= scanner_code.size(); ++hook) {
            if (!std::equal(kReadFileHookCall.begin(), kReadFileHookCall.end(),
                            scanner_code.begin() + hook)) {
                continue;
            }
            const std::size_t state_end =
                std::min(scanner_code.size(), hook + 0x80);
            for (std::size_t state = hook + kReadFileHookCall.size();
                 state + 7 <= state_end; ++state) {
                if (scanner_code[state] != 0xC6 ||
                    scanner_code[state + 1] != 0x05 ||
                    scanner_code[state + 6] != 0x01) {
                    continue;
                }
                const std::size_t commit_end =
                    std::min(scanner_code.size(), state + 0x80);
                bool commit_follows = false;
                for (std::size_t commit = state + 7;
                     commit + kCommitCall.size() <= commit_end; ++commit) {
                    if (std::equal(kCommitCall.begin(), kCommitCall.end(),
                                   scanner_code.begin() + commit)) {
                        commit_follows = true;
                        break;
                    }
                }
                if (!commit_follows) continue;

                std::uint32_t state32 = 0;
                std::memcpy(&state32, scanner_code.data() + state + 2,
                            sizeof(state32));
                activation_state = state32;
                ++state_candidates;
            }
        }
        if (state_candidates != 1 || !activation_state) {
            std::cout << "[activation-patch] expected one CMain activation state "
                         "marker, found " << state_candidates << '\n';
            return false;
        }

        std::array<std::uint8_t, kDsaPublicKeySize> replacement{};
        if (!ReadProcessMemory(process_, reinterpret_cast<const void*>(source),
                               replacement.data(), replacement.size(),
                               &bytes_read) || bytes_read != replacement.size()) {
            std::cout << "[activation-patch] could not read CMain DSA key source at 0x"
                      << std::hex << source << std::dec << " (Win32 "
                      << GetLastError() << ")\n";
            return false;
        }

        const std::uintptr_t target = activation_base + kDsaPublicKeyRva;
        std::array<std::uint8_t, kDsaPublicKeySize> before{};
        if (!ReadProcessMemory(process_, reinterpret_cast<const void*>(target),
                               before.data(), before.size(), &bytes_read) ||
            bytes_read != before.size()) {
            std::cout << "[activation-patch] could not read Activation.dll DSA key "
                         "target (Win32 " << GetLastError() << ")\n";
            return false;
        }
        if (before == replacement) {
            std::cout << "[activation-patch] Activation.dll DSA key already matches "
                         "CMain's replacement\n";
        } else if (!std::equal(kOriginalPrefix.begin(), kOriginalPrefix.end(),
                               before.begin())) {
            std::cout << "[activation-patch] refusing to replace an unrecognized "
                         "Activation.dll DSA key at RVA 0xC75E0\n";
            return false;
        } else {
            DWORD old_protection = 0;
            void* const target_pointer = reinterpret_cast<void*>(target);
            if (!VirtualProtectEx(process_, target_pointer, replacement.size(),
                                  PAGE_READWRITE, &old_protection)) {
                std::cout << "[activation-patch] VirtualProtectEx(Activation DSA key) "
                             "failed (Win32 " << GetLastError() << ")\n";
                return false;
            }
            SIZE_T written = 0;
            const bool wrote = WriteProcessMemory(
                process_, target_pointer, replacement.data(), replacement.size(),
                &written) && written == replacement.size();
            const DWORD write_error = wrote ? ERROR_SUCCESS : GetLastError();
            DWORD ignored = 0;
            const bool restored = VirtualProtectEx(
                process_, target_pointer, replacement.size(), old_protection,
                &ignored) != FALSE;
            if (!wrote || !restored) {
                std::cout << "[activation-patch] direct Activation DSA key write failed "
                             "(Win32 " << (wrote ? GetLastError() : write_error)
                          << ")\n";
                return false;
            }

            std::array<std::uint8_t, kDsaPublicKeySize> after{};
            if (!ReadProcessMemory(process_, target_pointer, after.data(),
                                   after.size(), &bytes_read) ||
                bytes_read != after.size() || after != replacement) {
                std::cout << "[activation-patch] direct Activation DSA key "
                             "verification failed\n";
                return false;
            }
            std::size_t changed = 0;
            for (std::size_t index = 0; index < before.size(); ++index)
                if (before[index] != after[index]) ++changed;
            std::cout << "[activation-patch] copied CMain DSA key 0x" << std::hex
                      << source << " -> Activation.dll+0x" << kDsaPublicKeyRva
                      << std::dec << "; changed " << changed << '/'
                      << replacement.size() << " bytes" << std::endl;
        }

        std::uint8_t old_state = 0;
        if (!ReadProcessMemory(process_,
                               reinterpret_cast<const void*>(activation_state),
                               &old_state, sizeof(old_state), &bytes_read) ||
            bytes_read != sizeof(old_state)) {
            std::cout << "[activation-patch] could not read CMain activation state "
                         "at 0x" << std::hex << activation_state << std::dec
                      << " (Win32 " << GetLastError() << ")\n";
            return false;
        }
        if (old_state != 1) {
            const std::uint8_t complete = 1;
            DWORD old_protection = 0;
            void* const state_pointer =
                reinterpret_cast<void*>(activation_state);
            if (!VirtualProtectEx(process_, state_pointer, sizeof(complete),
                                  PAGE_READWRITE, &old_protection)) {
                std::cout << "[activation-patch] VirtualProtectEx(CMain activation "
                             "state) failed (Win32 " << GetLastError() << ")\n";
                return false;
            }
            SIZE_T written = 0;
            const bool wrote = WriteProcessMemory(
                process_, state_pointer, &complete, sizeof(complete), &written) &&
                written == sizeof(complete);
            const DWORD write_error = wrote ? ERROR_SUCCESS : GetLastError();
            DWORD ignored = 0;
            const bool restored = VirtualProtectEx(
                process_, state_pointer, sizeof(complete), old_protection,
                &ignored) != FALSE;
            std::uint8_t verified_state = 0;
            const bool verified = wrote && restored &&
                ReadProcessMemory(process_, state_pointer, &verified_state,
                                  sizeof(verified_state), &bytes_read) &&
                bytes_read == sizeof(verified_state) && verified_state == 1;
            if (!verified) {
                std::cout << "[activation-patch] could not mark CMain activation "
                             "state complete (Win32 "
                          << (wrote ? GetLastError() : write_error) << ")\n";
                return false;
            }
        }
        std::cout << "[activation-patch] marked CMain activation state complete at 0x"
                  << std::hex << activation_state << std::dec
                  << " (previous value " << static_cast<unsigned>(old_state)
                  << ')' << std::endl;
        return true;
    }


    static bool is_activation_dll_load(const DEBUG_EVENT& event) {
        const HANDLE file = event.u.LoadDll.hFile;
        if (!file) return false;

        std::vector<wchar_t> path(32768);
        const DWORD length = GetFinalPathNameByHandleW(
            file, path.data(), static_cast<DWORD>(path.size()),
            FILE_NAME_NORMALIZED);
        if (!length || length >= path.size()) return false;
        path.resize(length);
        return _wcsicmp(
            fs::path(std::wstring(path.data(), path.size())).filename().c_str(),
            L"Activation.dll") == 0;
    }

    static void close_debug_event_handles(const DEBUG_EVENT& event) noexcept {
        if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            if (event.u.CreateProcessInfo.hFile)
                CloseHandle(event.u.CreateProcessInfo.hFile);
            if (event.u.CreateProcessInfo.hProcess)
                CloseHandle(event.u.CreateProcessInfo.hProcess);
            if (event.u.CreateProcessInfo.hThread)
                CloseHandle(event.u.CreateProcessInfo.hThread);
        } else if (event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
            if (event.u.CreateThread.hThread)
                CloseHandle(event.u.CreateThread.hThread);
        } else if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
            if (event.u.LoadDll.hFile) CloseHandle(event.u.LoadDll.hFile);
        }
    }

    void detach_noexcept() noexcept {
        if (!attached_) return;
        DebugActiveProcessStop(process_id_);
        attached_ = false;
    }

    HANDLE process_ = nullptr;
    DWORD process_id_ = 0;
    std::uintptr_t activation_routine_address_ = 0;
    bool attached_ = false;
};

std::uintptr_t patch_cmain_lsx_redirect(HANDLE process,
                                        const std::string& lsx_host) {
    constexpr std::array<std::uint8_t, 34> pattern{
        0x8B, 0x55, 0x0C,                   // mov edx, [ebp+0ch]
        0x8B, 0x5D, 0x14,                   // mov ebx, [ebp+14h]
        0x8B, 0x02,                         // mov eax, [edx]
        0x25, 0xFF, 0xFF, 0xFF, 0xFE,       // and eax, 0xfeffffff
        0x3D, 0x80, 0x0B, 0x29, 0x4C,       // cmp eax, 0x4c290b80
        0x75, 0x06,                         // jne +6
        0xC7, 0x02, 0x7F, 0x00, 0x00, 0x01, // mov [edx], 127.0.0.1
        0x8B, 0x45, 0x10,                   // mov eax, [ebp+10h]
        0x66, 0x81, 0x38, 0x18, 0x20,       // cmp word [eax], 8216
    };
    constexpr std::size_t kPatchOffset = 13;
    std::array<std::uint8_t, 16> replacement{
        0x8B, 0x45, 0x10,                   // mov eax, [ebp+10h]
        0x66, 0x81, 0x38, 0x18, 0x20,       // cmp word [eax], 8216
        0x75, 0x06,                         // jne +6
        0xC7, 0x02, 0, 0, 0, 0,             // mov [edx], LSX host
    };
    in_addr address{};
    if (InetPtonA(AF_INET, lsx_host.c_str(), &address) != 1) {
        throw std::runtime_error("LSX host must be an IPv4 address.");
    }
    std::memcpy(replacement.data() + 12, &address, sizeof(address));

    constexpr SIZE_T kChunkSize = 1u << 20;
    std::vector<std::uintptr_t> matches;
    SYSTEM_INFO system_info{};
    GetSystemInfo(&system_info);
    std::uintptr_t cursor = reinterpret_cast<std::uintptr_t>(
        system_info.lpMinimumApplicationAddress);
    const std::uintptr_t maximum = reinterpret_cast<std::uintptr_t>(
        system_info.lpMaximumApplicationAddress);
    while (cursor < maximum) {
        MEMORY_BASIC_INFORMATION memory{};
        if (!VirtualQueryEx(process, reinterpret_cast<void*>(cursor),
                            &memory, sizeof(memory))) break;
        const std::uintptr_t base =
            reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
        const std::size_t region_size = memory.RegionSize;
        const DWORD protection = memory.Protect & 0xFFu;
        const bool executable = protection == PAGE_EXECUTE ||
            protection == PAGE_EXECUTE_READ ||
            protection == PAGE_EXECUTE_READWRITE ||
            protection == PAGE_EXECUTE_WRITECOPY;
        if (memory.State == MEM_COMMIT && executable &&
            !(memory.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
            for (std::size_t offset = 0; offset < region_size;) {
                const SIZE_T request = std::min<SIZE_T>(
                    kChunkSize + pattern.size() - 1, region_size - offset);
                std::vector<std::uint8_t> bytes(request);
                SIZE_T bytes_read = 0;
                if (ReadProcessMemory(process,
                        reinterpret_cast<void*>(base + offset), bytes.data(),
                        request, &bytes_read) && bytes_read >= pattern.size()) {
                    const auto end = bytes.begin() +
                        static_cast<std::ptrdiff_t>(bytes_read);
                    for (auto found = std::search(bytes.begin(), end,
                                                 pattern.begin(), pattern.end());
                         found != end;
                         found = std::search(found + 1, end,
                                             pattern.begin(), pattern.end())) {
                        matches.push_back(base + offset +
                            static_cast<std::size_t>(found - bytes.begin()));
                    }
                }
                offset += std::min<std::size_t>(kChunkSize, region_size - offset);
            }
        }
        if (!region_size || base + region_size <= cursor) break;
        cursor = base + region_size;
    }
    std::sort(matches.begin(), matches.end());
    matches.erase(std::unique(matches.begin(), matches.end()), matches.end());
    if (matches.size() != 1) {
        throw std::runtime_error(
            "Could not uniquely locate CMainx32's LSX redirect (found " +
            std::to_string(matches.size()) + ").");
    }

    auto* target = reinterpret_cast<void*>(matches.front() + kPatchOffset);
    DWORD old_protection = 0;
    if (!VirtualProtectEx(process, target, replacement.size(),
                          PAGE_EXECUTE_READWRITE, &old_protection)) {
        fail("VirtualProtectEx(CMainx32 LSX redirect) failed");
    }
    SIZE_T written = 0;
    const bool patched = WriteProcessMemory(
        process, target, replacement.data(), replacement.size(), &written) &&
        written == replacement.size();
    const DWORD error = patched ? ERROR_SUCCESS : GetLastError();
    DWORD ignored = 0;
    VirtualProtectEx(process, target, replacement.size(), old_protection, &ignored);
    if (!patched) fail("WriteProcessMemory(CMainx32 LSX redirect) failed", error);
    FlushInstructionCache(process, target, replacement.size());
    std::cout << "Patched CMainx32 LSX redirect to " << lsx_host << ":8216\n";

    MEMORY_BASIC_INFORMATION memory{};
    if (!VirtualQueryEx(process, reinterpret_cast<void*>(matches.front()),
                        &memory, sizeof(memory)) || !memory.AllocationBase) {
        fail("VirtualQueryEx(CMainx32 allocation) failed");
    }
    return reinterpret_cast<std::uintptr_t>(memory.AllocationBase);
}

#pragma pack(push, 1)
struct ZloContext32 {
    std::uint32_t magic;
    std::uint8_t status;
    std::uint32_t original_eip;
    std::uint32_t mapper_address;
    std::uint32_t image_base;
    std::uint32_t result;
    std::uint32_t last_error;
};
#pragma pack(pop)
static_assert(sizeof(ZloContext32) == 25);
static_assert(offsetof(ZloContext32, result) == 17);

std::unique_ptr<ActivationPatchMonitor> map_loader32(
    HANDLE process, HANDLE primary_thread, DWORD process_id,
    const fs::path& image_path, const std::string& service_host,
    const std::string& lsx_host, const std::string& instance_name) {
    std::vector<std::uint8_t> file = read_file(image_path);
    if (file.size() < sizeof(IMAGE_DOS_HEADER)) {
        throw std::runtime_error("Bootstrap is not a valid PE32 image.");
    }
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(file.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
        static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS32) >
            file.size()) {
        throw std::runtime_error("Bootstrap is not a valid PE32 image.");
    }
    auto* nt_file = reinterpret_cast<IMAGE_NT_HEADERS32*>(
        file.data() + dos->e_lfanew);
    if (nt_file->Signature != IMAGE_NT_SIGNATURE ||
        nt_file->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
        nt_file->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        throw std::runtime_error("Bootstrap must be an I386 PE32 image.");
    }

    std::vector<std::uint8_t> image(nt_file->OptionalHeader.SizeOfImage, 0);
    if (nt_file->OptionalHeader.SizeOfHeaders > file.size() ||
        nt_file->OptionalHeader.SizeOfHeaders > image.size()) {
        throw std::runtime_error("Malformed PE32 image: headers exceed file size.");
    }
    std::memcpy(image.data(), file.data(), nt_file->OptionalHeader.SizeOfHeaders);
    const auto* sections = IMAGE_FIRST_SECTION(nt_file);
    for (WORD index = 0; index < nt_file->FileHeader.NumberOfSections; ++index) {
        const auto& section = sections[index];
        if (!section.SizeOfRawData) continue;
        if (static_cast<std::size_t>(section.PointerToRawData) +
                    section.SizeOfRawData > file.size() ||
            static_cast<std::size_t>(section.VirtualAddress) +
                    section.SizeOfRawData > image.size()) {
            throw std::runtime_error("Malformed PE32 image: section is out of range.");
        }
        std::memcpy(image.data() + section.VirtualAddress,
                    file.data() + section.PointerToRawData,
                    section.SizeOfRawData);
    }

    patch_loader_instance_names(image, instance_name);
    patch_loader_connect_redirect(image, service_host);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(
        image.data() + dos->e_lfanew);
    const DWORD image_size = nt->OptionalHeader.SizeOfImage;
    void* remote_image = VirtualAllocEx(
        process, reinterpret_cast<void*>(nt->OptionalHeader.ImageBase), image_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_image) {
        remote_image = VirtualAllocEx(process, nullptr, image_size,
                                      MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
    }
    if (!remote_image) fail("VirtualAllocEx(mapped CLoaderx32) failed");
    const std::uint32_t remote_base =
        reinterpret_cast<std::uint32_t>(remote_image);
    const std::int64_t delta = static_cast<std::int64_t>(remote_base) -
                               nt->OptionalHeader.ImageBase;

    const auto& reloc_dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (delta != 0) {
        if (!reloc_dir.VirtualAddress || !reloc_dir.Size) {
            throw std::runtime_error("CLoaderx32 cannot be relocated.");
        }
        DWORD consumed = 0;
        while (consumed < reloc_dir.Size) {
            auto* block = at<IMAGE_BASE_RELOCATION>(
                image, reloc_dir.VirtualAddress + consumed);
            if (block->SizeOfBlock < sizeof(*block) ||
                block->SizeOfBlock > reloc_dir.Size - consumed) {
                throw std::runtime_error("Malformed PE32 relocation block.");
            }
            const DWORD count = (block->SizeOfBlock - sizeof(*block)) / sizeof(WORD);
            auto* entries = at<WORD>(
                image, reloc_dir.VirtualAddress + consumed + sizeof(*block));
            for (DWORD index = 0; index < count; ++index) {
                const WORD type = entries[index] >> 12;
                const WORD offset = entries[index] & 0x0FFF;
                if (type == IMAGE_REL_BASED_HIGHLOW) {
                    *at<std::uint32_t>(image,
                        block->VirtualAddress + offset) +=
                        static_cast<std::uint32_t>(delta);
                } else if (type != IMAGE_REL_BASED_ABSOLUTE) {
                    throw std::runtime_error("Unsupported PE32 relocation type.");
                }
            }
            consumed += block->SizeOfBlock;
        }
    }
    nt->OptionalHeader.ImageBase = remote_base;

    const EntryGate entry_gate =
        start_entry_gate(process, primary_thread, process_id);

    const auto& import_dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.VirtualAddress) {
        auto* descriptor = at<IMAGE_IMPORT_DESCRIPTOR>(
            image, import_dir.VirtualAddress);
        for (; descriptor->Name; ++descriptor) {
            const char* narrow_name = reinterpret_cast<const char*>(
                at<std::uint8_t>(image, descriptor->Name));
            const int wide_length = MultiByteToWideChar(
                CP_ACP, 0, narrow_name, -1, nullptr, 0);
            if (wide_length <= 0) fail("MultiByteToWideChar(x86 import) failed");
            std::wstring wide_name(static_cast<std::size_t>(wide_length), L'\0');
            MultiByteToWideChar(CP_ACP, 0, narrow_name, -1,
                                wide_name.data(), wide_length);
            wide_name.resize(wcslen(wide_name.c_str()));
            HMODULE local_module = LoadLibraryW(wide_name.c_str());
            if (!local_module) {
                throw std::runtime_error(
                    "Could not load x86 bootstrap dependency locally: " +
                    std::string(narrow_name));
            }
            remote_load_dependency(process, primary_thread, process_id, wide_name);

            const DWORD lookup_rva = descriptor->OriginalFirstThunk
                ? descriptor->OriginalFirstThunk
                : descriptor->FirstThunk;
            auto* lookup = at<IMAGE_THUNK_DATA32>(image, lookup_rva);
            auto* iat = at<IMAGE_THUNK_DATA32>(image, descriptor->FirstThunk);
            for (; lookup->u1.AddressOfData; ++lookup, ++iat) {
                FARPROC procedure = nullptr;
                if (IMAGE_SNAP_BY_ORDINAL32(lookup->u1.Ordinal)) {
                    procedure = GetProcAddress(
                        local_module, reinterpret_cast<LPCSTR>(
                            IMAGE_ORDINAL32(lookup->u1.Ordinal)));
                } else {
                    auto* by_name = at<IMAGE_IMPORT_BY_NAME>(
                        image, lookup->u1.AddressOfData);
                    procedure = GetProcAddress(
                        local_module, reinterpret_cast<char*>(by_name->Name));
                }
                if (!procedure) {
                    throw std::runtime_error(
                        "Could not resolve a CLoaderx32 import.");
                }
                HMODULE owner = nullptr;
                if (!GetModuleHandleExW(
                        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                        reinterpret_cast<LPCWSTR>(procedure), &owner)) {
                    fail("GetModuleHandleExW(CLoaderx32 import) failed");
                }
                remote_load_dependency(process, primary_thread, process_id,
                                       module_basename(owner));
                iat->u1.Function =
                    remote_address_for_local(process_id, procedure);
            }
        }
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote_image, image.data(), image.size(),
                            &written) || written != image.size()) {
        fail("WriteProcessMemory(mapped CLoaderx32) failed");
    }

    const auto& tls_dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls_dir.VirtualAddress &&
        tls_dir.Size >= sizeof(IMAGE_TLS_DIRECTORY32)) {
        auto* tls = at<IMAGE_TLS_DIRECTORY32>(image, tls_dir.VirtualAddress);
        const SIZE_T raw_tls_size =
            tls->EndAddressOfRawData - tls->StartAddressOfRawData;
        const SIZE_T tls_block_size = raw_tls_size + tls->SizeOfZeroFill;
        if (tls->AddressOfIndex && tls_block_size) {
            HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
            FARPROC tls_alloc = GetProcAddress(kernel32, "TlsAlloc");
            FARPROC tls_set_value = GetProcAddress(kernel32, "TlsSetValue");
            if (!tls_alloc || !tls_set_value) {
                throw std::runtime_error("Could not resolve x86 TLS APIs.");
            }
            const DWORD tls_index = remote_call3(
                process, primary_thread,
                remote_address_for_local(process_id, tls_alloc), 0, 0, 0);
            if (tls_index == TLS_OUT_OF_INDEXES) {
                throw std::runtime_error("TlsAlloc failed in the x86 target.");
            }
            void* remote_tls = VirtualAllocEx(process, nullptr, tls_block_size,
                                               MEM_COMMIT | MEM_RESERVE,
                                               PAGE_READWRITE);
            if (!remote_tls) fail("VirtualAllocEx(x86 static TLS) failed");
            const std::size_t template_rva =
                tls->StartAddressOfRawData - remote_base;
            if (raw_tls_size &&
                (!WriteProcessMemory(process, remote_tls,
                                     at<std::uint8_t>(image, template_rva),
                                     raw_tls_size, &written) ||
                 written != raw_tls_size)) {
                fail("WriteProcessMemory(x86 TLS template) failed");
            }
            if (!WriteProcessMemory(
                    process, reinterpret_cast<void*>(tls->AddressOfIndex),
                    &tls_index, sizeof(tls_index), &written) ||
                written != sizeof(tls_index)) {
                fail("WriteProcessMemory(x86 TLS index) failed");
            }
            if (!remote_call3(
                    process, primary_thread,
                    remote_address_for_local(process_id, tls_set_value),
                    tls_index, reinterpret_cast<std::uint32_t>(remote_tls), 0)) {
                throw std::runtime_error("TlsSetValue failed in the x86 target.");
            }
        }
        if (tls->AddressOfCallBacks) {
            const std::size_t callbacks_rva =
                tls->AddressOfCallBacks - remote_base;
            auto* callback = at<std::uint32_t>(image, callbacks_rva);
            for (; *callback; ++callback) {
                remote_call3(process, primary_thread, *callback, remote_base,
                             DLL_PROCESS_ATTACH, 0);
            }
        }
    }

    ZloContext32 context{
        0xDEADBEEF, 0, entry_gate.original_entry, 0, remote_base, 0, 0};
    void* remote_context = VirtualAllocEx(process, nullptr, sizeof(context),
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_READWRITE);
    if (!remote_context) fail("VirtualAllocEx(ZLO x86 context) failed");
    if (!WriteProcessMemory(process, remote_context, &context, sizeof(context),
                            &written) || written != sizeof(context)) {
        fail("WriteProcessMemory(ZLO x86 context) failed");
    }

    if (nt->OptionalHeader.AddressOfEntryPoint) {
        std::cout << "Calling mapped CLoaderx32 DllMain...\n";
        if (!remote_call3(
                process, primary_thread,
                remote_base + nt->OptionalHeader.AddressOfEntryPoint,
                remote_base, DLL_PROCESS_ATTACH,
                reinterpret_cast<std::uint32_t>(remote_context))) {
            throw std::runtime_error("Mapped CLoaderx32 DllMain rejected attach.");
        }
    }

    DWORD zlo_rva = 0;
    const auto& export_dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_dir.VirtualAddress) {
        auto* exports = at<IMAGE_EXPORT_DIRECTORY>(
            image, export_dir.VirtualAddress);
        auto* names = at<DWORD>(image, exports->AddressOfNames);
        auto* ordinals = at<WORD>(image, exports->AddressOfNameOrdinals);
        auto* functions = at<DWORD>(image, exports->AddressOfFunctions);
        for (DWORD index = 0; index < exports->NumberOfNames; ++index) {
            const char* name = reinterpret_cast<const char*>(
                at<std::uint8_t>(image, names[index]));
            if (std::strcmp(name, "ZLO") == 0) {
                zlo_rva = functions[ordinals[index]];
                break;
            }
        }
    }
    if (!zlo_rva) {
        throw std::runtime_error("Mapped CLoaderx32 has no ZLO export.");
    }

    const std::uint8_t mapped_status = 2;
    if (!WriteProcessMemory(
            process,
            static_cast<std::uint8_t*>(remote_context) +
                offsetof(ZloContext32, status),
            &mapped_status, sizeof(mapped_status), &written) ||
        written != sizeof(mapped_status)) {
        fail("WriteProcessMemory(updated x86 ZLO status) failed");
    }
    patch_game_blaze_redirector(process, service_host);
    std::cout << "Calling CLoaderx32 ZLO bootstrap export...\n";
    remote_call3(process, primary_thread, remote_base + zlo_rva,
                 reinterpret_cast<std::uint32_t>(remote_context), 0, 0);
    if (!ReadProcessMemory(process, remote_context, &context, sizeof(context),
                           nullptr)) {
        fail("ReadProcessMemory(ZLO x86 context) failed");
    }
    if (context.result != 0) {
        throw std::runtime_error(
            "CLoaderx32 ZLO bootstrap failed (status " +
            std::to_string(context.result) + ", detail " +
            std::to_string(context.last_error) + ").");
    }

    const std::uintptr_t cmain_base =
        patch_cmain_lsx_redirect(process, lsx_host);
    const std::optional<ActivationRoutineDiscovery> activation_routine =
        discover_cmain_activation_routine(process, cmain_base);
    std::unique_ptr<ActivationPatchMonitor> activation_monitor;
    if (activation_routine) {
        activation_monitor = std::make_unique<ActivationPatchMonitor>(
            process, process_id, activation_routine->address);
        std::cout << "[activation-patch] parent game monitor attached to process "
                  << process_id << '\n';
    } else {
        std::cout << "[activation-patch] CMain activation routine was not "
                     "found in the parent game process\n";
    }
    auto* mapped_sections = IMAGE_FIRST_SECTION(nt);
    for (WORD index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
        const auto& section = mapped_sections[index];
        const SIZE_T size = section.Misc.VirtualSize
            ? section.Misc.VirtualSize
            : section.SizeOfRawData;
        if (!size) continue;
        DWORD old_protection = 0;
        if (!VirtualProtectEx(
                process, reinterpret_cast<void*>(
                    remote_base + section.VirtualAddress),
                size, section_protection(section.Characteristics),
                &old_protection)) {
            fail("VirtualProtectEx(mapped CLoaderx32 section) failed");
        }
    }
    FlushInstructionCache(process, remote_image, image_size);
    release_entry_gate(process, entry_gate);
    return activation_monitor;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        const Arguments arguments = parse_arguments(argc, argv);
        if (arguments.monitor_activation) {
            Handle ready_event(OpenEventW(EVENT_MODIFY_STATE, FALSE,
                                          arguments.ready_event_name.c_str()));
            if (!ready_event) fail("OpenEventW(activation ready event) failed");
            Handle process(OpenProcess(PROCESS_CREATE_THREAD |
                                           PROCESS_QUERY_INFORMATION |
                                           PROCESS_VM_OPERATION |
                                           PROCESS_VM_READ |
                                           PROCESS_VM_WRITE |
                                           SYNCHRONIZE,
                                       FALSE, arguments.process_id));
            if (!process) fail("OpenProcess(activation target) failed");

            BOOL target_wow64 = FALSE;
            if (!IsWow64Process(process.get(), &target_wow64)) {
                fail("IsWow64Process(activation target) failed");
            }
            if (!target_wow64) {
                throw std::runtime_error(
                    "The activation monitor target is not running under WOW64.");
            }

            const std::optional<ActivationRoutineDiscovery> activation_routine =
                discover_cmain_activation_routine(
                    process.get(), 0);
            if (!activation_routine) {
                throw std::runtime_error(
                    "Could not uniquely discover the child CMainx32 activation routine.");
            }
            ActivationPatchMonitor activation_monitor(
                process.get(), arguments.process_id,
                activation_routine->address);
            if (!SetEvent(ready_event.get())) {
                fail("SetEvent(activation ready event) failed");
            }
            activation_monitor.wait_for_hit();
            return 0;
        }

        Handle process(OpenProcess(PROCESS_CREATE_THREAD |
                                       PROCESS_QUERY_INFORMATION |
                                       PROCESS_VM_OPERATION |
                                       PROCESS_VM_READ |
                                       PROCESS_VM_WRITE |
                                       PROCESS_SUSPEND_RESUME |
                                       SYNCHRONIZE,
                                   FALSE, arguments.process_id));
        if (!process) fail("OpenProcess(x86 target) failed");
        Handle thread(OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                     THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                                 FALSE, arguments.thread_id));
        if (!thread) fail("OpenThread(x86 primary thread) failed");

        BOOL target_wow64 = FALSE;
        if (!IsWow64Process(process.get(), &target_wow64)) {
            fail("IsWow64Process(x86 target) failed");
        }
        if (!target_wow64) {
            throw std::runtime_error(
                "zclient_injector32 was given a process that is not running under WOW64.");
        }

        std::unique_ptr<ActivationPatchMonitor> activation_monitor = map_loader32(
            process.get(), thread.get(), arguments.process_id,
            arguments.bootstrap, arguments.service_host,
            arguments.lsx_host, arguments.instance_name);
        std::cout << "Mapped CLoaderx32 and released the BF3 entry gate\n";
        if (activation_monitor) activation_monitor->wait_for_hit();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "injector32: " << error.what() << '\n';
        return 1;
    }
}
