#include "manual_map.h"

#include <tlhelp32.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

// class Handle {
// public:
//     explicit Handle(HANDLE value = nullptr) : value_(value) {}
//     ~Handle() {
//         if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
//     }
//     Handle(const Handle&) = delete;
//     Handle& operator=(const Handle&) = delete;
//     [[nodiscard]] HANDLE get() const { return value_; }
//     void reset(HANDLE value = nullptr) {
//         if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
//         value_ = value;
//     }
//     [[nodiscard]] explicit operator bool() const {
//         return value_ && value_ != INVALID_HANDLE_VALUE;
//     }
// private:
//     HANDLE value_;
// };

std::vector<std::uint8_t> read_file(const std::filesystem::path& path) 
{
    std::ifstream stream(path, std::ios::binary | std::ios::ate);

    if (!stream) 
    {
        fail("Could not open bootstrap image.");
    }

    const auto size = stream.tellg();
    if (size <= 0)
    {
        fail("Bootstrap image is empty.");
    }

    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    stream.seekg(0);

    if (!stream.read(reinterpret_cast<char*>(bytes.data()), size)) 
    {
        fail("Could not read bootstrap image.");
    }

    return bytes;
}

void patch_loader_instance_names(std::vector<std::uint8_t>& image,
                                 const std::string& instance_name) 
{
    if (instance_name.size() != 7) 
    {
        fail("CLoader instance name must contain seven characters.");
    }

    const std::array<std::pair<std::string_view, std::string>, 3> replacements{{
        {"\\\\.\\pipe\\ZClient", "\\\\.\\pipe\\" + instance_name},
        {"Global\\ZClient_CLoaderx64", "Local\\0" + instance_name + "_CLoaderx64"},
        {"Global\\ZClient_CLoaderx32", "Local\\0" + instance_name + "_CLoaderx32"},
    }};

    for (const auto& [original, replacement] : replacements) 
    {
        if (replacement.size() != original.size()) 
        {
            fail("Internal CLoader instance-name size mismatch.");
        }

        bool found = false;
        for (auto cursor = image.begin(); cursor != image.end();) 
        {
            cursor = std::search(cursor, image.end(), original.begin(), original.end());

            if (cursor == image.end()) 
            {
                break;
            }

            std::copy(replacement.begin(), replacement.end(), cursor);
            cursor += replacement.size();

            found = true;
        }

        // CLoader keeps both diagnostic/narrow copies and the UTF-16 literals
        // actually passed to CreateFileW/CreateFileMappingW.
        std::vector<std::uint8_t> original_wide;
        std::vector<std::uint8_t> replacement_wide;
        original_wide.reserve(original.size() * sizeof(wchar_t));
        replacement_wide.reserve(replacement.size() * sizeof(wchar_t));

        for (const unsigned char character : original) 
        {
            original_wide.push_back(character);
            original_wide.push_back(0);
        }

        for (const unsigned char character : replacement) 
        {
            replacement_wide.push_back(character);
            replacement_wide.push_back(0);
        }

        for (auto cursor = image.begin(); cursor != image.end();) 
        {
            cursor = std::search(cursor, image.end(), original_wide.begin(),
                                 original_wide.end());
           
            if (cursor == image.end())
            {
                break;
            }

            std::copy(replacement_wide.begin(), replacement_wide.end(), cursor);
            cursor += replacement_wide.size();

            found = true;
        }

        if (!found) 
        {
            fail("CLoader instance-name signature was not found.");
        }
    }
}

void patch_loader_dns_redirect(std::vector<std::uint8_t>& image,
                               const std::string& service_host) 
{
    // CLoaderx64's getaddrinfo hook classifies the EA redirector as case 1 and
    // resolves a hard-coded 127.0.0.1 string. Reuse an inactive service-host
    // slot for the selected LAN IPv4 and point the case-1 LEA at that slot.
    // RVAs are for the currently supported recovered CLoaderx64.
    constexpr std::size_t kCase1LeaRva = 0x110B6;
    constexpr std::size_t kCase1DispRva = kCase1LeaRva + 3;
    constexpr std::size_t kReplacementRva = 0x326FDF;
    constexpr std::string_view kOriginalReplacement = "wellcloud.zloemu.net";
    constexpr std::array<std::uint8_t, 3> kLeaPrefix = {0x48, 0x8D, 0x0D};

    if (service_host.empty() || service_host.size() > kOriginalReplacement.size() ||
        kReplacementRva + kOriginalReplacement.size() + 1 > image.size() ||
        kCase1DispRva + sizeof(std::int32_t) > image.size() ||
        !std::equal(kLeaPrefix.begin(), kLeaPrefix.end(), image.begin() + kCase1LeaRva) ||
        std::memcmp(image.data() + kReplacementRva, kOriginalReplacement.data(), kOriginalReplacement.size()) != 0) 
    {
        fail("CLoaderx64 DNS redirect signature does not match or service IPv4 is too long.");
    }

    std::fill_n(image.begin() + kReplacementRva, kOriginalReplacement.size() + 1, std::uint8_t{0});
    std::copy(service_host.begin(), service_host.end(), image.begin() + kReplacementRva);

    const auto next_instruction = static_cast<std::int64_t>(kCase1LeaRva + 7);
    const auto displacement = static_cast<std::int32_t>(static_cast<std::int64_t>(kReplacementRva) - next_instruction);
    
    std::memcpy(image.data() + kCase1DispRva, &displacement, sizeof(displacement));

    std::cout << "Patched CLoader DNS redirect from loopback to " << service_host << '\n';
}

void patch_loader_connect_redirect(std::vector<std::uint8_t>& image,
                                   const std::string& service_host) 
{
    in_addr address{};

    if (InetPtonA(AF_INET, service_host.c_str(), &address) != 1) 
    {
        fail("Service host must be an IPv4 address.");
    }

    constexpr std::array<std::pair<std::size_t, std::size_t>, 2> kHookRanges = {{
        {0x11B90, 0x11F90}, // WSAConnect hook
        {0x130C0, 0x13650}, // connect hook
    }};
    constexpr std::array<std::uint8_t, 4> kLoopback = {0x7F, 0x00, 0x00, 0x01};

    std::array<std::uint8_t, 4> replacement{};
    std::memcpy(replacement.data(), &address, replacement.size());
    unsigned patched = 0;
    for (const auto [begin, end] : kHookRanges) 
    {
        if (end > image.size()) 
        {
            fail("CLoaderx64 connect hook range is invalid.");
        }
        for (std::size_t offset = begin; offset + kLoopback.size() <= end; ++offset) 
        {
            if (std::equal(kLoopback.begin(), kLoopback.end(), image.begin() + offset)) 
            {
                std::copy(replacement.begin(), replacement.end(), image.begin() + offset);
                ++patched;
                offset += kLoopback.size() - 1;
            }
        }
    }

    if (patched != 14) 
    {
        fail("CLoaderx64 connect redirect signature count was " + std::to_string(patched) + ", expected 14.");
    }

    std::cout << "Patched " << patched << " CLoader connect redirect constants to " << service_host << '\n';
}

void patch_cmain_lsx_redirect_impl(HANDLE process, const std::string& service_host) 
{
    // CMain's connect callback originally redirected only the legacy address
    // 128.11.41.76 to loopback.  gos.ea.com no longer reliably resolves to
    // that address, so OriginSDK can create its port-6176 socket without ever
    // reaching the local LSX service on port 8216.  Match the callback's instruction
    // sequence and change only its five-byte address comparison into the
    // equivalent port comparison.  The following conditional branch and
    // loopback write remain unchanged.
    constexpr std::array<std::uint8_t, 34> kConnectPattern = {
        0x8B, 0x02,                         // mov eax, [rdx]
        0x25, 0xFF, 0xFF, 0xFF, 0xFE,       // and eax, 0xfeffffff
        0x48, 0x89, 0xCF,                   // mov rdi, rcx
        0x4C, 0x89, 0xC6,                   // mov rsi, r8
        0x4C, 0x89, 0xCB,                   // mov rbx, r9
        0x3D, 0x80, 0x0B, 0x29, 0x4C,       // cmp eax, 0x4c290b80
        0x75, 0x06,                         // jne +6
        0xC7, 0x02, 0x7F, 0x00, 0x00, 0x01, // mov [rdx], 0x0100007f
        0x66, 0x81, 0x3E, 0x18, 0x20,       // cmp word ptr [rsi], 0x2018
    };
    constexpr std::size_t kCompareOffset = 16;
    constexpr std::array<std::uint8_t, 5> kPortCompare = {
        0x66, 0x81, 0x3E, 0x18, 0x20, // cmp word ptr [rsi], 8216
    };
    constexpr SIZE_T kChunkSize = 1u << 20;

    SYSTEM_INFO system_info{};
    GetSystemInfo(&system_info);

    std::uintptr_t cursor = reinterpret_cast<std::uintptr_t>(system_info.lpMinimumApplicationAddress);
    const std::uintptr_t maximum = reinterpret_cast<std::uintptr_t>(system_info.lpMaximumApplicationAddress);

    std::vector<std::uintptr_t> matches;

    while (cursor < maximum) 
    {
        MEMORY_BASIC_INFORMATION memory{};

        if (!VirtualQueryEx(process, reinterpret_cast<const void*>(cursor), &memory, sizeof(memory))) 
        {
            break;
        }

        const auto base = reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
        const auto region_size = static_cast<std::size_t>(memory.RegionSize);
        const DWORD protection = memory.Protect & 0xFFu;
        const bool executable = protection == PAGE_EXECUTE ||
                                protection == PAGE_EXECUTE_READ ||
                                protection == PAGE_EXECUTE_READWRITE ||
                                protection == PAGE_EXECUTE_WRITECOPY;
        
        if (memory.State == MEM_COMMIT && executable && !(memory.Protect & (PAGE_GUARD | PAGE_NOACCESS))) 
        {
            for (std::size_t offset = 0; offset < region_size;) 
            {
                const SIZE_T request = std::min<SIZE_T>(
                    kChunkSize + kConnectPattern.size() - 1,
                    region_size - offset);
                std::vector<std::uint8_t> bytes(request);
                SIZE_T bytes_read = 0;

                if (ReadProcessMemory(
                        process, reinterpret_cast<const void*>(base + offset),
                        bytes.data(), request, &bytes_read) &&
                    bytes_read >= kConnectPattern.size()) 
                {
                    const auto end = bytes.begin() + static_cast<std::ptrdiff_t>(bytes_read);

                    for (auto found = std::search(bytes.begin(), end, kConnectPattern.begin(), kConnectPattern.end());
                         found != end;
                         found = std::search(found + 1, end, kConnectPattern.begin(), kConnectPattern.end())) 
                    {
                        matches.push_back(base + offset + static_cast<std::size_t>(found - bytes.begin()));
                    }
                }

                offset += std::min<std::size_t>(kChunkSize, region_size - offset);
            }
        }

        if (region_size == 0 || base + region_size <= cursor) 
        {
            break;
        }

        cursor = base + region_size;
    }

    std::sort(matches.begin(), matches.end());
    matches.erase(std::unique(matches.begin(), matches.end()), matches.end());

    if (matches.size() != 1) 
    {
        fail("Could not uniquely locate CMain's legacy LSX redirect (found " + std::to_string(matches.size()) + ").");
    }

    in_addr service_address{};
    if (InetPtonA(AF_INET, service_host.c_str(), &service_address) != 1) 
    {
        fail("Service host must be an IPv4 address.");
    }

    // The address rewrite immediately follows the conditional branch in the
    // matched callback: C7 02 <sockaddr bytes>.
    auto* address_immediate = reinterpret_cast<void*>(matches.front() + 25);
    SIZE_T address_written = 0;
    DWORD address_protection = 0;
    if (!VirtualProtectEx(process, address_immediate, sizeof(service_address), PAGE_EXECUTE_READWRITE, &address_protection) ||
        !WriteProcessMemory(process, address_immediate, &service_address, sizeof(service_address), &address_written) ||
        address_written != sizeof(service_address)) 
    {
        fail("Patch CMain LSX service address failed");
    }

    DWORD address_ignored = 0;
    VirtualProtectEx(process, address_immediate, sizeof(service_address), address_protection, &address_ignored);

    auto* compare = reinterpret_cast<void*>(matches.front() + kCompareOffset);
    DWORD old_protection = 0;
    if (!VirtualProtectEx(process, compare, kPortCompare.size(), PAGE_EXECUTE_READWRITE, &old_protection)) 
    {
        fail("VirtualProtectEx(CMain LSX redirect) failed");
    }

    SIZE_T written = 0;
    const bool patched = WriteProcessMemory(process, compare, kPortCompare.data(), kPortCompare.size(), &written) &&
                         written == kPortCompare.size();
    const DWORD write_error = patched ? ERROR_SUCCESS : GetLastError();

    DWORD ignored = 0;
    if (!VirtualProtectEx(process, compare, kPortCompare.size(), old_protection, &ignored)) 
    {
        fail("VirtualProtectEx(restore CMain LSX redirect) failed");
    }

    if (!patched) 
    {
        fail("WriteProcessMemory(CMain LSX redirect) failed", write_error);
    }

    if (!FlushInstructionCache(process, compare, kPortCompare.size())) 
    {
        fail("FlushInstructionCache(CMain LSX redirect) failed");
    }

    std::cout << "Patched CMain LSX redirect at 0x" << std::hex
              << reinterpret_cast<std::uintptr_t>(compare) << std::dec
              << " to " << service_host << '\n';
}

void patch_game_blaze_redirector_impl(HANDLE process, const std::string& service_host) 
{
    // The original ZClient hosts EA.dll, which intercepts Blaze's production
    // redirector and returns its local server address. The minimal launcher
    // has no in-process EA module, so direct the production redirector name to
    // the configured local HTTPS endpoint instead.
    constexpr std::array<std::string_view, 4> kHostnames = {
        "gosredirector.online.ea.com",
        "gosredirector.stest.ea.com",
        "gosredirector.scert.ea.com",
        "gosredirector.ea.com",
    };

    const std::string_view replacement_host = service_host;
    if (replacement_host.empty() || replacement_host.size() > kHostnames.back().size()) 
    {
        fail("Service host is too long for the game's redirector slot.");
    }
    
    constexpr SIZE_T kChunkSize = 1u << 20;
    SYSTEM_INFO system_info{};
    GetSystemInfo(&system_info);
    std::uintptr_t cursor = reinterpret_cast<std::uintptr_t>(
        system_info.lpMinimumApplicationAddress);
    const std::uintptr_t maximum = reinterpret_cast<std::uintptr_t>(
        system_info.lpMaximumApplicationAddress);
    struct Match { std::uintptr_t address; std::size_t length; };
    std::vector<Match> matches;
    while (cursor < maximum) {
        MEMORY_BASIC_INFORMATION memory{};
        if (!VirtualQueryEx(process, reinterpret_cast<const void*>(cursor),
                            &memory, sizeof(memory))) break;
        const auto base = reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
        const auto region_size = static_cast<std::size_t>(memory.RegionSize);
        if (memory.State == MEM_COMMIT &&
            !(memory.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
            for (std::size_t offset = 0; offset < region_size;) {
                const SIZE_T request = std::min<SIZE_T>(
                    kChunkSize + kHostnames.front().size(), region_size - offset);
                std::vector<std::uint8_t> bytes(request);
                SIZE_T bytes_read = 0;
                if (ReadProcessMemory(process,
                        reinterpret_cast<const void*>(base + offset), bytes.data(),
                        request, &bytes_read) && bytes_read >= kHostnames.back().size()) {
                    const auto begin = bytes.begin();
                    const auto end = begin + static_cast<std::ptrdiff_t>(bytes_read);
                    for (const auto hostname : kHostnames) {
                        for (auto found = std::search(begin, end, hostname.begin(), hostname.end());
                             found != end;
                             found = std::search(found + 1, end, hostname.begin(), hostname.end())) {
                            matches.push_back({base + offset +
                                               static_cast<std::size_t>(found - begin),
                                               hostname.size()});
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
              [](const Match& left, const Match& right) { return left.address < right.address; });
    matches.erase(std::unique(matches.begin(), matches.end(),
                              [](const Match& left, const Match& right) {
                                  return left.address == right.address;
                              }), matches.end());
    if (matches.empty()) {
        fail("Could not locate a Blaze redirector hostname in the game.");
    }
    for (const auto& match : matches) {
        std::vector<char> replacement(match.length, '\0');
        std::copy(replacement_host.begin(), replacement_host.end(), replacement.begin());
        auto* target = reinterpret_cast<void*>(match.address);
        DWORD old_protection = 0;
        if (!VirtualProtectEx(process, target, replacement.size(),
                              PAGE_READWRITE, &old_protection)) {
            fail("VirtualProtectEx(Blaze redirector) failed");
        }
        SIZE_T written = 0;
        const bool patched = WriteProcessMemory(process, target, replacement.data(),
                                                replacement.size(), &written) &&
                             written == replacement.size();
        const DWORD write_error = patched ? ERROR_SUCCESS : GetLastError();
        DWORD ignored = 0;
        VirtualProtectEx(process, target, replacement.size(), old_protection, &ignored);
        if (!patched) fail("WriteProcessMemory(Blaze redirector) failed", write_error);
    }
    std::cout << "Patched " << matches.size()
              << " Blaze redirector hostname(s) to " << service_host << '\n';
}

template <typename T>
T* at(std::vector<std::uint8_t>& image, std::size_t offset) {
    if (offset > image.size() || sizeof(T) > image.size() - offset) {
        fail("Malformed PE image: RVA is out of range.");
    }
    return reinterpret_cast<T*>(image.data() + offset);
}

std::uintptr_t remote_module_base(DWORD pid, std::wstring_view module_name) {
    Handle snapshot;
    // MSDN explicitly requires retrying module snapshots when the loader is
    // changing its module list. This is common here because CMain has just
    // loaded and ERROR_BAD_LENGTH is therefore not a fatal process error.
    for (unsigned attempt = 0; attempt != 50; ++attempt) {
        snapshot.reset(CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
        if (snapshot) break;
        const DWORD error = GetLastError();
        if (error == ERROR_PARTIAL_COPY) return 0;
        if (error != ERROR_BAD_LENGTH) {
            fail("CreateToolhelp32Snapshot failed", error);
        }
        Sleep(2);
    }
    if (!snapshot) {
        // Let callers that are already polling for loader initialization try
        // again instead of terminating an otherwise healthy launch.
        return 0;
    }
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot.get(), &entry)) fail("Module32FirstW failed");
    do {
        if (_wcsicmp(entry.szModule, std::wstring(module_name).c_str()) == 0) {
            return reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
        }
    } while (Module32NextW(snapshot.get(), &entry));
    return 0;
}

struct EntryGate {
    std::uint8_t* remote = nullptr;
    std::uint64_t original_entry = 0;
};

EntryGate start_at_loader_initialized_gate(HANDLE process, HANDLE primary_thread,
                                           DWORD process_id) {
    CONTEXT context{};
    context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
    if (!GetThreadContext(primary_thread, &context)) {
        fail("GetThreadContext(initial thread) failed");
    }

    // RtlUserThreadStart receives the executable entry point in RCX. Replace it
    // with a tiny gate. Windows still performs normal loader initialization, but
    // the executable itself cannot run until the final flag is released.
    std::array<std::uint8_t, 30> gate{
        0xC6, 0x05, 0x16, 0x00, 0x00, 0x00, 0x01, // reached = 1
        0x80, 0x3D, 0x0E, 0x00, 0x00, 0x00, 0x00, // cmp release, 0
        0x74, 0xF7,                               // je wait
        0x48, 0xB8,                               // mov rax, original entry
        0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xE0,                               // jmp rax
        0x00,                                     // release flag
        0x00                                      // reached flag
    };
    std::memcpy(gate.data() + 18, &context.Rcx, sizeof(context.Rcx));
    auto* remote = static_cast<std::uint8_t*>(VirtualAllocEx(
        process, nullptr, gate.size(), MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
    if (!remote) fail("VirtualAllocEx(entry gate) failed");
    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote, gate.data(), gate.size(), &written) ||
        written != gate.size()) {
        fail("WriteProcessMemory(entry gate) failed");
    }
    FlushInstructionCache(process, remote, gate.size());
    const std::uint64_t original_entry = context.Rcx;
    context.Rcx = reinterpret_cast<std::uint64_t>(remote);
    if (!SetThreadContext(primary_thread, &context)) {
        fail("SetThreadContext(entry gate) failed");
    }
    if (ResumeThread(primary_thread) == static_cast<DWORD>(-1)) {
        fail("ResumeThread(entry gate) failed");
    }

    constexpr DWORD kTimeoutMs = 30000;
    const ULONGLONG deadline = GetTickCount64() + kTimeoutMs;
    for (;;) {
        std::uint8_t reached = 0;
        ReadProcessMemory(process, remote + 29, &reached, sizeof(reached), nullptr);
        if (reached && remote_module_base(process_id, L"kernel32.dll") &&
            remote_module_base(process_id, L"kernelbase.dll")) {
            return {remote, original_entry};
        }
        if (GetTickCount64() >= deadline) {
            fail(
                "Timed out waiting for the target loader to reach its entry point.");
        }
        Sleep(1);
    }
}

void release_entry_gate(HANDLE process, const EntryGate& gate) {
    const std::uint8_t release = 1;
    SIZE_T written = 0;
    if (!WriteProcessMemory(process, gate.remote + 28, &release, sizeof(release),
                            &written) || written != sizeof(release)) {
        fail("WriteProcessMemory(release entry gate) failed");
    }
    FlushInstructionCache(process, gate.remote, 30);
}

std::wstring module_basename(HMODULE module) {
    std::array<wchar_t, 32768> path{};
    const DWORD length = GetModuleFileNameW(module, path.data(),
                                            static_cast<DWORD>(path.size()));
    if (!length || length == path.size()) fail("GetModuleFileNameW failed");
    return std::filesystem::path(std::wstring(path.data(), length)).filename().wstring();
}

std::uintptr_t remote_address_for_local(DWORD pid, FARPROC procedure) {
    const std::uintptr_t address = std::bit_cast<std::uintptr_t>(procedure);
    HMODULE owner = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(address), &owner)) {
        fail("GetModuleHandleExW(FROM_ADDRESS) failed");
    }
    const std::wstring name = module_basename(owner);
    const std::uintptr_t remote_base = remote_module_base(pid, name);
    if (!remote_base) {
        fail("Required module is not loaded in the target: " +
                                 std::string(name.begin(), name.end()));
    }
    return remote_base + (address -
                          reinterpret_cast<std::uintptr_t>(owner));
}

#pragma pack(push, 1)
struct RemoteCallData {
    std::uint64_t function;
    std::uint64_t arg1;
    std::uint64_t arg2;
    std::uint64_t arg3;
    std::uint64_t result;
    std::uint8_t done;
    std::uint64_t saved_rsp;
};
#pragma pack(pop)

DWORD remote_call3(HANDLE process, HANDLE primary_thread, std::uint64_t function,
                   std::uint64_t arg1, std::uint64_t arg2, std::uint64_t arg3) {
    // Execute on the already-running primary thread. Some games reject creation of
    // extra remote threads, which is why the original ZClient also uses a
    // context-hijack path for native x64 games.
    std::array<std::uint8_t, 66> code{
        0x49, 0xBA,                   // mov r10, data
        0, 0, 0, 0, 0, 0, 0, 0,
        0x49, 0x89, 0x62, 0x29,       // mov [r10+29h], rsp
        0x48, 0x83, 0xE4, 0xF0,       // and rsp, -16
        0x48, 0x83, 0xEC, 0x20,       // sub rsp, 20h (shadow space)
        0x49, 0x8B, 0x02,             // mov rax, [r10]
        0x49, 0x8B, 0x4A, 0x08,       // mov rcx, [r10+8]
        0x49, 0x8B, 0x52, 0x10,       // mov rdx, [r10+10h]
        0x4D, 0x8B, 0x42, 0x18,       // mov r8,  [r10+18h]
        0xFF, 0xD0,                   // call rax
        0x49, 0xBA,                   // mov r10, data (R10 is volatile)
        0, 0, 0, 0, 0, 0, 0, 0,
        0x49, 0x8B, 0x62, 0x29,       // mov rsp, [r10+29h]
        0x49, 0x89, 0x42, 0x20,       // mov [r10+20h], rax
        0x41, 0xC6, 0x42, 0x28, 0x01, // mov byte [r10+28h], 1
        0xF3, 0x90,                   // pause
        0xEB, 0xFC                    // jmp pause
    };
    const SIZE_T total = sizeof(RemoteCallData) + sizeof(code);
    void* remote = VirtualAllocEx(process, nullptr, total, MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
    if (!remote) fail("VirtualAllocEx(remote call) failed");
    struct FreeRemote {
        HANDLE process;
        void* address;
        ~FreeRemote() { VirtualFreeEx(process, address, 0, MEM_RELEASE); }
    } cleanup{process, remote};

    const RemoteCallData data{function, arg1, arg2, arg3, 0, 0, 0};
    const std::uint64_t remote_data = reinterpret_cast<std::uint64_t>(remote);
    std::memcpy(code.data() + 2, &remote_data, sizeof(remote_data));
    std::memcpy(code.data() + 41, &remote_data, sizeof(remote_data));
    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote, &data, sizeof(data), &written) ||
        written != sizeof(data) ||
        !WriteProcessMemory(process,
                            static_cast<std::uint8_t*>(remote) + sizeof(data),
                            code.data(), code.size(), &written) || written != code.size()) {
        fail("WriteProcessMemory(remote call) failed");
    }
    FlushInstructionCache(process, remote, total);

    if (SuspendThread(primary_thread) == static_cast<DWORD>(-1)) {
        fail("SuspendThread(remote call) failed");
    }
    CONTEXT saved{};
    saved.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(primary_thread, &saved)) {
        fail("GetThreadContext(remote call) failed");
    }
    CONTEXT redirected = saved;
    redirected.Rip = reinterpret_cast<std::uint64_t>(
        static_cast<std::uint8_t*>(remote) + sizeof(data));
    if (!SetThreadContext(primary_thread, &redirected)) {
        fail("SetThreadContext(remote call) failed");
    }
    if (ResumeThread(primary_thread) == static_cast<DWORD>(-1)) {
        fail("ResumeThread(remote call) failed");
    }

    RemoteCallData returned{};
    const ULONGLONG deadline = GetTickCount64() + 30000;
    for (;;) {
        if (!ReadProcessMemory(process, remote, &returned, sizeof(returned), nullptr)) {
            const DWORD read_error = GetLastError();
            DWORD exit_code = STILL_ACTIVE;
            if (GetExitCodeProcess(process, &exit_code) && exit_code != STILL_ACTIVE) {
                fail(
                    "Target exited during the hijacked-thread call (exit code " +
                    std::to_string(exit_code) + ", read error " +
                    std::to_string(read_error) + ").");
            }
            fail("ReadProcessMemory(remote call) failed", read_error);
        }
        if (returned.done) break;
        if (GetTickCount64() >= deadline) {
            fail("Timed out in hijacked-thread bootstrap call.");
        }
        Sleep(1);
    }

    if (SuspendThread(primary_thread) == static_cast<DWORD>(-1)) {
        fail("SuspendThread(restore remote call) failed");
    }
    if (!SetThreadContext(primary_thread, &saved)) {
        fail("SetThreadContext(restore remote call) failed");
    }
    if (ResumeThread(primary_thread) == static_cast<DWORD>(-1)) {
        fail("ResumeThread(restore remote call) failed");
    }
    return static_cast<DWORD>(returned.result);
}

void remote_load_dependency(HANDLE process, HANDLE primary_thread, DWORD pid,
                            const std::wstring& name) {
    if (remote_module_base(pid, std::filesystem::path(name).filename().wstring())) return;
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC load_library = GetProcAddress(kernel32, "LoadLibraryW");
    if (!load_library) fail("GetProcAddress(LoadLibraryW) failed");
    const auto remote_load_library = remote_address_for_local(pid, load_library);
    const SIZE_T bytes = (name.size() + 1) * sizeof(wchar_t);
    void* remote_name = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE,
                                       PAGE_READWRITE);
    if (!remote_name) fail("VirtualAllocEx(dependency name) failed");
    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote_name, name.c_str(), bytes, &written) ||
        written != bytes) {
        fail("WriteProcessMemory(dependency name) failed");
    }
    remote_call3(process, primary_thread, remote_load_library,
                 reinterpret_cast<std::uint64_t>(remote_name), 0, 0);
    VirtualFreeEx(process, remote_name, 0, MEM_RELEASE);
    if (!remote_module_base(pid, std::filesystem::path(name).filename().wstring())) {
        fail("Target could not load dependency: " +
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

#pragma pack(push, 1)
struct ZloContext64 {
    std::uint32_t magic;
    std::uint8_t status;
    std::uint64_t original_rip;
    std::uint64_t mapper_address;
    std::uint64_t image_base;
    std::uint32_t result;
    std::uint32_t last_error;
};
#pragma pack(pop)
static_assert(sizeof(ZloContext64) == 37);

} // namespace

std::vector<std::uint8_t> prepare_zclient_loader_image(
    const std::filesystem::path& image_path, const std::string& service_host,
    const std::string& instance_name) {
    std::vector<std::uint8_t> file = read_file(image_path);
    if (file.size() < sizeof(IMAGE_DOS_HEADER)) {
        fail("Bootstrap is not a valid PE image.");
    }
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(file.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
        static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) >
            file.size()) {
        fail("Bootstrap is not a valid PE image.");
    }
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(file.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        fail("Bootstrap must be a 64-bit PE image.");
    }

    std::vector<std::uint8_t> mapped(nt->OptionalHeader.SizeOfImage, 0);
    if (nt->OptionalHeader.SizeOfHeaders > file.size() ||
        nt->OptionalHeader.SizeOfHeaders > mapped.size()) {
        fail("Malformed PE image: headers exceed file size.");
    }
    std::memcpy(mapped.data(), file.data(), nt->OptionalHeader.SizeOfHeaders);
    const auto* sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const auto& section = sections[i];
        if (!section.SizeOfRawData) continue;
        if (static_cast<std::size_t>(section.PointerToRawData) +
                    section.SizeOfRawData > file.size() ||
            static_cast<std::size_t>(section.VirtualAddress) +
                    section.SizeOfRawData > mapped.size()) {
            fail("Malformed PE image: section is out of range.");
        }
        std::memcpy(mapped.data() + section.VirtualAddress,
                    file.data() + section.PointerToRawData,
                    section.SizeOfRawData);
    }

    patch_loader_dns_redirect(mapped, service_host);
    patch_loader_connect_redirect(mapped, service_host);
    patch_loader_instance_names(mapped, instance_name);

    // Convert the modified loaded-image RVAs back into the raw PE layout used
    // by CLoader's child-process injector through the named mapping.
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const auto& section = sections[i];
        if (!section.SizeOfRawData) continue;
        std::memcpy(file.data() + section.PointerToRawData,
                    mapped.data() + section.VirtualAddress,
                    section.SizeOfRawData);
    }
    return file;
}

std::vector<std::uint8_t> prepare_zclient_loader_names_only(
    const std::filesystem::path& image_path, const std::string& instance_name) {
    auto image = read_file(image_path);
    patch_loader_instance_names(image, instance_name);
    return image;
}

void patch_game_blaze_redirector(HANDLE process,
                                 const std::string& service_host) {
    patch_game_blaze_redirector_impl(process, service_host);
}

void patch_cmain_lsx_redirect(HANDLE process,
                              const std::string& service_host) {
    patch_cmain_lsx_redirect_impl(process, service_host);
}

std::uint16_t read_lsx_shim_port(DWORD process_id) {
    const std::wstring name = L"Local\\ZClient_LsxShimPort_" +
                              std::to_wstring(process_id);
    Handle mapping(OpenFileMappingW(FILE_MAP_READ, FALSE, name.c_str()));
    if (!mapping) fail("OpenFileMappingW(LSX shim port) failed");
    void* view = MapViewOfFile(mapping.get(), FILE_MAP_READ, 0, 0,
                               sizeof(std::uint16_t));
    if (!view) fail("MapViewOfFile(LSX shim port) failed");
    std::uint16_t port = 0;
    std::memcpy(&port, view, sizeof(port));
    UnmapViewOfFile(view);
    if (!port) fail("LSX shim published an invalid port.");
    return port;
}

void install_lsx_callback_redirect(HANDLE process, std::uint64_t loader_base,
                                   std::uint16_t local_port) {
    // CLoaderx64 stores the endpoint callback registered by CMain here. The
    // recovered image's preferred base is 0x26af30000 and the slot is
    // qword_26b2e91b8 (qword_26b2e89e0 + 251).
    constexpr std::uintptr_t kCallbackSlotRva = 0x3B91B8;
    auto* callback_slot = reinterpret_cast<void*>(loader_base + kCallbackSlotRva);
    std::uint64_t original = 0;
    SIZE_T transferred = 0;
    if (!ReadProcessMemory(process, callback_slot, &original, sizeof(original),
                           &transferred) || transferred != sizeof(original) || !original) {
        fail("ReadProcessMemory(CLoader LSX callback) failed");
    }

    // bool callback(SOCKET, uint32_t* address, uint16_t* port, sockaddr*).
    // Chain CMain first, then override only LSX endpoints. Address is in the
    // sockaddr's byte order while the callback port value is host order.
    std::vector<std::uint8_t> code = {
        0x48, 0x83, 0xEC, 0x38,                   // sub rsp, 38h
        0x48, 0x89, 0x54, 0x24, 0x20,             // mov [rsp+20h], rdx
        0x4C, 0x89, 0x44, 0x24, 0x28,             // mov [rsp+28h], r8
        0x48, 0xB8,                               // mov rax, original
        0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xD0,                               // call rax
        0x48, 0x8B, 0x54, 0x24, 0x20,             // mov rdx, [rsp+20h]
        0x4C, 0x8B, 0x44, 0x24, 0x28,             // mov r8, [rsp+28h]
        0x66, 0x41, 0x81, 0x38, 0x20, 0x18,       // cmp word [r8], 6176
        0x74, 0x08,                               // je redirect
        0x66, 0x41, 0x81, 0x38, 0x18, 0x20,       // cmp word [r8], 8216
        0x75, 0x0E,                               // jne done
        0xC7, 0x02, 0x7F, 0x00, 0x00, 0x01,       // mov dword [rdx], 0100007fh
        0x66, 0x41, 0xC7, 0x00, 0, 0,             // mov word [r8], local_port
        0xB0, 0x01,                               // mov al, 1
        0x48, 0x83, 0xC4, 0x38,                   // add rsp, 38h
        0xC3                                      // ret
    };
    std::memcpy(code.data() + 16, &original, sizeof(original));
    std::memcpy(code.data() + 62, &local_port, sizeof(local_port));
    void* remote_code = VirtualAllocEx(process, nullptr, code.size(),
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
    if (!remote_code) fail("VirtualAllocEx(LSX callback redirect) failed");
    if (!WriteProcessMemory(process, remote_code, code.data(), code.size(),
                            &transferred) || transferred != code.size()) {
        fail("WriteProcessMemory(LSX callback redirect) failed");
    }
    const std::uint64_t replacement = reinterpret_cast<std::uint64_t>(remote_code);
    if (!WriteProcessMemory(process, callback_slot, &replacement,
                            sizeof(replacement), &transferred) ||
        transferred != sizeof(replacement)) {
        fail("WriteProcessMemory(CLoader LSX callback) failed");
    }
    FlushInstructionCache(process, remote_code, code.size());
    std::cout << "Redirected CLoader LSX callback to private port "
              << local_port << '\n';
}

ManualMapResult manual_map_zclient_loader(
    HANDLE process, HANDLE primary_thread, DWORD process_id,
    const std::filesystem::path& image_path, const std::string& service_host,
    const std::string& lsx_host, const std::string& instance_name,
    const std::filesystem::path& preload_dll) {
    std::vector<std::uint8_t> file = read_file(image_path);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(file.data());
    if (file.size() < sizeof(*dos) || dos->e_magic != IMAGE_DOS_SIGNATURE ||
        dos->e_lfanew <= 0 ||
        static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > file.size()) {
        fail("Bootstrap is not a valid PE image.");
    }
    auto* nt_file = reinterpret_cast<IMAGE_NT_HEADERS64*>(file.data() + dos->e_lfanew);
    if (nt_file->Signature != IMAGE_NT_SIGNATURE ||
        nt_file->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt_file->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        fail("Bootstrap must be a 64-bit PE image.");
    }

    // Never resume the target into the x64 entry gate until the bootstrap has
    // been proven compatible. In particular, a PE32 game must be dispatched to
    // the native Win32 helper by the caller instead of reaching this path.
    const EntryGate entry_gate = start_at_loader_initialized_gate(
        process, primary_thread, process_id);

    const auto image_size = nt_file->OptionalHeader.SizeOfImage;
    std::vector<std::uint8_t> image(image_size, 0);
    if (nt_file->OptionalHeader.SizeOfHeaders > file.size()) {
        fail("Malformed PE image: headers exceed file size.");
    }
    std::memcpy(image.data(), file.data(), nt_file->OptionalHeader.SizeOfHeaders);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    auto* sections = IMAGE_FIRST_SECTION(nt_file);
    for (WORD i = 0; i < nt_file->FileHeader.NumberOfSections; ++i) {
        const auto& section = sections[i];
        if (!section.SizeOfRawData) continue;
        if (static_cast<std::size_t>(section.PointerToRawData) + section.SizeOfRawData >
                file.size() ||
            static_cast<std::size_t>(section.VirtualAddress) + section.SizeOfRawData >
                image.size()) {
            fail("Malformed PE image: section is out of range.");
        }
        std::memcpy(image.data() + section.VirtualAddress,
                    file.data() + section.PointerToRawData, section.SizeOfRawData);
    }
    patch_loader_dns_redirect(image, service_host);
    patch_loader_connect_redirect(image, service_host);
    patch_loader_instance_names(image, instance_name);

    void* remote_image = VirtualAllocEx(
        process, reinterpret_cast<void*>(nt->OptionalHeader.ImageBase), image_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_image) {
        remote_image = VirtualAllocEx(process, nullptr, image_size,
                                      MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
    }
    if (!remote_image) fail("VirtualAllocEx(mapped image) failed");
    const std::uint64_t remote_base = reinterpret_cast<std::uint64_t>(remote_image);
    const std::int64_t delta = static_cast<std::int64_t>(
        remote_base - nt->OptionalHeader.ImageBase);

    const auto& reloc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (delta != 0) {
        if (!reloc_dir.VirtualAddress || !reloc_dir.Size) {
            fail("Bootstrap cannot be relocated.");
        }
        DWORD consumed = 0;
        while (consumed < reloc_dir.Size) {
            auto* block = at<IMAGE_BASE_RELOCATION>(image,
                reloc_dir.VirtualAddress + consumed);
            if (block->SizeOfBlock < sizeof(*block)) break;
            const DWORD count = (block->SizeOfBlock - sizeof(*block)) / sizeof(WORD);
            auto* entries = at<WORD>(image,
                reloc_dir.VirtualAddress + consumed + sizeof(*block));
            for (DWORD i = 0; i < count; ++i) {
                const WORD type = entries[i] >> 12;
                const WORD offset = entries[i] & 0x0FFF;
                if (type == IMAGE_REL_BASED_DIR64) {
                    *at<std::uint64_t>(image, block->VirtualAddress + offset) += delta;
                } else if (type != IMAGE_REL_BASED_ABSOLUTE) {
                    fail("Unsupported PE relocation type.");
                }
            }
            consumed += block->SizeOfBlock;
        }
    }
    nt->OptionalHeader.ImageBase = remote_base;

    const auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.VirtualAddress) {
        auto* descriptor = at<IMAGE_IMPORT_DESCRIPTOR>(image, import_dir.VirtualAddress);
        for (; descriptor->Name; ++descriptor) {
            const char* narrow_name = reinterpret_cast<const char*>(
                at<std::uint8_t>(image, descriptor->Name));
            const int wide_length = MultiByteToWideChar(CP_ACP, 0, narrow_name, -1,
                                                        nullptr, 0);
            std::wstring wide_name(wide_length, L'\0');
            MultiByteToWideChar(CP_ACP, 0, narrow_name, -1, wide_name.data(), wide_length);
            wide_name.resize(wcslen(wide_name.c_str()));
            HMODULE local_module = LoadLibraryW(wide_name.c_str());
            if (!local_module) fail("LoadLibraryW(dependency) failed");
            remote_load_dependency(process, primary_thread, process_id, wide_name);

            const DWORD lookup_rva = descriptor->OriginalFirstThunk
                                         ? descriptor->OriginalFirstThunk
                                         : descriptor->FirstThunk;
            auto* lookup = at<IMAGE_THUNK_DATA64>(image, lookup_rva);
            auto* iat = at<IMAGE_THUNK_DATA64>(image, descriptor->FirstThunk);
            for (; lookup->u1.AddressOfData; ++lookup, ++iat) {
                FARPROC proc = nullptr;
                if (IMAGE_SNAP_BY_ORDINAL64(lookup->u1.Ordinal)) {
                    proc = GetProcAddress(local_module,
                        reinterpret_cast<LPCSTR>(IMAGE_ORDINAL64(lookup->u1.Ordinal)));
                } else {
                    auto* by_name = at<IMAGE_IMPORT_BY_NAME>(
                        image, static_cast<DWORD>(lookup->u1.AddressOfData));
                    proc = GetProcAddress(local_module,
                                          reinterpret_cast<char*>(by_name->Name));
                }
                if (!proc) fail("GetProcAddress(import) failed");
                HMODULE owner = nullptr;
                if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                        reinterpret_cast<LPCWSTR>(proc), &owner)) {
                    fail("GetModuleHandleExW(import owner) failed");
                }
                remote_load_dependency(process, primary_thread, process_id,
                                       module_basename(owner));
                iat->u1.Function = remote_address_for_local(process_id, proc);
            }
        }
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote_image, image.data(), image.size(), &written) ||
        written != image.size()) {
        fail("WriteProcessMemory(mapped image) failed");
    }

    const auto& exception_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exception_dir.VirtualAddress && exception_dir.Size) {
        std::cout << "Registering x64 unwind table...\n";
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        FARPROC rtl_add = GetProcAddress(ntdll, "RtlAddFunctionTable");
        if (!rtl_add || !remote_call3(process, primary_thread,
                remote_address_for_local(process_id, rtl_add),
                remote_base + exception_dir.VirtualAddress,
                exception_dir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), remote_base)) {
            fail("RtlAddFunctionTable failed for mapped image.");
        }
    }

    // Start the in-process shim before any mapped CLoader initialization runs.
    // CLoader and the game may query and cache the machine identity from
    // GetAdaptersAddresses during TLS callbacks, DllMain, or ZLO. Loading the
    // shim afterward is too late to give each local instance a distinct
    // transport identity.
    std::uint16_t lsx_shim_port = 0;
    if (!preload_dll.empty()) {
        const std::wstring ready_name = L"Local\\ZClient_LsxShimReady_" +
                                        std::to_wstring(process_id);
        Handle ready_event(CreateEventW(nullptr, TRUE, FALSE, ready_name.c_str()));
        if (!ready_event) fail("CreateEventW(LSX shim ready) failed");
        remote_load_dependency(process, primary_thread, process_id,
                               std::filesystem::absolute(preload_dll).wstring());
        const DWORD ready = WaitForSingleObject(ready_event.get(), 10000);
        if (ready != WAIT_OBJECT_0) {
            fail(
                ready == WAIT_TIMEOUT
                    ? "Timed out waiting for the in-process LSX shim."
                    : "Waiting for the in-process LSX shim failed.");
        }
        lsx_shim_port = read_lsx_shim_port(process_id);
        std::cout << "In-process LSX shim is ready before CLoader initialization; trace: "
                  << (std::filesystem::absolute(preload_dll).parent_path() /
                      (L"ZClient.LsxShim-" + std::to_wstring(process_id) + L".log"))
                  << '\n';
    }

    const auto& tls_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls_dir.VirtualAddress && tls_dir.Size >= sizeof(IMAGE_TLS_DIRECTORY64)) {
        auto* tls = at<IMAGE_TLS_DIRECTORY64>(image, tls_dir.VirtualAddress);
        const SIZE_T raw_tls_size = static_cast<SIZE_T>(
            tls->EndAddressOfRawData - tls->StartAddressOfRawData);
        const SIZE_T tls_block_size = raw_tls_size + tls->SizeOfZeroFill;
        if (tls->AddressOfIndex && tls_block_size) {
            std::cout << "Initializing static TLS...\n";
            HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
            FARPROC tls_alloc = GetProcAddress(kernel32, "TlsAlloc");
            FARPROC tls_set_value = GetProcAddress(kernel32, "TlsSetValue");
            if (!tls_alloc || !tls_set_value) {
                fail("Could not resolve TLS initialization APIs");
            }
            const DWORD tls_index = remote_call3(
                process, primary_thread,
                remote_address_for_local(process_id, tls_alloc), 0, 0, 0);
            if (tls_index == TLS_OUT_OF_INDEXES) {
                fail("TlsAlloc failed in target process.");
            }

            void* remote_tls = VirtualAllocEx(process, nullptr, tls_block_size,
                                               MEM_COMMIT | MEM_RESERVE,
                                               PAGE_READWRITE);
            if (!remote_tls) fail("VirtualAllocEx(static TLS block) failed");
            const auto tls_template_rva = static_cast<std::size_t>(
                tls->StartAddressOfRawData - remote_base);
            if (raw_tls_size &&
                (!WriteProcessMemory(process, remote_tls,
                                     at<std::uint8_t>(image, tls_template_rva),
                                     raw_tls_size, &written) ||
                 written != raw_tls_size)) {
                fail("WriteProcessMemory(static TLS template) failed");
            }
            if (!WriteProcessMemory(
                    process, reinterpret_cast<void*>(tls->AddressOfIndex),
                    &tls_index, sizeof(tls_index), &written) ||
                written != sizeof(tls_index)) {
                fail("WriteProcessMemory(TLS index) failed");
            }
            const DWORD tls_set = remote_call3(
                process, primary_thread,
                remote_address_for_local(process_id, tls_set_value), tls_index,
                reinterpret_cast<std::uint64_t>(remote_tls), 0);
            if (!tls_set) {
                fail("TlsSetValue failed in target process.");
            }
        }
        if (tls->AddressOfCallBacks) {
            std::cout << "Running TLS callbacks...\n";
            const auto callback_rva = static_cast<std::size_t>(
                tls->AddressOfCallBacks - remote_base);
            auto* callbacks = at<std::uint64_t>(image, callback_rva);
            for (; *callbacks; ++callbacks) {
                remote_call3(process, primary_thread, *callbacks, remote_base,
                             DLL_PROCESS_ATTACH, 0);
            }
        }
    }

    // CLoader requires its private bootstrap context as DllMain's lpReserved
    // argument. A null value makes process attach fail intentionally.
    ZloContext64 context{0xDEADBEEF, 0, entry_gate.original_entry, 0,
                         remote_base, 0, 0};
    void* remote_context = VirtualAllocEx(process, nullptr, sizeof(context),
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_READWRITE);
    if (!remote_context) fail("VirtualAllocEx(ZLO context) failed");
    if (!WriteProcessMemory(process, remote_context, &context, sizeof(context),
                            &written) || written != sizeof(context)) {
        fail("WriteProcessMemory(ZLO context) failed");
    }

    if (nt->OptionalHeader.AddressOfEntryPoint) {
        std::cout << "Calling mapped DllMain...\n";
        // sleep for 10 seconds
        //Sleep(10000);
        const DWORD attached = remote_call3(
            process, primary_thread,
            remote_base + nt->OptionalHeader.AddressOfEntryPoint,
            remote_base, DLL_PROCESS_ATTACH,
            reinterpret_cast<std::uint64_t>(remote_context));
        if (!attached) fail("Mapped loader DllMain rejected attach.");
    }

    DWORD zlo_rva = 0;
    const auto& export_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_dir.VirtualAddress) {
        auto* exports = at<IMAGE_EXPORT_DIRECTORY>(image, export_dir.VirtualAddress);
        auto* names = at<DWORD>(image, exports->AddressOfNames);
        auto* ordinals = at<WORD>(image, exports->AddressOfNameOrdinals);
        auto* functions = at<DWORD>(image, exports->AddressOfFunctions);
        for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
            const char* name = reinterpret_cast<const char*>(at<std::uint8_t>(image, names[i]));
            if (std::strcmp(name, "ZLO") == 0) {
                zlo_rva = functions[ordinals[i]];
                break;
            }
        }
    }
    if (!zlo_rva) fail("Mapped loader has no ZLO export.");

    const std::uint8_t mapped_status = 2;
    if (!WriteProcessMemory(process,
                            static_cast<std::uint8_t*>(remote_context) +
                                offsetof(ZloContext64, status),
                            &mapped_status, sizeof(mapped_status), &written) ||
        written != sizeof(mapped_status)) {
        fail("WriteProcessMemory(updated ZLO status) failed");
    }
    // Patch the game's redirector strings before CLoader's ZLO export runs.
    // ZLO initializes the network hooks and may cache the destination during
    // that call; changing the image afterward leaves its loopback proxy aimed
    // at the original production redirector.
    patch_game_blaze_redirector_impl(process, service_host);

    std::cout << "Calling ZLO bootstrap export...\n";
    remote_call3(process, primary_thread, remote_base + zlo_rva,
                 reinterpret_cast<std::uint64_t>(remote_context), 0, 0);
    if (!ReadProcessMemory(process, remote_context, &context, sizeof(context), nullptr)) {
        fail("ReadProcessMemory(ZLO context) failed");
    }
    if (context.result != 0) {
        fail("ZLO bootstrap failed (status " +
                                 std::to_string(context.result) + ", detail " +
                                 std::to_string(context.last_error) + ").");
    }

    patch_cmain_lsx_redirect_impl(process, lsx_host);

    if (lsx_shim_port) {
        install_lsx_callback_redirect(process, remote_base, lsx_shim_port);
        const std::wstring process_suffix = std::to_wstring(process_id);
        const std::wstring enable_name =
            L"Local\\ZClient_LsxShimEnableNetwork_" + process_suffix;
        const std::wstring network_ready_name =
            L"Local\\ZClient_LsxShimNetworkReady_" + process_suffix;
        Handle enable_event(OpenEventW(EVENT_MODIFY_STATE, FALSE,
                                       enable_name.c_str()));
        Handle network_ready_event(OpenEventW(SYNCHRONIZE, FALSE,
                                              network_ready_name.c_str()));
        if (!enable_event || !network_ready_event) {
            fail("OpenEventW(LSX shim network activation) failed");
        }
        if (!SetEvent(enable_event.get())) {
            fail("SetEvent(LSX shim network activation) failed");
        }
        const DWORD network_ready =
            WaitForSingleObject(network_ready_event.get(), 10000);
        if (network_ready != WAIT_OBJECT_0) {
            fail(
                network_ready == WAIT_TIMEOUT
                    ? "Timed out enabling LSX shim network hooks."
                    : "Waiting for LSX shim network hooks failed.");
        }
        std::cout << "In-process LSX shim network hooks are active\n";
    }

    auto* mapped_sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const auto& section = mapped_sections[i];
        const SIZE_T size = section.Misc.VirtualSize
                                ? section.Misc.VirtualSize
                                : section.SizeOfRawData;
        if (!size) continue;
        DWORD old_protection = 0;
        if (!VirtualProtectEx(process,
                reinterpret_cast<void*>(remote_base + section.VirtualAddress), size,
                section_protection(section.Characteristics), &old_protection)) {
            fail("VirtualProtectEx(mapped section) failed");
        }
    }
    FlushInstructionCache(process, remote_image, image_size);

    // Diagnostic probes are intentionally disabled in the runnable build.
    // Their spin loops replace process-termination APIs and therefore alter
    // normal Origin helper cleanup.
    if constexpr (false) {
    // CLoader terminates a newly created child when its injection helper
    // returns 0x301, 0x504, or 0x508. Probe the call site before KernelBase's
    // TerminateProcess wrapper can reuse RDI and obscure that result.
    constexpr std::uintptr_t kChildTerminateSiteRva = 0x17A6A;
    auto* remote_child_probe = static_cast<std::uint8_t*>(VirtualAllocEx(
        process, nullptr, sizeof(ExitProbeData) + 160,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!remote_child_probe) fail("VirtualAllocEx(child probe) failed");
    const std::uint64_t child_probe_data =
        reinterpret_cast<std::uint64_t>(remote_child_probe);
    std::vector<std::uint8_t> child_code;
    auto cemit = [&](std::initializer_list<std::uint8_t> bytes) {
        child_code.insert(child_code.end(), bytes);
    };
    auto cemit_u64 = [&](std::uint64_t value) {
        const auto* p = reinterpret_cast<const std::uint8_t*>(&value);
        child_code.insert(child_code.end(), p, p + sizeof(value));
    };
    cemit({0x49, 0xBB}); cemit_u64(child_probe_data); // mov r11, data
    cemit({0x41, 0xC7, 0x03, 0, 0, 0, 0});          // exit_code = 0
    cemit({0x41, 0xC7, 0x43, 0x04, 1, 0, 0, 0});    // triggered = 1
    cemit({0x49, 0x8B, 0x0C, 0x24});                // rcx = [r12]
    cemit({0x49, 0x89, 0x4B, 0x08});                // process_handle = rcx
    cemit({0x49, 0x89, 0x7B, 0x10});                // caller_status = rdi
    cemit({0x49, 0x89, 0x43, 0x18});                // entry_rax = rax
    for (std::uint8_t i = 0; i < 8; ++i) {
        if (i == 0) cemit({0x48, 0x8B, 0x14, 0x24});
        else cemit({0x48, 0x8B, 0x54, 0x24,
                    static_cast<std::uint8_t>(i * 8)});
        cemit({0x49, 0x89, 0x53,
               static_cast<std::uint8_t>(32 + i * 8)});
    }
    // The injector context is CLoader's global object.  +0x6c holds the
    // Win32 detail set by its child-mapping implementation and +0x38 is the
    // shared bootstrap image size.  Retain both before stopping at the
    // failure boundary.
    cemit({0x49, 0xBB}); cemit_u64(remote_base + 0x3B75E0);
    cemit({0x41, 0x8B, 0x43, 0x6C});
    cemit({0x41, 0x89, 0x43, 0x60});
    cemit({0x41, 0x8B, 0x43, 0x38});
    cemit({0x41, 0x89, 0x43, 0x64});
    cemit({0xF3, 0x90, 0xEB, 0xFC});
    auto* remote_child_code = remote_child_probe + sizeof(ExitProbeData);
    ExitProbeData empty_child_probe{};
    if (!WriteProcessMemory(process, remote_child_probe, &empty_child_probe,
                            sizeof(empty_child_probe), &written) ||
        !WriteProcessMemory(process, remote_child_code, child_code.data(),
                            child_code.size(), &written)) {
        fail("WriteProcessMemory(child probe) failed");
    }
    std::array<std::uint8_t, 12> child_jump{
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0};
    const std::uint64_t child_code_address =
        reinterpret_cast<std::uint64_t>(remote_child_code);
    std::memcpy(child_jump.data() + 2, &child_code_address,
                sizeof(child_code_address));
    void* child_site = reinterpret_cast<void*>(
        remote_base + kChildTerminateSiteRva);
    DWORD old_child_protection = 0;
    if (!VirtualProtectEx(process, child_site, child_jump.size(),
                          PAGE_EXECUTE_READWRITE, &old_child_protection) ||
        !WriteProcessMemory(process, child_site, child_jump.data(),
                            child_jump.size(), &written)) {
        fail("Install child-injection probe failed");
    }
    DWORD ignored_child_protection = 0;
    VirtualProtectEx(process, child_site, child_jump.size(),
                     old_child_protection, &ignored_child_protection);
    FlushInstructionCache(process, child_site, child_jump.size());

    const auto local_ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto local_exit = GetProcAddress(local_ntdll, "RtlExitUserProcess");
    if (!local_exit) fail("GetProcAddress(RtlExitUserProcess) failed");
    const std::uintptr_t remote_exit =
        remote_address_for_local(process_id, local_exit);
    constexpr SIZE_T kProbeSize = sizeof(ExitProbeData) + 160;
    auto* remote_probe = static_cast<std::uint8_t*>(VirtualAllocEx(
        process, nullptr, kProbeSize, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
    if (!remote_probe) fail("VirtualAllocEx(exit probe) failed");
    const std::uint64_t probe_data = reinterpret_cast<std::uint64_t>(remote_probe);
    std::vector<std::uint8_t> probe_code;
    auto emit = [&](std::initializer_list<std::uint8_t> bytes) {
        probe_code.insert(probe_code.end(), bytes);
    };
    auto emit_u64 = [&](std::uint64_t value) {
        const auto* p = reinterpret_cast<const std::uint8_t*>(&value);
        probe_code.insert(probe_code.end(), p, p + sizeof(value));
    };
    emit({0x48, 0xB8}); emit_u64(probe_data);
    emit({0x89, 0x08});
    emit({0xC7, 0x40, 0x04, 1, 0, 0, 0});
    for (std::uint8_t i = 0; i < 8; ++i) {
        if (i == 0) emit({0x48, 0x8B, 0x14, 0x24});
        else emit({0x48, 0x8B, 0x54, 0x24,
                   static_cast<std::uint8_t>(i * 8)});
        emit({0x48, 0x89, 0x50,
              static_cast<std::uint8_t>(32 + i * 8)});
    }
    emit({0xF3, 0x90, 0xEB, 0xFC});
    auto* remote_probe_code = remote_probe + sizeof(ExitProbeData);
    ExitProbeData empty_probe{};
    if (!WriteProcessMemory(process, remote_probe, &empty_probe,
                            sizeof(empty_probe), &written) ||
        !WriteProcessMemory(process, remote_probe_code, probe_code.data(),
                            probe_code.size(), &written)) {
        fail("WriteProcessMemory(exit probe) failed");
    }
    std::array<std::uint8_t, 12> exit_jump{
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0};
    const std::uint64_t probe_code_address =
        reinterpret_cast<std::uint64_t>(remote_probe_code);
    std::memcpy(exit_jump.data() + 2, &probe_code_address,
                sizeof(probe_code_address));
    DWORD old_exit_protection = 0;
    if (!VirtualProtectEx(process, reinterpret_cast<void*>(remote_exit),
                          exit_jump.size(), PAGE_EXECUTE_READWRITE,
                          &old_exit_protection) ||
        !WriteProcessMemory(process, reinterpret_cast<void*>(remote_exit),
                            exit_jump.data(), exit_jump.size(), &written)) {
        fail("Install RtlExitUserProcess probe failed");
    }
    DWORD ignored_protection = 0;
    VirtualProtectEx(process, reinterpret_cast<void*>(remote_exit),
                     exit_jump.size(), old_exit_protection, &ignored_protection);
    FlushInstructionCache(process, reinterpret_cast<void*>(remote_exit),
                          exit_jump.size());

    const auto local_terminate = GetProcAddress(local_ntdll, "NtTerminateProcess");
    if (!local_terminate) fail("GetProcAddress(NtTerminateProcess) failed");
    const std::uintptr_t remote_terminate =
        remote_address_for_local(process_id, local_terminate);
    auto* remote_terminate_probe = static_cast<std::uint8_t*>(VirtualAllocEx(
        process, nullptr, kProbeSize, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
    if (!remote_terminate_probe) fail("VirtualAllocEx(terminate probe) failed");
    const std::uint64_t terminate_data =
        reinterpret_cast<std::uint64_t>(remote_terminate_probe);
    std::vector<std::uint8_t> terminate_code;
    auto temit = [&](std::initializer_list<std::uint8_t> bytes) {
        terminate_code.insert(terminate_code.end(), bytes);
    };
    auto temit_u64 = [&](std::uint64_t value) {
        const auto* p = reinterpret_cast<const std::uint8_t*>(&value);
        terminate_code.insert(terminate_code.end(), p, p + sizeof(value));
    };
    temit({0x49, 0xB8}); temit_u64(terminate_data); // mov r8, data
    temit({0x41, 0x89, 0x10});                     // exit_code = edx
    temit({0x41, 0xC7, 0x40, 0x04, 1, 0, 0, 0});  // triggered = 1
    temit({0x49, 0x89, 0x48, 0x08});               // process_handle = rcx
    temit({0x49, 0x89, 0x78, 0x10});               // caller_status = rdi
    temit({0x49, 0x89, 0x40, 0x18});               // entry_rax = rax
    for (std::uint8_t i = 0; i < 8; ++i) {
        if (i == 0) temit({0x48, 0x8B, 0x14, 0x24});
        else temit({0x48, 0x8B, 0x54, 0x24,
                    static_cast<std::uint8_t>(i * 8)});
        temit({0x49, 0x89, 0x50,
               static_cast<std::uint8_t>(32 + i * 8)});
    }
    temit({0xF3, 0x90, 0xEB, 0xFC}); // pause; spin at fatal boundary
    auto* remote_terminate_code =
        remote_terminate_probe + sizeof(ExitProbeData);
    if (!WriteProcessMemory(process, remote_terminate_probe, &empty_probe,
                            sizeof(empty_probe), &written) ||
        !WriteProcessMemory(process, remote_terminate_code,
                            terminate_code.data(), terminate_code.size(),
                            &written)) {
        fail("WriteProcessMemory(terminate probe) failed");
    }
    std::array<std::uint8_t, 12> terminate_jump{
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0};
    const std::uint64_t terminate_code_address =
        reinterpret_cast<std::uint64_t>(remote_terminate_code);
    std::memcpy(terminate_jump.data() + 2, &terminate_code_address,
                sizeof(terminate_code_address));
    DWORD old_terminate_protection = 0;
    if (!VirtualProtectEx(process, reinterpret_cast<void*>(remote_terminate),
                          terminate_jump.size(), PAGE_EXECUTE_READWRITE,
                          &old_terminate_protection) ||
        !WriteProcessMemory(process, reinterpret_cast<void*>(remote_terminate),
                            terminate_jump.data(), terminate_jump.size(),
                            &written)) {
        fail("Install NtTerminateProcess probe failed");
    }
    VirtualProtectEx(process, reinterpret_cast<void*>(remote_terminate),
                     terminate_jump.size(), old_terminate_protection,
                     &ignored_protection);
    FlushInstructionCache(process, reinterpret_cast<void*>(remote_terminate),
                          terminate_jump.size());
    release_entry_gate(process, entry_gate);
    // CMain continues to use this context asynchronously. In particular it
    // writes its post-load failure code at +29 and Win32/detail value at +33.
    return {reinterpret_cast<std::uintptr_t>(remote_context),
            reinterpret_cast<std::uintptr_t>(remote_probe),
            reinterpret_cast<std::uintptr_t>(remote_terminate_probe),
            reinterpret_cast<std::uintptr_t>(remote_child_probe)};
    }
    release_entry_gate(process, entry_gate);
    return {reinterpret_cast<std::uintptr_t>(remote_context), 0, 0, 0};
}
