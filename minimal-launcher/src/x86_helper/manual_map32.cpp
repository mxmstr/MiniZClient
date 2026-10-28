#include "manual_map32.h"

#include <tlhelp32.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#if defined(_WIN64)
#error manual_map32.cpp must be built for Win32, not x64.
#endif

namespace {

class Handle {
public:
    explicit Handle(HANDLE value = nullptr) : value_(value) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value_(other.release()) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) reset(other.release());
        return *this;
    }
    [[nodiscard]] HANDLE get() const { return value_; }
    [[nodiscard]] explicit operator bool() const {
        return value_ && value_ != INVALID_HANDLE_VALUE;
    }
    HANDLE release() {
        HANDLE result = value_;
        value_ = nullptr;
        return result;
    }
    void reset(HANDLE value = nullptr) {
        if (*this) CloseHandle(value_);
        value_ = value;
    }

private:
    HANDLE value_ = nullptr;
};

[[noreturn]] void fail(const std::string& message,
                       DWORD error = GetLastError()) {
    throw std::runtime_error(message + " (Win32 " +
                             std::to_string(error) + ")");
}

std::vector<std::uint8_t> read_file(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) fail("Could not open x86 bootstrap image");
    const auto size = stream.tellg();
    if (size <= 0) throw std::runtime_error("x86 bootstrap image is empty");
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    stream.seekg(0);
    if (!stream.read(reinterpret_cast<char*>(bytes.data()), size)) {
        fail("Could not read x86 bootstrap image");
    }
    return bytes;
}

template <typename T>
T* at(std::vector<std::uint8_t>& image, std::size_t offset) {
    if (offset > image.size() || sizeof(T) > image.size() - offset) {
        throw std::runtime_error("Malformed PE32 image: RVA is out of range");
    }
    return reinterpret_cast<T*>(image.data() + offset);
}

std::uint32_t address32(const void* address, const char* operation) {
    const auto value = reinterpret_cast<std::uintptr_t>(address);
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error(std::string(operation) +
                                 " returned an address outside the x86 address space");
    }
    return static_cast<std::uint32_t>(value);
}

void patch_loader_instance_names(std::vector<std::uint8_t>& image,
                                 const std::string& instance_name) {
    if (instance_name.size() != 7) {
        throw std::runtime_error("CLoader instance name must contain seven characters");
    }
    const std::array<std::pair<std::string_view, std::string>, 3> replacements{{
        {"\\\\.\\pipe\\ZClient", "\\\\.\\pipe\\" + instance_name},
        {"Global\\ZClient_CLoaderx64", "Global\\" + instance_name + "_CLoaderx64"},
        {"Global\\ZClient_CLoaderx32", "Global\\" + instance_name + "_CLoaderx32"},
    }};

    for (const auto& [original, replacement] : replacements) {
        if (replacement.size() != original.size()) {
            throw std::runtime_error("Internal CLoader namespace length mismatch");
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
            throw std::runtime_error("CLoader namespace signature was not found");
        }
    }
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
        if (error != ERROR_BAD_LENGTH) fail("CreateToolhelp32Snapshot failed", error);
        Sleep(2);
    }
    if (!snapshot) return 0;

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot.get(), &entry)) {
        fail("Module32FirstW failed");
    }
    do {
        if (_wcsicmp(entry.szModule, std::wstring(module_name).c_str()) == 0) {
            return reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
        }
    } while (Module32NextW(snapshot.get(), &entry));
    return 0;
}

std::wstring module_basename(HMODULE module) {
    std::array<wchar_t, 32768> path{};
    const DWORD length = GetModuleFileNameW(module, path.data(),
                                            static_cast<DWORD>(path.size()));
    if (!length || length == path.size()) fail("GetModuleFileNameW failed");
    return std::filesystem::path(std::wstring(path.data(), length))
        .filename().wstring();
}

std::uint32_t remote_address_for_local(DWORD process_id, FARPROC procedure) {
    const auto address = std::bit_cast<std::uintptr_t>(procedure);
    HMODULE owner = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(address), &owner)) {
        fail("GetModuleHandleExW(FROM_ADDRESS) failed");
    }
    const std::wstring name = module_basename(owner);
    const std::uintptr_t remote_base = remote_module_base(process_id, name);
    if (!remote_base) {
        throw std::runtime_error("Required x86 module is not loaded in target");
    }
    return static_cast<std::uint32_t>(
        remote_base + address - reinterpret_cast<std::uintptr_t>(owner));
}

struct EntryGate32 {
    std::uint8_t* remote = nullptr;
    std::uint32_t original_entry = 0;
};

EntryGate32 start_at_loader_initialized_gate(HANDLE process,
                                             HANDLE primary_thread,
                                             DWORD process_id) {
    CONTEXT context{};
    context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
    if (!GetThreadContext(primary_thread, &context)) {
        fail("GetThreadContext(x86 initial thread) failed");
    }
    if (!context.Eax) {
        throw std::runtime_error("Suspended x86 thread has no entry address in EAX");
    }

    // Windows' x86 RtlUserThreadStart receives the executable entry point in
    // EAX. Redirect that argument to this gate while allowing LdrInitializeThunk
    // to complete normally.
    std::array<std::uint8_t, 25> gate{
        0xC6, 0x05, 0, 0, 0, 0, 0x01, // mov byte ptr [reached], 1
        0x80, 0x3D, 0, 0, 0, 0, 0x00, // cmp byte ptr [release], 0
        0x74, 0xF7,                   // je cmp
        0xB8, 0, 0, 0, 0,             // mov eax, original entry
        0xFF, 0xE0,                   // jmp eax
        0x00,                         // release
        0x00,                         // reached
    };
    auto* remote = static_cast<std::uint8_t*>(VirtualAllocEx(
        process, nullptr, gate.size(), MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
    if (!remote) fail("VirtualAllocEx(x86 entry gate) failed");

    const std::uint32_t release = address32(remote + 23, "x86 entry gate");
    const std::uint32_t reached = address32(remote + 24, "x86 entry gate");
    std::memcpy(gate.data() + 2, &reached, sizeof(reached));
    std::memcpy(gate.data() + 9, &release, sizeof(release));
    std::memcpy(gate.data() + 18, &context.Eax, sizeof(context.Eax));

    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote, gate.data(), gate.size(), &written) ||
        written != gate.size()) {
        fail("WriteProcessMemory(x86 entry gate) failed");
    }
    FlushInstructionCache(process, remote, gate.size());

    const std::uint32_t original_entry = context.Eax;
    context.Eax = address32(remote, "x86 entry gate");
    if (!SetThreadContext(primary_thread, &context)) {
        fail("SetThreadContext(x86 entry gate) failed");
    }
    if (ResumeThread(primary_thread) == static_cast<DWORD>(-1)) {
        fail("ResumeThread(x86 entry gate) failed");
    }

    const ULONGLONG deadline = GetTickCount64() + 30000;
    for (;;) {
        std::uint8_t flag = 0;
        SIZE_T read = 0;
        if (!ReadProcessMemory(process, remote + 24, &flag, sizeof(flag), &read)) {
            fail("ReadProcessMemory(x86 entry gate) failed");
        }
        if (flag && remote_module_base(process_id, L"kernel32.dll") &&
            remote_module_base(process_id, L"kernelbase.dll")) {
            return {remote, original_entry};
        }
        if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) {
            throw std::runtime_error("Target exited before reaching its x86 entry gate");
        }
        if (GetTickCount64() >= deadline) {
            throw std::runtime_error(
                "Timed out waiting for the WOW64 loader to reach its x86 entry point");
        }
        Sleep(1);
    }
}

void release_entry_gate(HANDLE process, const EntryGate32& gate) {
    const std::uint8_t release = 1;
    SIZE_T written = 0;
    if (!WriteProcessMemory(process, gate.remote + 23, &release,
                            sizeof(release), &written) ||
        written != sizeof(release)) {
        fail("WriteProcessMemory(release x86 entry gate) failed");
    }
    FlushInstructionCache(process, gate.remote, 25);
}

#pragma pack(push, 1)
struct RemoteCall32Data {
    std::uint32_t result;
    std::uint8_t done;
};

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
static_assert(offsetof(ZloContext32, result) == 0x11);

std::uint32_t remote_call3(HANDLE process, HANDLE primary_thread,
                           std::uint32_t function, std::uint32_t arg1,
                           std::uint32_t arg2, std::uint32_t arg3) {
    // The saved CONTEXT restores EIP/ESP after the call, so this stub works for
    // both stdcall (DllMain/Win32 APIs) and the cdecl ZLO export.
    std::array<std::uint8_t, 40> code{
        0x68, 0, 0, 0, 0,             // push arg3
        0x68, 0, 0, 0, 0,             // push arg2
        0x68, 0, 0, 0, 0,             // push arg1
        0xB8, 0, 0, 0, 0,             // mov eax, function
        0xFF, 0xD0,                   // call eax
        0xA3, 0, 0, 0, 0,             // mov [result], eax
        0xC6, 0x05, 0, 0, 0, 0, 0x01, // mov byte ptr [done], 1
        0xF3, 0x90,                   // pause
        0xEB, 0xFC,                   // jmp pause
    };
    const SIZE_T total = sizeof(RemoteCall32Data) + code.size();
    auto* remote = static_cast<std::uint8_t*>(VirtualAllocEx(
        process, nullptr, total, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE));
    if (!remote) fail("VirtualAllocEx(x86 remote call) failed");

    struct RemoteFree {
        HANDLE process;
        void* address;
        ~RemoteFree() { VirtualFreeEx(process, address, 0, MEM_RELEASE); }
    } cleanup{process, remote};

    const std::uint32_t result_address = address32(remote, "x86 remote call");
    const std::uint32_t done_address = result_address +
                                       offsetof(RemoteCall32Data, done);
    std::memcpy(code.data() + 1, &arg3, sizeof(arg3));
    std::memcpy(code.data() + 6, &arg2, sizeof(arg2));
    std::memcpy(code.data() + 11, &arg1, sizeof(arg1));
    std::memcpy(code.data() + 16, &function, sizeof(function));
    std::memcpy(code.data() + 23, &result_address, sizeof(result_address));
    std::memcpy(code.data() + 29, &done_address, sizeof(done_address));

    const RemoteCall32Data empty{};
    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote, &empty, sizeof(empty), &written) ||
        written != sizeof(empty) ||
        !WriteProcessMemory(process, remote + sizeof(empty), code.data(),
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
    redirected.Eip = address32(remote + sizeof(empty), "x86 remote call");
    if (!SetThreadContext(primary_thread, &redirected)) {
        fail("SetThreadContext(x86 remote call) failed");
    }
    if (ResumeThread(primary_thread) == static_cast<DWORD>(-1)) {
        fail("ResumeThread(x86 remote call) failed");
    }

    RemoteCall32Data returned{};
    const ULONGLONG deadline = GetTickCount64() + 30000;
    for (;;) {
        if (!ReadProcessMemory(process, remote, &returned, sizeof(returned), nullptr)) {
            fail("ReadProcessMemory(x86 remote call) failed");
        }
        if (returned.done) break;
        if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) {
            throw std::runtime_error("Target exited during x86 bootstrap call");
        }
        if (GetTickCount64() >= deadline) {
            throw std::runtime_error("Timed out in x86 hijacked-thread call");
        }
        Sleep(1);
    }

    if (SuspendThread(primary_thread) == static_cast<DWORD>(-1)) {
        fail("SuspendThread(restore x86 remote call) failed");
    }
    if (!SetThreadContext(primary_thread, &saved)) {
        fail("SetThreadContext(restore x86 remote call) failed");
    }
    if (ResumeThread(primary_thread) == static_cast<DWORD>(-1)) {
        fail("ResumeThread(restore x86 remote call) failed");
    }
    return returned.result;
}

void remote_load_dependency(HANDLE process, HANDLE primary_thread,
                            DWORD process_id, const std::wstring& name) {
    const std::wstring basename =
        std::filesystem::path(name).filename().wstring();
    if (remote_module_base(process_id, basename)) return;

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC load_library = GetProcAddress(kernel32, "LoadLibraryW");
    if (!load_library) fail("GetProcAddress(LoadLibraryW) failed");
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
        fail("WriteProcessMemory(x86 dependency name) failed");
    }
    remote_call3(process, primary_thread, remote_load_library,
                  address32(remote_name, "x86 dependency name"), 0, 0);
    VirtualFreeEx(process, remote_name, 0, MEM_RELEASE);
    if (!remote_module_base(process_id, basename)) {
        throw std::runtime_error("Target could not load x86 dependency");
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
    constexpr std::array<std::string_view, 4> hostnames = {
        "gosredirector.online.ea.com",
        "gosredirector.stest.ea.com",
        "gosredirector.scert.ea.com",
        "gosredirector.ea.com",
    };
    if (service_host.empty() || service_host.size() > hostnames.back().size()) {
        throw std::runtime_error("Service host is too long for the game redirector slot");
    }

    SYSTEM_INFO system{};
    GetSystemInfo(&system);
    std::uintptr_t cursor = reinterpret_cast<std::uintptr_t>(
        system.lpMinimumApplicationAddress);
    const std::uintptr_t maximum = reinterpret_cast<std::uintptr_t>(
        system.lpMaximumApplicationAddress);
    struct Match { std::uintptr_t address; std::size_t length; };
    std::vector<Match> matches;
    constexpr SIZE_T chunk_size = 1u << 20;

    while (cursor < maximum) {
        MEMORY_BASIC_INFORMATION memory{};
        if (!VirtualQueryEx(process, reinterpret_cast<void*>(cursor), &memory,
                            sizeof(memory))) break;
        const auto base = reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
        const auto size = static_cast<std::size_t>(memory.RegionSize);
        if (memory.State == MEM_COMMIT &&
            !(memory.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
            for (std::size_t offset = 0; offset < size;) {
                const SIZE_T request = std::min<SIZE_T>(
                    chunk_size + hostnames.front().size(), size - offset);
                std::vector<std::uint8_t> bytes(request);
                SIZE_T read = 0;
                if (ReadProcessMemory(process,
                        reinterpret_cast<void*>(base + offset), bytes.data(),
                        request, &read)) {
                    const auto end = bytes.begin() + static_cast<std::ptrdiff_t>(read);
                    for (const auto hostname : hostnames) {
                        for (auto found = std::search(bytes.begin(), end,
                                                     hostname.begin(), hostname.end());
                             found != end;
                             found = std::search(found + 1, end,
                                                 hostname.begin(), hostname.end())) {
                            matches.push_back({base + offset +
                                static_cast<std::size_t>(found - bytes.begin()),
                                hostname.size()});
                        }
                    }
                }
                offset += std::min<std::size_t>(chunk_size, size - offset);
            }
        }
        if (!size || base + size <= cursor) break;
        cursor = base + size;
    }

    std::sort(matches.begin(), matches.end(),
              [](const Match& a, const Match& b) { return a.address < b.address; });
    matches.erase(std::unique(matches.begin(), matches.end(),
                              [](const Match& a, const Match& b) {
                                  return a.address == b.address;
                              }), matches.end());
    if (matches.empty()) {
        throw std::runtime_error("Could not locate a Blaze redirector hostname in the x86 game");
    }
    for (const Match& match : matches) {
        std::vector<char> replacement(match.length, '\0');
        std::copy(service_host.begin(), service_host.end(), replacement.begin());
        auto* target = reinterpret_cast<void*>(match.address);
        DWORD old = 0;
        if (!VirtualProtectEx(process, target, replacement.size(), PAGE_READWRITE,
                              &old)) {
            fail("VirtualProtectEx(x86 Blaze redirector) failed");
        }
        SIZE_T written = 0;
        const bool ok = WriteProcessMemory(process, target, replacement.data(),
                                           replacement.size(), &written) &&
                        written == replacement.size();
        const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        DWORD ignored = 0;
        VirtualProtectEx(process, target, replacement.size(), old, &ignored);
        if (!ok) fail("WriteProcessMemory(x86 Blaze redirector) failed", error);
    }
}

void wait_for_preload_ready(DWORD process_id) {
    const std::wstring ready_name = L"Local\\ZClient_LsxShimReady_" +
                                    std::to_wstring(process_id);
    Handle ready(CreateEventW(nullptr, TRUE, FALSE, ready_name.c_str()));
    if (!ready) fail("CreateEventW(x86 preload ready) failed");
    const DWORD wait = WaitForSingleObject(ready.get(), 10000);
    if (wait != WAIT_OBJECT_0) {
        throw std::runtime_error(wait == WAIT_TIMEOUT
            ? "Timed out waiting for the x86 preload DLL"
            : "Waiting for the x86 preload DLL failed");
    }
}

void activate_preload_network(DWORD process_id) {
    const std::wstring suffix = std::to_wstring(process_id);
    const std::wstring enable_name =
        L"Local\\ZClient_LsxShimEnableNetwork_" + suffix;
    const std::wstring ready_name =
        L"Local\\ZClient_LsxShimNetworkReady_" + suffix;
    Handle enable(OpenEventW(EVENT_MODIFY_STATE, FALSE, enable_name.c_str()));
    Handle ready(OpenEventW(SYNCHRONIZE, FALSE, ready_name.c_str()));
    if (!enable || !ready) {
        fail("OpenEventW(x86 preload network activation) failed");
    }
    if (!SetEvent(enable.get())) fail("SetEvent(x86 preload network activation) failed");
    const DWORD wait = WaitForSingleObject(ready.get(), 10000);
    if (wait != WAIT_OBJECT_0) {
        throw std::runtime_error(wait == WAIT_TIMEOUT
            ? "Timed out enabling x86 preload network hooks"
            : "Waiting for x86 preload network hooks failed");
    }
}

} // namespace

ManualMap32Result manual_map_zclient_loader32(
    HANDLE process, HANDLE primary_thread, DWORD process_id,
    const ManualMap32Options& options) {
    const EntryGate32 gate = start_at_loader_initialized_gate(
        process, primary_thread, process_id);

    std::vector<std::uint8_t> file = read_file(options.loader);
    if (file.size() < sizeof(IMAGE_DOS_HEADER)) {
        throw std::runtime_error("Bootstrap is not a valid PE32 image");
    }
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(file.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
        static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS32) >
            file.size()) {
        throw std::runtime_error("Bootstrap is not a valid PE32 image");
    }
    auto* nt_file = reinterpret_cast<IMAGE_NT_HEADERS32*>(
        file.data() + dos->e_lfanew);
    if (nt_file->Signature != IMAGE_NT_SIGNATURE ||
        nt_file->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
        nt_file->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        throw std::runtime_error("Bootstrap must be an x86 PE image");
    }

    const std::size_t image_size = nt_file->OptionalHeader.SizeOfImage;
    std::vector<std::uint8_t> image(image_size, 0);
    if (nt_file->OptionalHeader.SizeOfHeaders > file.size() ||
        nt_file->OptionalHeader.SizeOfHeaders > image.size()) {
        throw std::runtime_error("Malformed PE32 image: headers exceed image size");
    }
    std::memcpy(image.data(), file.data(), nt_file->OptionalHeader.SizeOfHeaders);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(
        image.data() + dos->e_lfanew);
    const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        file.data() + dos->e_lfanew + offsetof(IMAGE_NT_HEADERS32, OptionalHeader) +
        nt_file->FileHeader.SizeOfOptionalHeader);
    for (WORD index = 0; index < nt_file->FileHeader.NumberOfSections; ++index) {
        const auto& section = sections[index];
        if (!section.SizeOfRawData) continue;
        if (static_cast<std::size_t>(section.PointerToRawData) +
                    section.SizeOfRawData > file.size() ||
            static_cast<std::size_t>(section.VirtualAddress) +
                    section.SizeOfRawData > image.size()) {
            throw std::runtime_error("Malformed PE32 image: section is out of range");
        }
        std::memcpy(image.data() + section.VirtualAddress,
                    file.data() + section.PointerToRawData,
                    section.SizeOfRawData);
    }

    patch_loader_instance_names(image, options.instance_name);

    void* remote_image = VirtualAllocEx(
        process, reinterpret_cast<void*>(nt->OptionalHeader.ImageBase), image_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_image) {
        remote_image = VirtualAllocEx(process, nullptr, image_size,
                                      MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
    }
    if (!remote_image) fail("VirtualAllocEx(mapped x86 image) failed");
    const std::uint32_t remote_base = address32(remote_image, "mapped x86 image");
    const std::int64_t delta = static_cast<std::int64_t>(remote_base) -
                               nt->OptionalHeader.ImageBase;

    const auto reloc =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (delta != 0) {
        if (!reloc.VirtualAddress || !reloc.Size) {
            throw std::runtime_error("x86 bootstrap cannot be relocated");
        }
        DWORD consumed = 0;
        while (consumed < reloc.Size) {
            auto* block = at<IMAGE_BASE_RELOCATION>(
                image, reloc.VirtualAddress + consumed);
            if (block->SizeOfBlock < sizeof(*block)) break;
            const DWORD count = (block->SizeOfBlock - sizeof(*block)) / sizeof(WORD);
            auto* entries = at<WORD>(
                image, reloc.VirtualAddress + consumed + sizeof(*block));
            for (DWORD index = 0; index < count; ++index) {
                const WORD type = entries[index] >> 12;
                const WORD offset = entries[index] & 0xfff;
                if (type == IMAGE_REL_BASED_HIGHLOW) {
                    *at<std::uint32_t>(image, block->VirtualAddress + offset) +=
                        static_cast<std::uint32_t>(delta);
                } else if (type != IMAGE_REL_BASED_ABSOLUTE) {
                    throw std::runtime_error("Unsupported PE32 relocation type");
                }
            }
            consumed += block->SizeOfBlock;
        }
    }
    nt->OptionalHeader.ImageBase = remote_base;

    const auto imports =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imports.VirtualAddress) {
        auto* descriptor = at<IMAGE_IMPORT_DESCRIPTOR>(image,
                                                       imports.VirtualAddress);
        for (; descriptor->Name; ++descriptor) {
            const char* narrow = reinterpret_cast<const char*>(
                at<std::uint8_t>(image, descriptor->Name));
            const int length = MultiByteToWideChar(CP_ACP, 0, narrow, -1,
                                                    nullptr, 0);
            if (length <= 1) throw std::runtime_error("Malformed PE32 import name");
            std::wstring wide(static_cast<std::size_t>(length), L'\0');
            MultiByteToWideChar(CP_ACP, 0, narrow, -1, wide.data(), length);
            wide.resize(std::wcslen(wide.c_str()));

            HMODULE local_module = LoadLibraryW(wide.c_str());
            if (!local_module) fail("LoadLibraryW(x86 dependency) failed");
            remote_load_dependency(process, primary_thread, process_id, wide);

            const DWORD lookup_rva = descriptor->OriginalFirstThunk
                ? descriptor->OriginalFirstThunk : descriptor->FirstThunk;
            auto* lookup = at<IMAGE_THUNK_DATA32>(image, lookup_rva);
            auto* iat = at<IMAGE_THUNK_DATA32>(image, descriptor->FirstThunk);
            for (; lookup->u1.AddressOfData; ++lookup, ++iat) {
                FARPROC procedure = nullptr;
                if (IMAGE_SNAP_BY_ORDINAL32(lookup->u1.Ordinal)) {
                    procedure = GetProcAddress(local_module,
                        reinterpret_cast<LPCSTR>(
                            IMAGE_ORDINAL32(lookup->u1.Ordinal)));
                } else {
                    auto* by_name = at<IMAGE_IMPORT_BY_NAME>(
                        image, lookup->u1.AddressOfData);
                    procedure = GetProcAddress(
                        local_module, reinterpret_cast<char*>(by_name->Name));
                }
                if (!procedure) fail("GetProcAddress(x86 import) failed");
                HMODULE owner = nullptr;
                if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                        reinterpret_cast<LPCWSTR>(procedure),
                                        &owner)) {
                    fail("GetModuleHandleExW(x86 import owner) failed");
                }
                remote_load_dependency(process, primary_thread, process_id,
                                       module_basename(owner));
                iat->u1.Function = remote_address_for_local(process_id, procedure);
            }
        }
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remote_image, image.data(), image.size(),
                            &written) || written != image.size()) {
        fail("WriteProcessMemory(mapped x86 image) failed");
    }

    if (!options.preload_dll.empty()) {
        const std::wstring ready_name = L"Local\\ZClient_LsxShimReady_" +
                                        std::to_wstring(process_id);
        Handle ready(CreateEventW(nullptr, TRUE, FALSE, ready_name.c_str()));
        if (!ready) fail("CreateEventW(x86 preload ready) failed");
        remote_load_dependency(process, primary_thread, process_id,
            std::filesystem::absolute(options.preload_dll).wstring());
        const DWORD wait = WaitForSingleObject(ready.get(), 10000);
        if (wait != WAIT_OBJECT_0) {
            throw std::runtime_error(wait == WAIT_TIMEOUT
                ? "Timed out waiting for the x86 preload DLL"
                : "Waiting for the x86 preload DLL failed");
        }
    }

    const auto tls = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls.VirtualAddress && tls.Size >= sizeof(IMAGE_TLS_DIRECTORY32)) {
        auto* directory = at<IMAGE_TLS_DIRECTORY32>(image, tls.VirtualAddress);
        const SIZE_T raw_size = directory->EndAddressOfRawData -
                                directory->StartAddressOfRawData;
        const SIZE_T block_size = raw_size + directory->SizeOfZeroFill;
        if (directory->AddressOfIndex && block_size) {
            HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
            FARPROC tls_alloc = GetProcAddress(kernel32, "TlsAlloc");
            FARPROC tls_set = GetProcAddress(kernel32, "TlsSetValue");
            if (!tls_alloc || !tls_set) {
                throw std::runtime_error("Could not resolve x86 TLS APIs");
            }
            const DWORD tls_index = remote_call3(
                process, primary_thread,
                remote_address_for_local(process_id, tls_alloc), 0, 0, 0);
            if (tls_index == TLS_OUT_OF_INDEXES) {
                throw std::runtime_error("TlsAlloc failed in x86 target");
            }
            void* remote_tls = VirtualAllocEx(process, nullptr, block_size,
                                               MEM_COMMIT | MEM_RESERVE,
                                               PAGE_READWRITE);
            if (!remote_tls) fail("VirtualAllocEx(x86 static TLS) failed");
            const std::size_t template_rva =
                directory->StartAddressOfRawData - remote_base;
            if (raw_size &&
                (!WriteProcessMemory(process, remote_tls,
                                     at<std::uint8_t>(image, template_rva),
                                     raw_size, &written) ||
                 written != raw_size)) {
                fail("WriteProcessMemory(x86 static TLS) failed");
            }
            const DWORD remote_index = directory->AddressOfIndex;
            if (!WriteProcessMemory(process,
                    reinterpret_cast<void*>(remote_index), &tls_index,
                    sizeof(tls_index), &written) ||
                written != sizeof(tls_index)) {
                fail("WriteProcessMemory(x86 TLS index) failed");
            }
            if (!remote_call3(process, primary_thread,
                    remote_address_for_local(process_id, tls_set), tls_index,
                    address32(remote_tls, "x86 static TLS"), 0)) {
                throw std::runtime_error("TlsSetValue failed in x86 target");
            }
        }
        if (directory->AddressOfCallBacks) {
            const std::size_t callbacks_rva =
                directory->AddressOfCallBacks - remote_base;
            auto* callback = at<std::uint32_t>(image, callbacks_rva);
            for (; *callback; ++callback) {
                remote_call3(process, primary_thread, *callback, remote_base,
                             DLL_PROCESS_ATTACH, 0);
            }
        }
    }

    ZloContext32 context{0xDEADBEEF, 0, gate.original_entry, 0,
                         remote_base, 0, 0};
    void* remote_context = VirtualAllocEx(process, nullptr, sizeof(context),
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_READWRITE);
    if (!remote_context) fail("VirtualAllocEx(x86 ZLO context) failed");
    if (!WriteProcessMemory(process, remote_context, &context, sizeof(context),
                            &written) || written != sizeof(context)) {
        fail("WriteProcessMemory(x86 ZLO context) failed");
    }
    const std::uint32_t remote_context32 =
        address32(remote_context, "x86 ZLO context");

    if (nt->OptionalHeader.AddressOfEntryPoint) {
        const DWORD attached = remote_call3(
            process, primary_thread,
            remote_base + nt->OptionalHeader.AddressOfEntryPoint,
            remote_base, DLL_PROCESS_ATTACH, remote_context32);
        if (!attached) {
            throw std::runtime_error("Mapped x86 loader DllMain rejected attach");
        }
    }

    DWORD zlo_rva = 0;
    const auto exports =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exports.VirtualAddress) {
        auto* directory = at<IMAGE_EXPORT_DIRECTORY>(image,
                                                     exports.VirtualAddress);
        auto* names = at<DWORD>(image, directory->AddressOfNames);
        auto* ordinals = at<WORD>(image, directory->AddressOfNameOrdinals);
        auto* functions = at<DWORD>(image, directory->AddressOfFunctions);
        for (DWORD index = 0; index < directory->NumberOfNames; ++index) {
            const char* name = reinterpret_cast<const char*>(
                at<std::uint8_t>(image, names[index]));
            if (std::strcmp(name, "ZLO") == 0) {
                zlo_rva = functions[ordinals[index]];
                break;
            }
        }
    }
    if (!zlo_rva) throw std::runtime_error("Mapped x86 loader has no ZLO export");

    const std::uint8_t mapped_status = 2;
    if (!WriteProcessMemory(process,
            static_cast<std::uint8_t*>(remote_context) +
                offsetof(ZloContext32, status),
            &mapped_status, sizeof(mapped_status), &written) ||
        written != sizeof(mapped_status)) {
        fail("WriteProcessMemory(x86 ZLO status) failed");
    }

    patch_game_blaze_redirector(process, options.service_host);
    remote_call3(process, primary_thread, remote_base + zlo_rva,
                 remote_context32, 0, 0);
    if (!ReadProcessMemory(process, remote_context, &context, sizeof(context),
                           nullptr)) {
        fail("ReadProcessMemory(x86 ZLO context) failed");
    }
    if (context.result != 0) {
        throw std::runtime_error("x86 ZLO bootstrap failed (status " +
            std::to_string(context.result) + ", detail " +
            std::to_string(context.last_error) + ")");
    }

    if (!options.preload_dll.empty()) activate_preload_network(process_id);

    auto* mapped_sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        image.data() + dos->e_lfanew + offsetof(IMAGE_NT_HEADERS32, OptionalHeader) +
        nt->FileHeader.SizeOfOptionalHeader);
    for (WORD index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
        const auto& section = mapped_sections[index];
        const SIZE_T size = section.Misc.VirtualSize
            ? section.Misc.VirtualSize : section.SizeOfRawData;
        if (!size) continue;
        DWORD old = 0;
        if (!VirtualProtectEx(process,
                reinterpret_cast<void*>(remote_base + section.VirtualAddress),
                size, section_protection(section.Characteristics), &old)) {
            fail("VirtualProtectEx(mapped x86 section) failed");
        }
    }
    FlushInstructionCache(process, remote_image, image_size);
    release_entry_gate(process, gate);
    return {remote_base, remote_context32};
}

