#include <windows.h>

#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>

#include "manual_map32.h"

#if defined(_WIN64)
#error zclient_injector32 must be built for Win32, not x64.
#endif

namespace {

class Handle {
public:
    explicit Handle(HANDLE value = nullptr) : value_(value) {}
    ~Handle() {
        if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
    }

    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;

    [[nodiscard]] HANDLE get() const { return value_; }
    [[nodiscard]] explicit operator bool() const {
        return value_ && value_ != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE value_;
};

[[noreturn]] void usage() {
    throw std::runtime_error(
        "usage: zclient_injector32 --pid <id> --tid <id> "
        "--loader <CLoaderx32.dll> --instance <7chars> "
        "--service-host <IPv4> [--preload <ZClient.LsxShim32.dll>]");
}

std::uint32_t parse_u32(std::wstring_view text, const char* option) {
    if (text.empty()) usage();
    std::wstring copy(text);
    wchar_t* end = nullptr;
    errno = 0;
    const unsigned long value = std::wcstoul(copy.c_str(), &end, 0);
    if (errno == ERANGE || !end || *end || value == 0 ||
        value > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error(std::string(option) + " is not a valid nonzero DWORD");
    }
    return static_cast<std::uint32_t>(value);
}

std::string narrow_ascii(std::wstring_view text, const char* option) {
    std::string result;
    result.reserve(text.size());
    for (const wchar_t ch : text) {
        if (ch <= 0 || ch > 0x7f) {
            throw std::runtime_error(std::string(option) + " must be ASCII");
        }
        result.push_back(static_cast<char>(ch));
    }
    return result;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        DWORD process_id = 0;
        DWORD thread_id = 0;
        ManualMap32Options options;

        for (int index = 1; index < argc; ++index) {
            const std::wstring_view option(argv[index]);
            if (option == L"--help" || option == L"-h") usage();
            if (index + 1 >= argc) usage();
            const std::wstring_view value(argv[++index]);

            if (option == L"--pid") {
                process_id = parse_u32(value, "--pid");
            } else if (option == L"--tid") {
                thread_id = parse_u32(value, "--tid");
            } else if (option == L"--loader") {
                options.loader = std::filesystem::absolute(value);
            } else if (option == L"--preload") {
                options.preload_dll = std::filesystem::absolute(value);
            } else if (option == L"--instance") {
                options.instance_name = narrow_ascii(value, "--instance");
            } else if (option == L"--service-host") {
                options.service_host = narrow_ascii(value, "--service-host");
            } else {
                usage();
            }
        }

        if (!process_id || !thread_id || options.loader.empty() ||
            options.instance_name.size() != 7 || options.service_host.empty()) {
            usage();
        }
        if (!std::filesystem::is_regular_file(options.loader)) {
            throw std::runtime_error("32-bit loader does not exist");
        }
        if (!options.preload_dll.empty() &&
            !std::filesystem::is_regular_file(options.preload_dll)) {
            throw std::runtime_error("32-bit preload DLL does not exist");
        }

        constexpr DWORD process_access =
            PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ |
            PROCESS_VM_WRITE | SYNCHRONIZE;
        Handle process(OpenProcess(process_access, FALSE, process_id));
        if (!process) {
            throw std::runtime_error("OpenProcess failed (Win32 " +
                                     std::to_string(GetLastError()) + ")");
        }

        constexpr DWORD thread_access =
            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME |
            THREAD_QUERY_INFORMATION | SYNCHRONIZE;
        Handle thread(OpenThread(thread_access, FALSE, thread_id));
        if (!thread) {
            throw std::runtime_error("OpenThread failed (Win32 " +
                                     std::to_string(GetLastError()) + ")");
        }

        const ManualMap32Result result = manual_map_zclient_loader32(
            process.get(), thread.get(), process_id, options);
        std::cout << "INJECT32_OK loader=0x" << std::hex << result.loader_base
                  << " context=0x" << result.zlo_context << std::dec << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "zclient_injector32: " << error.what() << '\n';
        return 1;
    }
}

