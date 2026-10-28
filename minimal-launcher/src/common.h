#pragma once

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
#include <functional>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <iterator>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

[[noreturn]] void fail(const std::string& message, DWORD error = GetLastError());
[[noreturn]] void fail(const std::wstring& message, DWORD error = GetLastError());
std::string encode_utf8(std::wstring_view value);
std::wstring decode_utf8(std::string_view text);

namespace fs = std::filesystem;

class Handle 
{

public:

    Handle() = default;
    explicit Handle(HANDLE value) : value_(value) {}
    ~Handle() { reset(); }

    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;

    Handle(Handle&& other) noexcept : value_(other.release()) {}
    Handle& operator=(Handle&& other) noexcept 
    {
        if (this != &other) reset(other.release());
        return *this;
    }

    [[nodiscard]] HANDLE get() const { return value_; }
    [[nodiscard]] explicit operator bool() const 
    {
        return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
    }

    HANDLE release() 
    {
        HANDLE result = value_;
        value_ = nullptr;
        return result;
    }

    void reset(HANDLE value = nullptr) 
    {
        if (*this) CloseHandle(value_);
        value_ = value;
    }

private:

    HANDLE value_ = nullptr;

};

class ScopedMarkerFile 
{

public:

    explicit ScopedMarkerFile(fs::path path) : path_(std::move(path)) 
    {
        Handle file(CreateFileW(path_.c_str(), GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
                                
        if (file) 
        {
            created_ = true;
            return;
        }

        const DWORD error = GetLastError();
        if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS) 
        {
            fail(L"Could not create CMain marker " + path_.wstring(), error);
        }
    }

    ~ScopedMarkerFile() 
    {
        if (created_) 
        {
            DeleteFileW(path_.c_str());
        }
    }

    ScopedMarkerFile(const ScopedMarkerFile&) = delete;
    ScopedMarkerFile& operator=(const ScopedMarkerFile&) = delete;

    [[nodiscard]] bool created() const { return created_; }

private:

    fs::path path_;
    bool created_ = false;

};


class SharedImageMapping 
{

public:

    SharedImageMapping(const wchar_t* name, const fs::path& image_path) 
    {
        std::ifstream image(image_path, std::ios::binary | std::ios::ate);
        if (!image) 
        {
            throw std::runtime_error("Unable to open x86 bootstrap image.");
        }

        const auto size = image.tellg();
        if (size <= 0 || static_cast<unsigned long long>(size) > UINT32_MAX - sizeof(std::uint32_t)) 
        {
            throw std::runtime_error("x86 bootstrap image has an invalid size.");
        }

        const auto payload_size = static_cast<std::uint32_t>(size);
        std::vector<std::uint8_t> payload(payload_size);
        image.seekg(0);

        if (!image.read(reinterpret_cast<char*>(payload.data()), payload.size())) 
        {
            throw std::runtime_error("Unable to read x86 bootstrap image.");
        }

        publish(name, payload);
    }

    SharedImageMapping(const wchar_t* name, const std::vector<std::uint8_t>& payload) 
    {
        publish(name, payload);
    }

private:

    void publish(const wchar_t* name, const std::vector<std::uint8_t>& payload) 
    {
        if (payload.empty() || payload.size() > UINT32_MAX - sizeof(std::uint32_t)) 
        {
            throw std::runtime_error("Bootstrap image has an invalid size.");
        }

        const auto payload_size = static_cast<std::uint32_t>(payload.size());
        mapping_.reset(CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
                                          0, payload_size + sizeof(payload_size), name));

        if (!mapping_) 
        {
            fail(L"CreateFileMappingW(CLoader) failed");
        }

        if (GetLastError() == ERROR_ALREADY_EXISTS) 
        {
            throw std::runtime_error("A requested Global\\ZClient_CLoader mapping is already owned by another process.");
        }

        void* view = MapViewOfFile(mapping_.get(), FILE_MAP_WRITE, 0, 0, 0);
        if (!view) 
        {
            fail(L"MapViewOfFile(CLoader) failed");
        }

        std::memcpy(view, &payload_size, sizeof(payload_size));
        std::memcpy(static_cast<std::uint8_t*>(view) + sizeof(payload_size), payload.data(), payload.size());
        
        UnmapViewOfFile(view);
    }

    Handle mapping_;

};


class ZClientPipeHost 
{

public:

    explicit ZClientPipeHost(std::uint32_t client_token, std::wstring pipe_name,
                             std::string game_executable, std::uint32_t module_id,
                             std::uint32_t game_module_id,
                             std::string activation_executable,
                             std::uint32_t activation_module_id,
                             std::function<void(DWORD)> activation_process_callback = {})
        : client_token_(client_token), pipe_name_(std::move(pipe_name)),
          game_executable_(std::move(game_executable)), module_id_(module_id),
          game_module_id_(game_module_id),
          activation_executable_(std::move(activation_executable)),
          activation_module_id_(activation_module_id),
          activation_process_callback_(std::move(activation_process_callback))
    {
        // Each CLoader protocol stage opens a separate connection to the same
        // upstream endpoint. Keep the full set of server instances available
        // and recycle them after clients disconnect.
        constexpr std::size_t kInstances = 10;
        for (std::size_t i = 0; i < kInstances; ++i) 
        {
            Handle pipe(CreateNamedPipeW(
                pipe_name_.c_str(), PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                10, 1024 * 1024, 1024 * 1024, 0, nullptr));

            if (!pipe) 
            {
                fail(L"CreateNamedPipeW(instance ZClient pipe) failed");
            }

            pipes_.push_back(std::move(pipe));
        }
    }

    ~ZClientPipeHost() 
    {
        stopping_.store(true, std::memory_order_release);

        for (auto& pipe : pipes_) 
        {
            CancelIoEx(pipe.get(), nullptr);
            DisconnectNamedPipe(pipe.get());
        }

        for (auto& worker : workers_) 
        {
            if (worker.joinable()) worker.join();
        }
    }

    void start() 
    {
        for (std::size_t i = 0; i < pipes_.size(); ++i) 
        {
            workers_.emplace_back([this, i] { run(pipes_[i].get(), i); });
        }
    }

private:

    std::vector<Handle> pipes_;
    std::uint32_t client_token_;
    std::wstring pipe_name_;
    std::string game_executable_;
    std::uint32_t module_id_;
    std::uint32_t game_module_id_;
    std::string activation_executable_;
    std::uint32_t activation_module_id_;
    std::function<void(DWORD)> activation_process_callback_;
    std::atomic_bool stopping_{false};
    std::vector<std::thread> workers_;
    std::mutex output_mutex_;
    std::mutex activation_process_mutex_;
    std::unordered_set<DWORD> monitored_activation_processes_;

    static bool contains_utf16_ascii_ci(const std::vector<unsigned char>& frame,
                                        std::string_view text) 
    {
        if (frame.size() < text.size() * 2) return false;

        for (std::size_t offset = 0; offset + text.size() * 2 <= frame.size(); ++offset) 
        {
            bool matches = true;

            for (std::size_t i = 0; i < text.size(); ++i) 
            {
                const unsigned char value = frame[offset + i * 2];
                const unsigned char folded = value >= 'A' && value <= 'Z'
                    ? static_cast<unsigned char>(value - 'A' + 'a') 
                    : value;

                if (folded != static_cast<unsigned char>(text[i]) ||
                    frame[offset + i * 2 + 1] != 0) 
                {
                    matches = false;
                    break;
                }
            }

            if (matches) return true;
        }

        return false;
    }

    void run(HANDLE pipe, std::size_t instance) 
    {
        while (!stopping_.load(std::memory_order_acquire)) 
        {
            const BOOL connected = ConnectNamedPipe(pipe, nullptr);
            if (!connected) 
            {
                const DWORD error = GetLastError();
                if (error != ERROR_PIPE_CONNECTED) 
                {
                    if (error != ERROR_OPERATION_ABORTED &&
                        error != ERROR_INVALID_HANDLE) 
                    {
                        std::lock_guard lock(output_mutex_);
                        std::cout << "ZClient pipe instance " 
                                  << instance
                                  << " failed to accept a client (Win32 "
                                  << error 
                                  << ")\n";
                    }
                    return;
                }
            }

            if (stopping_.load(std::memory_order_acquire)) return;

            ULONG client_process_id = 0;
            if (!GetNamedPipeClientProcessId(pipe, &client_process_id))
            {
                std::lock_guard lock(output_mutex_);
                std::cout << "ZClient pipe instance " << instance
                          << " could not identify its client process (Win32 "
                          << GetLastError() << ")\n";
            }
            else
            {
                std::lock_guard lock(output_mutex_);
                std::cout << "ZClient pipe instance " << instance
                          << " connected (client PID " << client_process_id
                          << ")\n";
            }

            serve_client(pipe, instance, client_process_id);

            if (stopping_.load(std::memory_order_acquire)) return;

            if (!DisconnectNamedPipe(pipe)) 
            {
                const DWORD error = GetLastError();
                if (error == ERROR_OPERATION_ABORTED ||
                    error == ERROR_INVALID_HANDLE) 
                {
                    return;
                }
            }
        }
    }

    void serve_client(HANDLE pipe, std::size_t instance,
                      DWORD client_process_id) 
    {
        std::vector<unsigned char> buffer(64 * 1024);
        std::vector<unsigned char> pending;

        for (;;) 
        {
            DWORD bytes = 0;
            if (!ReadFile(pipe, buffer.data(), static_cast<DWORD>(buffer.size()), &bytes, nullptr) || !bytes) 
            {
                break;
            }

            pending.insert(pending.end(), buffer.begin(), buffer.begin() + bytes);

            // Pipe reads are a byte stream: a five-byte frame header and its
            // payload can arrive in separate ReadFile calls.
            while (pending.size() >= 5) 
            {
                const std::uint32_t payload_size =
                    (static_cast<std::uint32_t>(pending[1]) << 24) |
                    (static_cast<std::uint32_t>(pending[2]) << 16) |
                    (static_cast<std::uint32_t>(pending[3]) << 8) |
                    static_cast<std::uint32_t>(pending[4]);
                
                if (payload_size > 16 * 1024 * 1024) 
                {
                    std::lock_guard lock(output_mutex_);
                    std::cout << "ZClient pipe instance " << instance
                              << " rejected oversized frame (" << payload_size
                              << " bytes)\n";
                    return;
                }

                const std::size_t frame_size = 5 + payload_size;
                if (pending.size() < frame_size) break;

                {
                    std::lock_guard lock(output_mutex_);
                    std::cout << "ZClient pipe instance " << instance
                              << " received opcode "
                              << static_cast<unsigned>(pending[0]) << ", "
                              << payload_size << " payload bytes:";

                    const std::size_t shown = std::min<std::size_t>(frame_size, 512);
                    for (std::size_t i = 0; i < shown; ++i) 
                    {
                        std::cout << ' ' << std::hex << std::setw(2)
                                  << std::setfill('0')
                                  << static_cast<unsigned>(pending[i]);
                    }

                    if (shown != frame_size) std::cout << " ...";
                    std::cout << std::dec << '\n';
                }

                const unsigned char* reply = nullptr;
                std::size_t reply_size = 0;
                const char* reply_description = nullptr;

                // Opcode 1 selects the module and executable-specific record.
                // These pairs were captured from the original 2026-09-08
                // ZClient payload. Both executables use the same module but
                // have distinct second identifiers.
                const auto make_opcode1_reply = [this](std::uint32_t executable_id) 
                {
                    return std::array<unsigned char, 13>{
                        0x01, 0x00, 0x00, 0x00, 0x08,
                        static_cast<unsigned char>(module_id_ >> 24),
                        static_cast<unsigned char>(module_id_ >> 16),
                        static_cast<unsigned char>(module_id_ >> 8),
                        static_cast<unsigned char>(module_id_),
                        static_cast<unsigned char>(executable_id >> 24),
                        static_cast<unsigned char>(executable_id >> 16),
                        static_cast<unsigned char>(executable_id >> 8),
                        static_cast<unsigned char>(executable_id),
                    };
                };

                const auto game_opcode1_reply = make_opcode1_reply(game_module_id_);
                const auto activation_opcode1_reply = make_opcode1_reply(activation_module_id_);
                // The original handler initializes both fields to zero when
                // neither its id nor executable lookup resolves.
                static constexpr unsigned char unknown_opcode1_reply[] = {
                    0x01, 0x00, 0x00, 0x00, 0x08,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                };

                // Opcode 2 repeats game identification after CMain starts.
                // The recovered handler returns a success byte followed by
                // games_manager+0xB0. Its constructor initializes that field
                // to 0xA0000009; it is a protocol/client token, not an account
                // id.
                const unsigned char opcode2_reply[] = {
                    0x02, 0x00, 0x00, 0x00, 0x05,
                    0x01,
                    static_cast<unsigned char>(client_token_ >> 24),
                    static_cast<unsigned char>(client_token_ >> 16),
                    static_cast<unsigned char>(client_token_ >> 8),
                    static_cast<unsigned char>(client_token_),
                };

                if (pending[0] == 1) 
                {
                    const std::vector<unsigned char> request_payload(pending.begin() + 5, pending.begin() + frame_size);
                    
                    if (!activation_executable_.empty() &&
                        contains_utf16_ascii_ci(request_payload, activation_executable_)) 
                    {
                        reply = activation_opcode1_reply.data();
                        reply_size = activation_opcode1_reply.size();
                        reply_description = "selected configured child executable module";

                    } 
                    else if (contains_utf16_ascii_ci(request_payload, game_executable_)) 
                    {
                        reply = game_opcode1_reply.data();
                        reply_size = game_opcode1_reply.size();
                        reply_description = "selected configured game executable module";
                    } 
                    else 
                    {
                        reply = unknown_opcode1_reply;
                        reply_size = sizeof(unknown_opcode1_reply);
                        reply_description = "returned an unresolved opcode-1 module pair";
                    }
                } 
                else if (pending[0] == 2) 
                {
                    reply = opcode2_reply;
                    reply_size = sizeof(opcode2_reply);
                    reply_description = "accepted CMain launch with client token";

                    // Opcode 1 may be sent by the parent CLoader before the
                    // activation process exists, while opcode 2 is sent by
                    // CMain in the new process. Classify this request from its
                    // own executable payload instead of assuming both pipe
                    // connections have the same client PID. By opcode 2,
                    // CMain is resident and blocked waiting for this reply.
                    const std::vector<unsigned char> request_payload(
                        pending.begin() + 5, pending.begin() + frame_size);
                    const bool activation_request =
                        !activation_executable_.empty() &&
                        contains_utf16_ascii_ci(
                            request_payload, activation_executable_);
                    bool start_monitor = false;
                    if (activation_request && client_process_id)
                    {
                        std::lock_guard lock(activation_process_mutex_);
                        start_monitor = monitored_activation_processes_
                            .insert(client_process_id).second;
                    }
                    if (start_monitor && activation_process_callback_)
                    {
                        try
                        {
                            activation_process_callback_(client_process_id);
                        }
                        catch (const std::exception& error)
                        {
                            std::lock_guard lock(output_mutex_);
                            std::cout << "ZClient pipe instance " << instance
                                      << " could not start the activation scanner "
                                         "monitor: " << error.what() << '\n';
                        }
                    }
                }

                if (reply) 
                {
                    DWORD written = 0;
                    const BOOL ok = WriteFile(pipe, reply,
                                              static_cast<DWORD>(reply_size),
                                              &written, nullptr);
                    std::lock_guard lock(output_mutex_);

                    if (!ok || written != reply_size) 
                    {
                        std::cout << "ZClient pipe instance " << instance
                                  << " failed to write opcode-"
                                  << static_cast<unsigned>(pending[0])
                                  << " reply (Win32 "
                                  << GetLastError() << ")\n";
                    } 
                    else 
                    {
                        std::cout << "ZClient pipe instance " << instance
                                  << ' ' << reply_description;
                        if (pending[0] == 2) {
                            std::cout << " 0x" << std::hex << client_token_
                                      << std::dec;
                        }
                        std::cout << '\n';
                    }
                }

                pending.erase(pending.begin(), pending.begin() + frame_size);
            }
        }
    }
};
