#pragma once

#include <winsock2.h>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

class LicenseReplayServer
{
public:
    LicenseReplayServer(const std::filesystem::path& response_path,
                        std::string signature,
                        std::uint16_t port = 5080);
    ~LicenseReplayServer();

    LicenseReplayServer(const LicenseReplayServer&) = delete;
    LicenseReplayServer& operator=(const LicenseReplayServer&) = delete;

    std::uint16_t port() const noexcept { return port_; }

private:
    void serve();
    void handle_client(SOCKET client);

    SOCKET listener_ = INVALID_SOCKET;
    std::vector<std::uint8_t> response_;
    std::string signature_;
    std::uint16_t port_ = 0;
    std::atomic<bool> stopping_ = false;
    std::thread worker_;
    bool winsock_started_ = false;
};
