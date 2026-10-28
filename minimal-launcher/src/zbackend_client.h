#pragma once

#include <cstdint>
#include <memory>
#include <string>

class ZBackendClient {
public:
    ZBackendClient(std::wstring endpoint, std::wstring login, std::string digest_hex);
    ~ZBackendClient();

    ZBackendClient(const ZBackendClient&) = delete;
    ZBackendClient& operator=(const ZBackendClient&) = delete;

    [[nodiscard]] std::uint32_t account_id() const;
    [[nodiscard]] const std::wstring& display_name() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
