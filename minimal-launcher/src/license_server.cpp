#include "license_server.h"

#include <ws2tcpip.h>

#include <array>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string_view>

namespace {

void send_all(SOCKET socket, const char* data, std::size_t size)
{
    while (size != 0)
    {
        const int chunk = send(socket, data,
                               static_cast<int>(std::min<std::size_t>(size, INT_MAX)), 0);
        if (chunk == SOCKET_ERROR || chunk == 0)
            throw std::runtime_error("sending activation license response failed");
        data += chunk;
        size -= static_cast<std::size_t>(chunk);
    }
}

void send_all(SOCKET socket, const std::vector<std::uint8_t>& data)
{
    send_all(socket, reinterpret_cast<const char*>(data.data()), data.size());
}

} // namespace

LicenseReplayServer::LicenseReplayServer(const std::filesystem::path& response_path,
                                         std::string signature,
                                         std::uint16_t port)
    : signature_(std::move(signature))
{
    std::ifstream input(response_path, std::ios::binary);
    if (!input)
        throw std::runtime_error(
            "could not open activation license response: " + response_path.string());
    response_.assign(std::istreambuf_iterator<char>(input),
                     std::istreambuf_iterator<char>());
    if (response_.empty())
        throw std::runtime_error("activation license response is empty");
    if (signature_.empty() || signature_.find_first_of("\r\n") != std::string::npos)
        throw std::runtime_error("activation license signature is missing or invalid");

    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
        throw std::runtime_error("WSAStartup for activation license server failed");
    winsock_started_ = true;

    listener_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener_ == INVALID_SOCKET)
        throw std::runtime_error("socket for activation license server failed");

    BOOL exclusive = TRUE;
    setsockopt(listener_, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
               reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    InetPtonA(AF_INET, "127.0.0.1", &address.sin_addr);
    if (bind(listener_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR)
        throw std::runtime_error(
            "could not bind activation license server to 127.0.0.1:" +
            std::to_string(port) + " (Winsock " + std::to_string(WSAGetLastError()) + ")");
    if (listen(listener_, SOMAXCONN) == SOCKET_ERROR)
        throw std::runtime_error("listen for activation license server failed");

    int address_size = sizeof(address);
    if (getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &address_size) == SOCKET_ERROR)
        throw std::runtime_error("getsockname for activation license server failed");
    port_ = ntohs(address.sin_port);

    worker_ = std::thread(&LicenseReplayServer::serve, this);
    std::cout << "Activation license replay is listening on 127.0.0.1:"
              << port_ << " (" << response_.size() << " signed bytes)\n";
}

LicenseReplayServer::~LicenseReplayServer()
{
    stopping_ = true;
    if (listener_ != INVALID_SOCKET)
    {
        closesocket(listener_);
        listener_ = INVALID_SOCKET;
    }
    if (worker_.joinable()) worker_.join();
    if (winsock_started_) WSACleanup();
}

void LicenseReplayServer::serve()
{
    while (!stopping_)
    {
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(listener_, &readable);
        timeval timeout{};
        timeout.tv_usec = 100000;
        const int ready = select(0, &readable, nullptr, nullptr, &timeout);
        if (stopping_) break;
        if (ready <= 0) continue;

        SOCKET client = accept(listener_, nullptr, nullptr);
        if (client == INVALID_SOCKET) continue;
        try
        {
            handle_client(client);
        }
        catch (const std::exception& error)
        {
            std::cerr << "Activation license request failed: " << error.what() << '\n';
        }
        shutdown(client, SD_BOTH);
        closesocket(client);
    }
}

void LicenseReplayServer::handle_client(SOCKET client)
{
    DWORD timeout = 5000;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    std::string request;
    std::array<char, 2048> buffer{};
    while (request.find("\r\n\r\n") == std::string::npos && request.size() < 16384)
    {
        const int received = recv(client, buffer.data(), static_cast<int>(buffer.size()), 0);
        if (received <= 0) break;
        request.append(buffer.data(), static_cast<std::size_t>(received));
    }

    const std::size_t line_end = request.find("\r\n");
    const std::string_view first_line(request.data(),
        line_end == std::string::npos ? request.size() : line_end);
    const bool is_license = first_line.rfind("GET /licenses?", 0) == 0 ||
                            first_line.rfind("GET /licenses ", 0) == 0;
    if (!is_license)
    {
        constexpr std::string_view not_found =
            "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        send_all(client, not_found.data(), not_found.size());
        return;
    }

    const std::string headers =
        "HTTP/1.1 200 OK\r\n"
        "Connection: close\r\n"
        "Content-Type: application/octet-stream\r\n"
        "X-Signature: " + signature_ + "\r\n"
        "X-ZLO: ZLO\r\n"
        "Content-Length: " + std::to_string(response_.size()) + "\r\n\r\n";
    send_all(client, headers.data(), headers.size());
    send_all(client, response_);
    std::cout << "Replayed signed activation license for " << first_line << '\n';
}
