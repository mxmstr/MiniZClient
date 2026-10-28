#include <winsock2.h>
#include <ws2tcpip.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include "license_server.h"

int main()
{
    const std::filesystem::path response_path =
        std::filesystem::temp_directory_path() / "zclient-license-server-test.bin";
    {
        std::ofstream output(response_path, std::ios::binary);
        output << "signed-body";
    }

    try
    {
        LicenseReplayServer server(response_path, "test-signature", 0);
        SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(server.port());
        InetPtonA(AF_INET, "127.0.0.1", &address.sin_addr);
        if (connect(client, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR)
            return 1;
        const std::string request =
            "GET /licenses?contentId=71724 HTTP/1.1\r\nHost: proxy.novafusion.ea.com\r\n\r\n";
        send(client, request.data(), static_cast<int>(request.size()), 0);
        std::string response;
        char buffer[1024];
        for (;;)
        {
            const int received = recv(client, buffer, sizeof(buffer), 0);
            if (received <= 0) break;
            response.append(buffer, static_cast<std::size_t>(received));
        }
        closesocket(client);
        std::filesystem::remove(response_path);
        if (response.find("HTTP/1.1 200 OK") == std::string::npos ||
            response.find("X-Signature: test-signature") == std::string::npos ||
            response.find("\r\n\r\nsigned-body") == std::string::npos)
            return 1;
        std::cout << "activation license replay server returned signed bytes\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::filesystem::remove(response_path);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
