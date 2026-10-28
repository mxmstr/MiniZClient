#pragma once

#include "common.h"
#include "aes_key.h"

#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <vector>

class LsxServer 
{

public:
    
    LsxServer(std::string bind_host, std::uint16_t port, std::wstring eaid,
              std::wstring content_id, std::string auth_token, std::string game_title,
              std::uint64_t account_id = 1000000000001ull);
    ~LsxServer();

    LsxServer(const LsxServer&) = delete;
    LsxServer& operator=(const LsxServer&) = delete;

    [[nodiscard]] std::uint16_t port() const;

private:

    class Impl;
    std::unique_ptr<Impl> impl_;

};

struct ClientSession 
{
    std::unique_ptr<AesKey> key;
    std::string content_id;
    std::string game_version = "1.0.0.0";
    std::string game_title;
    bool login_events_sent = false;
};

class LsxServer::Impl 
{

public:
    
    [[nodiscard]] std::uint16_t port() const { return port_; }

    Impl(std::string bind_host, std::uint16_t port, std::wstring eaid, std::wstring content_id,
         std::string auth_token, std::string game_title, std::uint64_t account_id);

    ~Impl();

private:

    std::uint16_t port_;
    std::string eaid_;
    std::string content_id_;
    std::string account_id_;
    std::string auth_token_;
    std::string game_title_;
    bool winsock_started_ = false;
    std::string bind_host_;
    SOCKET listener_ = INVALID_SOCKET;
    std::atomic<bool> stopping_{false};
    std::thread worker_;
    std::mutex clients_mutex_;
    std::set<SOCKET> active_clients_;
    std::vector<std::thread> client_threads_;

    [[noreturn]] void fail_socket(const char* operation);
    void run();
    void serve(SOCKET client);
    bool handle_challenge(SOCKET client, const std::string& xml, ClientSession& session);
    std::string make_response(const std::string& xml, const ClientSession& session);
    bool send_packet(SOCKET client, const std::string& xml, const AesKey* key);

};
