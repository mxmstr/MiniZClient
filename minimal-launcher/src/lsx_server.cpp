#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>

#include "common.h"
#include "lsx_server.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace 
{

constexpr std::array<unsigned char, 16> kDefaultKey = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
};
constexpr std::string_view kChallenge = "cacf897a20b6d612ad0c05e011df52bb";
constexpr std::string_view kZloAuthToken = "WAHAHA_IMMA_ZLO_TOKEN";
constexpr std::string_view kLocalAuthTokenPrefix = "ZLOCAL1:";

std::mutex g_output_mutex;

void debug_lsx(std::string_view message) {
    std::string output = "[ZClient.LSX] ";
    output.append(message);
    if (output.empty() || output.back() != '\n') output.push_back('\n');
    OutputDebugStringA(output.c_str());
}

std::string narrow(std::wstring_view value) 
{
    if (value.empty()) 
    {
        return {};
    }

    const int needed = WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                           static_cast<int>(value.size()),
                                           nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
    {
        return {};
    }

    std::string result(static_cast<std::size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                        result.data(), needed, nullptr, nullptr);
    
    return result;
}

std::string xml_escape(std::string_view value) 
{
    std::string result;
    result.reserve(value.size());

    for (const char ch : value) 
    {
        switch (ch) 
        {
            case '&': result += "&amp;"; break;
            case '<': result += "&lt;"; break;
            case '>': result += "&gt;"; break;
            case '\"': result += "&quot;"; break;
            case '\'': result += "&apos;"; break;
            default: result.push_back(ch); break;
        }
    }

    return result;
}

std::optional<std::string> xml_attribute(std::string_view xml,
                                         std::string_view name) 
{
    const std::string prefix = std::string(name) + "=\"";
    const std::size_t start = xml.find(prefix);

    if (start == std::string_view::npos) 
    {
        return std::nullopt;
    }

    const std::size_t value_start = start + prefix.size();
    const std::size_t end = xml.find('\"', value_start);

    if (end == std::string_view::npos) 
    {
        return std::nullopt;
    }

    return std::string(xml.substr(value_start, end - value_start));
}

std::optional<std::string> xml_element(std::string_view xml,
                                       std::string_view name)
{
    const std::string open = "<" + std::string(name) + ">";
    const std::string close = "</" + std::string(name) + ">";
    const std::size_t start = xml.find(open);

    if (start == std::string_view::npos) 
    {
        return std::nullopt;
    }

    const std::size_t value_start = start + open.size();
    const std::size_t end = xml.find(close, value_start);

    if (end == std::string_view::npos) 
    {
        return std::nullopt;
    }

    return std::string(xml.substr(value_start, end - value_start));
}

std::string hex_encode(const std::vector<unsigned char>& bytes) 
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string result(bytes.size() * 2, '\0');
    
    for (std::size_t i = 0; i < bytes.size(); ++i) 
    {
        result[i * 2] = digits[bytes[i] >> 4];
        result[i * 2 + 1] = digits[bytes[i] & 0x0f];
    }
    
    return result;
}

int hex_value(char ch) 
{
    if (ch >= '0' && ch <= '9') 
    {
        return ch - '0';
    }

    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    
    if (ch >= 'a' && ch <= 'f') 
    {
        return ch - 'a' + 10;
    }

    return -1;
}

std::vector<unsigned char> hex_decode(std::string_view text) 
{
    std::vector<unsigned char> result;
    result.reserve(text.size() / 2);
    int high = -1;
    
    for (const char ch : text) 
    {
        const int value = hex_value(ch);
        if (value < 0) 
        {
            continue;
        }
        if (high < 0) 
        {
            high = value;
        } 
        else 
        {
            result.push_back(static_cast<unsigned char>((high << 4) | value));
            high = -1;
        }
    }

    if (high >= 0) return {};
    
    return result;
}

std::array<unsigned char, 16> make_lsx_key(std::uint16_t seed) 
{
    if (!seed)
    {
        return kDefaultKey;
    }

    auto crand = [](std::uint32_t& state) 
    {
        state = state * 214013u + 2531011u;
        return (state >> 16) & 0xffffu;
    };
    
    std::uint32_t state = 7;
    const std::uint32_t first = crand(state);
    state = first + seed;
    std::array<unsigned char, 16> result{};

    for (auto& byte : result) 
    {
        byte = static_cast<unsigned char>(crand(state));
    }

    return result;
}

bool send_all(SOCKET socket, std::string_view bytes) 
{
    std::size_t sent = 0;

    while (sent < bytes.size()) 
    {
        const int result = send(socket, bytes.data() + sent,
                                static_cast<int>(bytes.size() - sent), 0);
        if (result <= 0) 
        {
            return false;
        }

        sent += static_cast<std::size_t>(result);
    }

    return true;
}

std::string request_tag(std::string_view xml) 
{
    const std::size_t request = xml.find("<Request");
    if (request == std::string_view::npos) 
    {
        return {};
    }

    const std::size_t start = xml.find('<', request + 1);
    if (start == std::string_view::npos) 
    {
        return {};
    }

    const std::size_t end = xml.find_first_of(" />\t\r\n", start + 1);
    if (end == std::string_view::npos) 
    {
        return {};
    }

    return std::string(xml.substr(start + 1, end - start - 1));
}

std::string services_response() 
{
    static constexpr std::pair<std::string_view, std::string_view> services[] = {
        {"EbisuSDK", "SDK"}, {"EbisuSDK", "PROFILE"},
        {"XMPP", "PRESENCE"}, {"XMPP", "FRIENDS"},
        {"Commerce", "COMMERCE"}, {"EbisuSDK", "RECENTPLAYER"},
        {"EbisuSDK", "IGO"}, {"EbisuSDK", "MISC"},
        {"EALS", "LOGIN"}, {"Utility", "UTILITY"},
        {"XMPP", "XMPP"}, {"XMPP", "CHAT"},
        {"EbisuSDK", "IGO_EVENT"}, {"EALS", "EALS_EVENTS"},
        {"EbisuSDK", "LOGIN_EVENT"}, {"XMPP", "INVITE_EVENT"},
        {"EbisuSDK", "PROFILE_EVENT"}, {"XMPP", "PRESENCE_EVENT"},
        {"XMPP", "FRIENDS_EVENT"}, {"Commerce", "COMMERCE_EVENT"},
        {"XMPP", "CHAT_EVENT"}, {"EbisuSDK", "DOWNLOAD_EVENT"},
        {"EbisuSDK", "PERMISSION"}, {"EbisuSDK", "RESOURCES"},
        {"EbisuSDK", "BLOCKED_USERS"}, {"EbisuSDK", "BLOCKED_USER_EVENT"},
        {"EbisuSDK", "GET_USERID"}, {"EbisuSDK", "ONLINE_STATUS_EVENT"},
        {"EbisuSDK", "ACHIEVEMENT"}, {"EbisuSDK", "ACHIEVEMENT_EVENT"},
        {"EbisuSDK", "BROADCAST_EVENT"}, {"PI", "PROGRESSIVE_INSTALLATION"},
        {"PI", "PROGRESSIVE_INSTALLATION_EVENT"}, {"EbisuSDK", "CONTENT"},
    };

    std::string result = "<GetConfigResponse>";
    for (const auto& [name, facility] : services) 
    {
        result += "<Service Name=\"" + std::string(name) + "\" Facility=\"" + std::string(facility) + "\"/>";
    }

    result += "</GetConfigResponse>";

    return result;
}

} // namespace


LsxServer::LsxServer(std::string bind_host, std::uint16_t port, std::wstring eaid,
                     std::wstring content_id, std::string auth_token, std::string game_title,
                     std::uint64_t account_id, std::uint32_t client_token)
    : impl_(std::make_unique<Impl>(std::move(bind_host), port, std::move(eaid),
                                   std::move(content_id), std::move(auth_token),
                                   std::move(game_title), account_id, client_token)) {}
                                   
LsxServer::~LsxServer() = default;

LsxServer::Impl::Impl(std::string bind_host, std::uint16_t port, std::wstring eaid, std::wstring content_id,
         std::string auth_token, std::string game_title, std::uint64_t account_id)
    : Impl(std::move(bind_host), port, std::move(eaid), std::move(content_id),
           std::move(auth_token), std::move(game_title), account_id,
           0xa0000009u) {}

LsxServer::Impl::Impl(std::string bind_host, std::uint16_t port, std::wstring eaid,
         std::wstring content_id, std::string auth_token, std::string game_title,
         std::uint64_t account_id, std::uint32_t client_token)
        : port_(port), eaid_(narrow(eaid)), content_id_(narrow(content_id)),
          account_id_(std::to_string(account_id)), auth_token_(std::move(auth_token)),
          game_title_(std::move(game_title)), client_token_(client_token),
          bind_host_(std::move(bind_host)) 
{
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) 
    {
        fail("WSAStartup for LSX server failed");
    }
    winsock_started_ = true;

    // Fail early if the platform AES provider cannot round-trip the LSX
    // encoding used after ChallengeAccepted.
    {
        const AesKey self_test_key(kDefaultKey);
        constexpr std::string_view plaintext = "lsx-self-test";
        if (self_test_key.decrypt(self_test_key.encrypt(plaintext)) != plaintext) 
        {
            fail("LSX AES self-test failed");
        }
    }

    listener_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener_ == INVALID_SOCKET) fail_socket("socket");

    BOOL exclusive = TRUE;
    setsockopt(listener_, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port_);
    if (inet_pton(AF_INET, bind_host_.c_str(), &address.sin_addr) != 1) 
    {
        fail("LSX bind host must be an IPv4 address.");
    }

    if (bind(listener_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) 
    {
        fail_socket("bind(LSX)");
    }

    int address_size = sizeof(address);
    if (getsockname(listener_, reinterpret_cast<sockaddr*>(&address), &address_size) == SOCKET_ERROR) 
    {
        fail_socket("getsockname(LSX)");
    }

    if (listen(listener_, SOMAXCONN) == SOCKET_ERROR)
    {
        fail_socket("listen(LSX)");
    }

    u_long nonblocking = 1;
    ioctlsocket(listener_, FIONBIO, &nonblocking);
    worker_ = std::thread([this] { run(); });
    std::lock_guard lock(g_output_mutex);
    port_ = ntohs(address.sin_port);

    std::cout << "LSX service is listening on " << bind_host_ << ':' << port_ << '\n';
}

LsxServer::Impl::~Impl() 
{
    stopping_.store(true, std::memory_order_release);
    
    if (listener_ != INVALID_SOCKET) 
    {
        closesocket(listener_);
    }
    
    if (worker_.joinable()) 
    {
        worker_.join();
    }
    
    listener_ = INVALID_SOCKET;

    std::vector<SOCKET> active;
    {
        std::lock_guard lock(clients_mutex_);
        active.assign(active_clients_.begin(), active_clients_.end());
        active_clients_.clear();
    }
    
    for (const SOCKET client : active) 
    {
        shutdown(client, SD_BOTH);
        closesocket(client);
    }
    
    for (auto& client_thread : client_threads_) 
    {
        if (client_thread.joinable()) 
        {
            client_thread.join();
        }
    }
    
    if (winsock_started_) 
    {
        WSACleanup();
    }
}

std::uint16_t LsxServer::port() const 
{
    return impl_->port();
}


[[noreturn]] void LsxServer::Impl::fail_socket(const char* operation) 
{
    const int error = WSAGetLastError();

    if (listener_ != INVALID_SOCKET) 
    {
        closesocket(listener_);
        listener_ = INVALID_SOCKET;
    }

    if (winsock_started_) 
    {
        WSACleanup();
        winsock_started_ = false;
    }

    fail(std::string(operation) + " failed (Winsock " + std::to_string(error) + ")");
}

void LsxServer::Impl::run() 
{
    while (!stopping_.load(std::memory_order_acquire)) 
    {
        SOCKET client = accept(listener_, nullptr, nullptr);

        if (client == INVALID_SOCKET) 
        {
            const int error = WSAGetLastError();

            if (error != WSAEWOULDBLOCK && error != WSAEINTR &&
                !stopping_.load(std::memory_order_acquire)) 
            {
                std::lock_guard lock(g_output_mutex);
                std::cout << "LSX accept failed (Winsock " << error << ")\n";
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(20));

            continue;
        }

        {
            std::lock_guard lock(clients_mutex_);
            active_clients_.insert(client);
        }

        try 
        {
            client_threads_.emplace_back([this, client] {
                try 
                {
                    serve(client);
                } 
                catch (const std::exception& error) 
                {
                    std::lock_guard lock(g_output_mutex);
                    std::cout << "LSX client worker failed: "
                                << error.what() << '\n';
                }
                bool close_client = false;
                {
                    std::lock_guard lock(clients_mutex_);
                    close_client = active_clients_.erase(client) != 0;
                }
                if (close_client) 
                {
                    closesocket(client);
                }
            });
        } 
        catch (const std::exception& error) 
        {
            {
                std::lock_guard lock(clients_mutex_);
                active_clients_.erase(client);
            }
            closesocket(client);
            std::lock_guard lock(g_output_mutex);
            std::cout << "Could not start LSX client worker: "
                        << error.what() << '\n';
        }
    }
}

void LsxServer::Impl::serve(SOCKET client) 
{
    DWORD timeout = 100;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    BOOL nodelay = TRUE;
    setsockopt(client, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

    {
        std::lock_guard lock(g_output_mutex);
        std::cout << "LSX client connected\n";
        debug_lsx("client connected");
    }

    // Older OriginSDK transports are server-first and wait for Challenge.
    // Rivals first sends the framed ZClient opcode-2 identity record on the
    // same stream, then changes that stream into an LSX session after the
    // token acknowledgement.
    std::array<unsigned char, 256> probe{};
    const int probed = recv(client, reinterpret_cast<char*>(probe.data()),
                            static_cast<int>(probe.size()), MSG_PEEK);
    bool identity_accepted = false;
    if (probed >= 5 && probe[0] == 2)
    {
        const std::uint32_t payload_length =
            (static_cast<std::uint32_t>(probe[1]) << 24) |
            (static_cast<std::uint32_t>(probe[2]) << 16) |
            (static_cast<std::uint32_t>(probe[3]) << 8) |
            static_cast<std::uint32_t>(probe[4]);
        const std::size_t frame_length = 5u + payload_length;
        if (frame_length <= probe.size() &&
            static_cast<std::size_t>(probed) >= frame_length)
        {
            std::vector<char> request(frame_length);
            if (recv(client, request.data(), static_cast<int>(request.size()), 0) !=
                static_cast<int>(request.size()))
            {
                return;
            }
            const std::array<unsigned char, 10> reply = {
                0x02, 0x00, 0x00, 0x00, 0x05, 0x01,
                static_cast<unsigned char>(client_token_ >> 24),
                static_cast<unsigned char>(client_token_ >> 16),
                static_cast<unsigned char>(client_token_ >> 8),
                static_cast<unsigned char>(client_token_),
            };
            if (send(client, reinterpret_cast<const char*>(reply.data()),
                     static_cast<int>(reply.size()), 0) !=
                static_cast<int>(reply.size()))
            {
                return;
            }
            debug_lsx("accepted opcode-2 identity and returned client token " +
                      std::to_string(client_token_));
            identity_accepted = true;
        }
    }
    if (probed > 0 && !identity_accepted)
    {
        static constexpr char digits[] = "0123456789abcdef";
        std::string hex;
        const std::size_t shown = std::min<std::size_t>(
            static_cast<std::size_t>(probed), 96);
        hex.reserve(shown * 3);
        for (std::size_t i = 0; i < shown; ++i)
        {
            if (i) hex.push_back(' ');
            hex.push_back(digits[probe[i] >> 4]);
            hex.push_back(digits[probe[i] & 0x0f]);
        }
        debug_lsx("rejected client-first EA broker record (" +
                  std::to_string(probed) + " bytes peeked): " + hex);
        return;
    }
    if (probed == SOCKET_ERROR)
    {
        const int error = WSAGetLastError();
        if (error != WSAETIMEDOUT && error != WSAEWOULDBLOCK &&
            error != WSAEINTR)
        {
            return;
        }
    }

    if (identity_accepted)
    {
        // This is the CMain/ZClient identity control channel. It remains open
        // while OriginSDK establishes LSX on the adjacent translated port;
        // sending an LSX Challenge here makes Rivals close the control socket
        // and abort initialization.
        timeout = 250;
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        std::array<char, 256> control_buffer{};
        while (!stopping_.load(std::memory_order_acquire))
        {
            const int result = recv(client, control_buffer.data(),
                                    static_cast<int>(control_buffer.size()), 0);
            if (result == 0) break;
            if (result == SOCKET_ERROR)
            {
                const int error = WSAGetLastError();
                if (error == WSAETIMEDOUT || error == WSAEWOULDBLOCK ||
                    error == WSAEINTR)
                {
                    continue;
                }
                break;
            }
            debug_lsx("identity control channel sent " +
                      std::to_string(result) + " additional byte(s)");
        }
        debug_lsx("identity control channel disconnected");
        return;
    }

    timeout = 250;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    const std::string challenge =
        "<LSX><Event sender=\"EALS\"><Challenge key=\"" +
        std::string(kChallenge) +
        "\" build=\"release\" version=\"13,387,0,5900\"/></Event></LSX>";

    if (!send_packet(client, challenge, nullptr)) 
    {
        return;
    }

    ClientSession session;
    session.game_title = game_title_;
    std::string pending;
    std::array<char, 8192> buffer{};

    while (!stopping_.load(std::memory_order_acquire)) 
    {
        const int received = recv(client, buffer.data(), static_cast<int>(buffer.size()), 0);
        
        if (received == 0) 
        {
            break;
        }

        if (received == SOCKET_ERROR) 
        {
            const int error = WSAGetLastError();
            if (error == WSAETIMEDOUT || error == WSAEWOULDBLOCK || error == WSAEINTR) 
            {
                continue;
            }
            break;
        }

        pending.append(buffer.data(), static_cast<std::size_t>(received));
        
        for (;;) 
        {
            const std::size_t end = pending.find('\0');

            if (end == std::string::npos) 
            {
                break;
            }

            std::string packet = pending.substr(0, end);
            pending.erase(0, end + 1);

            if (packet.empty()) 
            {
                continue;
            }

            std::string xml;
            try 
            {
                xml = session.key ? session.key->decrypt(hex_decode(packet)) : packet;
            } 
            catch (const std::exception& error) 
            {
                std::lock_guard lock(g_output_mutex);
                std::cout << "LSX decrypt failed: " << error.what() << '\n';
                debug_lsx(std::string("decrypt failed: ") + error.what());
                return;
            }

            {
                std::lock_guard lock(g_output_mutex);
                std::cout << "LSX received: " << xml << '\n';
                debug_lsx(std::string("received: ") + xml);
            }

            if (xml.find("<ChallengeResponse") != std::string::npos) 
            {
                if (!handle_challenge(client, xml, session)) return;
                continue;
            }

            const std::string tag = request_tag(xml);
            const std::string response = make_response(xml, session);
            if (!response.empty() && !send_packet(client, response, session.key.get())) 
            {
                return;
            }

            // OriginCheckOnline reads state populated by these asynchronous
            // events; a successful GetProfile response alone does not mark
            // the Origin user or the client connection as online.  Send them
            // only after the profile request has completed so OriginSDK has
            // installed the event facilities returned by GetConfig.
            if (tag == "GetProfile")
            {
                const std::string login_event =
                    "<LSX><Event sender=\"EbisuSDK\">"
                    "<Login IsLoggedIn=\"true\" UserIndex=\"0\""
                    " LoginReasonCode=\"ALREADY_ONLINE\"/>"
                    "</Event></LSX>";
                const std::string online_event =
                    "<LSX><Event sender=\"EbisuSDK\">"
                    "<OnlineStatusEvent isOnline=\"true\"/>"
                    "</Event></LSX>";

                if (!send_packet(client, login_event, session.key.get()) ||
                    !send_packet(client, online_event, session.key.get()))
                {
                    return;
                }
                session.login_events_sent = true;
            }
        }
    }

    std::lock_guard lock(g_output_mutex);
    std::cout << "LSX client disconnected\n";
    debug_lsx("client disconnected");
}

bool LsxServer::Impl::handle_challenge(SOCKET client, const std::string& xml,
                        ClientSession& session) 
{
    const std::string id = xml_attribute(xml, "id").value_or("0");
    const std::string recipient = xml_attribute(xml, "recipient").value_or("EALS");
    // Some OriginSDK builds put version="" on the outer Request. Limit
    // these lookups to the ChallengeResponse element so that empty wrapper
    // metadata cannot hide the actual encryption protocol version.
    const std::size_t challenge_offset = xml.find("<ChallengeResponse");
    const std::string_view challenge_xml = challenge_offset == std::string::npos
        ? std::string_view(xml)
        : std::string_view(xml).substr(challenge_offset);
    const std::string client_key =
        xml_attribute(challenge_xml, "key").value_or("");
    const std::string client_response =
        xml_attribute(challenge_xml, "response").value_or("");
    const std::string protocol =
        xml_attribute(challenge_xml, "version").value_or("2");

    // CMain rewrites the key independently from the response in the
    // minimal path. OriginSDK accepts only the acknowledgement derived
    // from that rewritten key; echoing client_response closes LSX before
    // GetConfig even though the unmodified ZClient trace shows equality.
    if (client_key.empty() || client_response.empty())
    {
        return false;
    } 

    const AesKey default_key(kDefaultKey);
    const std::string accept_key = hex_encode(default_key.encrypt(client_key));
    const std::string response =
        "<LSX><Response sender=\"" + xml_escape(recipient) + "\" id=\"" +
        xml_escape(id) + "\"><ChallengeAccepted response=\"" + accept_key +
        "\"/></Response></LSX>";
    
    if (!send_packet(client, response, nullptr)) 
    {
        return false;
    }

    std::uint16_t seed = 0;
    if (protocol == "3" && accept_key.size() >= 2) 
    {
        seed = static_cast<std::uint16_t>(
            (static_cast<unsigned char>(accept_key[0]) << 8) |
            static_cast<unsigned char>(accept_key[1]));
    }

    session.key = std::make_unique<AesKey>(make_lsx_key(seed));
    session.game_version = xml_element(xml, "Version").value_or("1.0.0.0");
    session.game_title = xml_element(xml, "Title").value_or(game_title_);
    const std::string reported_content = xml_element(xml, "ContentId").value_or(content_id_);
    session.content_id = reported_content;

    {
        std::lock_guard lock(g_output_mutex);
        std::cout << "LSX challenge accepted: title " << session.game_title
                    << ", content " << reported_content << ", version "
                    << session.game_version << ", protocol " << protocol << '\n';
    }

    return true;
}

std::string LsxServer::Impl::make_response(const std::string& xml,
                            const ClientSession& session) 
{
    enum class Request 
    {
        unknown,
        get_config,
        get_profile,
        get_setting,
        get_game_info,
        get_all_game_info,
        is_progressive_installation_available,
        are_chunks_installed,
        get_internet_connected_state,
        request_license,
        get_auth_token,
        get_auth_code,
        get_block_list,
        get_presence,
        query_friends,
        query_presence,
        query_entitlements,
        query_offers,
        get_voip_status,
        set_downloader_utilization,
    };

    const auto classify_request = [](std::string_view value) 
    {
        struct Entry 
        {
            std::string_view tag;
            Request request;
        };
        
        static constexpr Entry entries[] = {
            {"GetConfig", Request::get_config},
            {"GetProfile", Request::get_profile},
            {"GetSetting", Request::get_setting},
            {"GetGameInfo", Request::get_game_info},
            {"GetAllGameInfo", Request::get_all_game_info},
            {"IsProgressiveInstallationAvailable", Request::is_progressive_installation_available},
            {"AreChunksInstalled", Request::are_chunks_installed},
            {"GetInternetConnectedState", Request::get_internet_connected_state},
            {"RequestLicense", Request::request_license},
            {"GetAuthToken", Request::get_auth_token},
            {"GetAuthCode", Request::get_auth_code},
            {"GetBlockList", Request::get_block_list},
            {"GetPresence", Request::get_presence},
            {"QueryFriends", Request::query_friends},
            {"QueryPresence", Request::query_presence},
            {"QueryEntitlements", Request::query_entitlements},
            {"QueryOffers", Request::query_offers},
            {"GetVoipStatus", Request::get_voip_status},
            {"SetDownloaderUtilization", Request::set_downloader_utilization},
        };

        for (const Entry& entry : entries) {
            if (value == entry.tag) return entry.request;
        }
        return Request::unknown;
    };

    const std::string tag = request_tag(xml);
    if (tag.empty()) return {};
    const std::string id = xml_attribute(xml, "id").value_or("0");
    const std::string sender = xml_attribute(xml, "recipient").value_or("EbisuSDK");
    std::string body;

    switch (classify_request(tag)) 
    {
        case Request::get_config:
            body = services_response();
            break;
        case Request::get_profile:
            body = "<GetProfileResponse UserIndex=\"0\" PersonaId=\"" + account_id_ +
                "\" IsSubscriber=\"false\" IsTrialSubscriber=\"false\""
                " SubscriberLevel=\"0\" IsSteamSubscriber=\"false\" Persona=\"" +
                xml_escape(eaid_) +
                "\" CommerceCountry=\"US\" AvatarId=\"C:\\ProgramData\\ZLOEmu\\Avatars\\" +
                account_id_ + "_40x40.png\" UserId=\"" + account_id_ +
                "\" GeoCountry=\"US\" CommerceCurrency=\"ZLO\" Country=\"RU\""
                " IsUnderAge=\"false\"/>";
            break;
        case Request::get_setting: {
            const std::string setting = xml_attribute(xml, "SettingId").value_or("");
            const std::string value =
                (setting == "ENVIRONMENT" || setting == "Environment")
                    ? "production"
                    : "false";
            body = "<GetSettingResponse Setting=\"" + value + "\"/>";
            break;
        }
        case Request::get_game_info: {
            const std::string info = xml_attribute(xml, "GameInfoId").value_or("");
            std::string value = "false";
            if (info == "LANGUAGES") {
                value = "de_DE,en_US,es_ES,es_MX,fr_FR,it_IT,ja_JP,ko_KR,pl_PL,pt_BR,ru_RU,zh_CN,zh_TW";
            } else if (info == "INSTALLED_LANGUAGE") {
                value = "en_US";
            }
            body = "<GetGameInfoResponse GameInfo=\"" + value + "\"/>";
            break;
        }
        case Request::get_all_game_info:
            body = "<GetAllGameInfoResponse FullGamePurchased=\"true\""
                " FullGameReleased=\"true\" InstalledVersion=\"" +
                xml_escape(session.game_version) +
                "\" MaxGroupSize=\"16\""
                " Languages=\"de_DE,en_US,es_ES,es_MX,fr_FR,it_IT,ja_JP,ko_KR,pl_PL,pt_BR,ru_RU,zh_CN,zh_TW\""
                " Expiration=\"0000-00-00T00:00:00\" UpToDate=\"true\""
                " HasExpiration=\"false\" EntitlementSource=\"EA\""
                " AvailableVersion=\"" + xml_escape(session.game_version) +
                "\" DisplayName=\"" + xml_escape(session.game_title) +
                "\" FreeTrial=\"false\" InstalledLanguage=\"en_US\""
                " FullGameReleaseDate=\"2013-11-15T00:00:00\""
                " SystemTime=\"2026-09-25T00:00:00\"/>";
            break;
        case Request::is_progressive_installation_available:
            body = "<IsProgressiveInstallationAvailableResponse ItemId=\"" +
                xml_escape(xml_attribute(xml, "ItemId").value_or(content_id_)) +
                "\" Available=\"false\"/>";
            break;
        case Request::are_chunks_installed:
            body = "<AreChunksInstalledResponse ItemId=\"" +
                xml_escape(xml_attribute(xml, "ItemId").value_or(content_id_)) +
                "\" Installed=\"true\"/>";
            break;
        case Request::get_internet_connected_state:
            body = "<InternetConnectedState connected=\"1\"/>";
            break;
        case Request::request_license:
            body = "<RequestLicenseResponse License=\"\"/>";
            break;
        case Request::get_auth_token:
        {
            // The recovered ZLO LSX implementation returns this fixed
            // OriginSDK token. Rivals needs that legacy prefix to pass its
            // local sign-in gate, while the Blaze backend also needs the
            // instance identity. Append the launcher's private identity token
            // and configured account ID without changing the legacy prefix.
            std::string origin_token(kZloAuthToken);
            if (auth_token_.rfind(kLocalAuthTokenPrefix, 0) == 0) {
                origin_token += ":" + auth_token_ + ":" + account_id_;
            }
            body = "<AuthToken value=\"" + xml_escape(origin_token) + "\"/>";
            break;
        }
        case Request::get_auth_code:
            body = "<AuthCode value=\"invalid\"/>";
            break;
        case Request::get_block_list:
            body = "<GetBlockListResponse Return=\"Success\"/>";
            break;
        case Request::get_presence:
            body = "<GetPresenceResponse UserId=\"" + account_id_ +
                "\" Presence=\"INGAME\"/>";
            break;
        case Request::query_friends:
            body = "<QueryFriendsResponse>"
                "<Friend Presence=\"OFFLINE\" UserId=\"1\" State=\"MUTUAL\""
                " AvatarId=\"C:\\ProgramData\\ZLOEmu\\Avatars\\1_40x40.png\""
                " PersonaId=\"1\" Persona=\"jimmytenders\"/>"
                "</QueryFriendsResponse>";
            break;
        case Request::query_presence:
            body = "<QueryPresenceResponse/>";
            break;
        case Request::query_entitlements:
        {
            std::string group = xml_attribute(xml, "Group").value_or("");

            // Most Wanted 2012 asks for all entitlements with Group="" and
            // then uses the ONLINE_ACCESS result as its Origin-online gate.
            // These values are the PC DVD 1.0 entitlement constants embedded
            // in NFS13.exe.  An empty response leaves OriginSDK initialized
            // but makes the title report that no Origin user is signed in.
            const bool nfs13 = group.empty() &&
                (session.content_id == "71530" ||
                 session.game_title.find("Most Wanted") != std::string::npos);

            if (nfs13)
            {
                body = "<QueryEntitlementsResponse>"
                    "<Entitlement EntitlementTag=\"ONLINE_ACCESS\""
                    " Group=\"NFS13PC\" EntitlementId=\"300368\""
                    " ItemId=\"OFB-NWNA:22766\""
                    " GrantDate=\"2012-10-30T00:00:00Z\""
                    " LastModifiedDate=\"2012-10-30T00:00:00Z\""
                    " Type=\"ONLINE_ACCESS\"/>"
                    "</QueryEntitlementsResponse>";
            }
            else
            {
                body = "<QueryEntitlementsResponse/>";
            }
            break;
        }
            break;
        case Request::query_offers:
            body = "<QueryOffersResponse/>";
            break;
        case Request::get_voip_status:
            body = "<GetVoipStatusResponse Available=\"false\" Active=\"false\"/>";
            break;
        case Request::set_downloader_utilization:
            return {};
        case Request::unknown:
            body = "<ErrorSuccess Code=\"0\" Description=\"\"/>";
            break;
    }

    {
        std::lock_guard lock(g_output_mutex);
        std::cout << "LSX replying to " << tag << '\n';
        debug_lsx(std::string("replying to ") + tag);
    }

    return "<LSX><Response sender=\"" + xml_escape(sender) + "\" id=\"" +
            xml_escape(id) + "\">" + body + "</Response></LSX>";
}

bool LsxServer::Impl::send_packet(SOCKET client, const std::string& xml, const AesKey* key) 
{
    std::string packet = key ? hex_encode(key->encrypt(xml)) : xml;
    packet.push_back('\0');
    
    {
        std::lock_guard lock(g_output_mutex);
        std::cout << "LSX sent: " << xml << '\n';
        debug_lsx(std::string("sent: ") + xml);
    }

    return send_all(client, packet);
}
