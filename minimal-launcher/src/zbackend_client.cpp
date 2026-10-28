#include "zbackend_client.h"

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <vector>

namespace {

constexpr std::uint32_t kHelloMagic = 0xdefec8ed;
constexpr std::uint16_t kDeadMagic = 0xdead;
constexpr std::uint32_t kProtocol = 0xc588f5f6;

void put_le32(unsigned char* p, std::uint32_t value) {
    p[0] = static_cast<unsigned char>(value);
    p[1] = static_cast<unsigned char>(value >> 8);
    p[2] = static_cast<unsigned char>(value >> 16);
    p[3] = static_cast<unsigned char>(value >> 24);
}

std::uint32_t get_le32(const unsigned char* p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint32_t get_be32(const unsigned char* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           static_cast<std::uint32_t>(p[3]);
}

std::string narrow_utf8(std::wstring_view value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                         value.data(), static_cast<int>(value.size()),
                                         nullptr, 0, nullptr, nullptr);
    if (size <= 0) throw std::runtime_error("backend login is not valid Unicode");
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                        static_cast<int>(value.size()), result.data(), size,
                        nullptr, nullptr);
    return result;
}

std::wstring widen_utf8(std::string_view value) {
    if (value.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                         value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (size <= 0) return {};
    std::wstring result(size, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                        static_cast<int>(value.size()), result.data(), size);
    return result;
}

std::vector<unsigned char> decode_hex(std::string_view text) {
    if (text.size() != 32) throw std::runtime_error("--zbackend-digest must contain exactly 32 hex characters");
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<unsigned char> result(16);
    for (std::size_t i = 0; i < result.size(); ++i) {
        const int hi = nibble(text[i * 2]);
        const int lo = nibble(text[i * 2 + 1]);
        if (hi < 0 || lo < 0) throw std::runtime_error("--zbackend-digest contains a non-hex character");
        result[i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return result;
}

void send_all(SOCKET socket, const unsigned char* data, std::size_t size) {
    while (size) {
        const int sent = send(socket, reinterpret_cast<const char*>(data),
                              static_cast<int>(size), 0);
        if (sent <= 0) throw std::runtime_error("zbackend send failed: " + std::to_string(WSAGetLastError()));
        data += sent;
        size -= static_cast<std::size_t>(sent);
    }
}

void recv_all(SOCKET socket, unsigned char* data, std::size_t size) {
    while (size) {
        const int received = recv(socket, reinterpret_cast<char*>(data),
                                  static_cast<int>(size), 0);
        if (received <= 0) throw std::runtime_error("zbackend connection closed");
        data += received;
        size -= static_cast<std::size_t>(received);
    }
}

class AesDirection {
public:
    explicit AesDirection(const std::array<unsigned char, 16>& clear) {
        std::array<unsigned char, 16> key{};
        std::memcpy(key.data(), clear.data(), 4);
        std::memcpy(key.data() + 4, "FUCK", 4);
        std::memcpy(key.data() + 8, clear.data() + 4, 4);
        std::memcpy(key.data() + 12, "_RKN", 4);
        std::memcpy(iv_.data(), clear.data() + 8, 4);
        std::memcpy(iv_.data() + 4, "NKR_", 4);
        std::memcpy(iv_.data() + 8, clear.data() + 12, 4);
        std::memcpy(iv_.data() + 12, "KCUF", 4);

        if (BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0 ||
            BCryptSetProperty(algorithm_, BCRYPT_CHAINING_MODE,
                              reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
                              sizeof(BCRYPT_CHAIN_MODE_CBC), 0) < 0) {
            throw std::runtime_error("could not initialize backend AES");
        }
        DWORD object_length = 0;
        DWORD result_size = 0;
        if (BCryptGetProperty(algorithm_, BCRYPT_OBJECT_LENGTH,
                              reinterpret_cast<PUCHAR>(&object_length), sizeof(object_length),
                              &result_size, 0) < 0) {
            throw std::runtime_error("could not query backend AES");
        }
        object_.resize(object_length);
        if (BCryptGenerateSymmetricKey(algorithm_, &key_, object_.data(),
                                       static_cast<ULONG>(object_.size()), key.data(),
                                       static_cast<ULONG>(key.size()), 0) < 0) {
            throw std::runtime_error("could not create backend AES key");
        }
    }

    ~AesDirection() {
        if (key_) BCryptDestroyKey(key_);
        if (algorithm_) BCryptCloseAlgorithmProvider(algorithm_, 0);
    }

    void crypt(bool encrypt, unsigned char* data, std::size_t size) {
        if (!size || size % 16) throw std::runtime_error("invalid backend AES block length");
        std::array<unsigned char, 16> iv = iv_;
        ULONG written = 0;
        const NTSTATUS status = encrypt
            ? BCryptEncrypt(key_, data, static_cast<ULONG>(size), nullptr, iv.data(),
                            static_cast<ULONG>(iv.size()), data, static_cast<ULONG>(size), &written, 0)
            : BCryptDecrypt(key_, data, static_cast<ULONG>(size), nullptr, iv.data(),
                            static_cast<ULONG>(iv.size()), data, static_cast<ULONG>(size), &written, 0);
        if (status < 0 || written != size) throw std::runtime_error("backend AES operation failed");
        if (encrypt) {
            std::memcpy(iv_.data(), data + size - 16, 16);
        } else {
            // BCrypt mutates its IV, so retain the final ciphertext block captured before decrypt.
            iv_ = iv;
        }
    }

    void decrypt_with_chaining(unsigned char* data, std::size_t size) {
        std::array<unsigned char, 16> last{};
        std::memcpy(last.data(), data + size - 16, 16);
        crypt(false, data, size);
        iv_ = last;
    }

private:
    BCRYPT_ALG_HANDLE algorithm_ = nullptr;
    BCRYPT_KEY_HANDLE key_ = nullptr;
    std::vector<unsigned char> object_;
    std::array<unsigned char, 16> iv_{};
};

} // namespace

class ZBackendClient::Impl {
public:
    Impl(std::wstring endpoint, std::wstring login, std::string digest_hex)
        : login_(std::move(login)) {
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data)) throw std::runtime_error("WSAStartup failed");
        wsa_started_ = true;
        connect_socket(endpoint);
        handshake();
        authenticate(decode_hex(digest_hex));
        worker_ = std::thread([this] { keep_alive(); });
    }

    ~Impl() {
        stopping_.store(true);
        if (socket_ != INVALID_SOCKET) shutdown(socket_, SD_BOTH);
        if (worker_.joinable()) worker_.join();
        if (socket_ != INVALID_SOCKET) closesocket(socket_);
        if (wsa_started_) WSACleanup();
    }

    void connect_socket(const std::wstring& endpoint) {
        std::wstring host = endpoint;
        std::wstring port = L"48385";
        const std::size_t colon = endpoint.rfind(L':');
        if (colon != std::wstring::npos && endpoint.find(L':') == colon) {
            host = endpoint.substr(0, colon);
            port = endpoint.substr(colon + 1);
        }
        if (host.empty() || port.empty()) throw std::runtime_error("invalid --zbackend endpoint");
        ADDRINFOW hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        PADDRINFOW addresses = nullptr;
        if (GetAddrInfoW(host.c_str(), port.c_str(), &hints, &addresses)) {
            throw std::runtime_error("could not resolve zbackend endpoint");
        }
        for (PADDRINFOW address = addresses; address; address = address->ai_next) {
            socket_ = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
            if (socket_ != INVALID_SOCKET &&
                connect(socket_, address->ai_addr, static_cast<int>(address->ai_addrlen)) == 0) break;
            if (socket_ != INVALID_SOCKET) closesocket(socket_);
            socket_ = INVALID_SOCKET;
        }
        FreeAddrInfoW(addresses);
        if (socket_ == INVALID_SOCKET) throw std::runtime_error("could not connect to zbackend");
    }

    void handshake() {
        std::array<unsigned char, 16> clear{};
        if (BCryptGenRandom(nullptr, clear.data(), static_cast<ULONG>(clear.size()),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
            throw std::runtime_error("could not generate backend handshake");
        }
        out_ = std::make_unique<AesDirection>(clear);
        std::array<unsigned char, 32> hello{};
        std::memcpy(hello.data(), clear.data(), 16);
        BCryptGenRandom(nullptr, hello.data() + 16, 4, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        put_le32(hello.data() + 20, kHelloMagic);
        hello[24] = static_cast<unsigned char>(kDeadMagic);
        hello[25] = static_cast<unsigned char>(kDeadMagic >> 8);
        put_le32(hello.data() + 28, kProtocol);
        out_->crypt(true, hello.data() + 16, 16);
        send_all(socket_, hello.data(), hello.size());

        recv_all(socket_, hello.data(), hello.size());
        std::array<unsigned char, 16> server_clear{};
        std::memcpy(server_clear.data(), hello.data(), 16);
        in_ = std::make_unique<AesDirection>(server_clear);
        in_->decrypt_with_chaining(hello.data() + 16, 16);
        if (get_le32(hello.data() + 20) != kHelloMagic ||
            hello[24] != static_cast<unsigned char>(kDeadMagic) ||
            hello[25] != static_cast<unsigned char>(kDeadMagic >> 8)) {
            throw std::runtime_error("zbackend returned an invalid handshake");
        }
    }

    void send_packet(const std::vector<unsigned char>& packet) {
        const std::size_t padded = (packet.size() + 15) & ~std::size_t(15);
        std::vector<unsigned char> encrypted(padded);
        std::memcpy(encrypted.data(), packet.data(), packet.size());
        out_->crypt(true, encrypted.data(), encrypted.size());
        send_all(socket_, encrypted.data(), encrypted.size());
    }

    std::vector<unsigned char> receive_packet() {
        std::array<unsigned char, 16> first{};
        recv_all(socket_, first.data(), first.size());
        in_->decrypt_with_chaining(first.data(), first.size());
        const std::size_t size = 5 + get_le32(first.data() + 1);
        if (size < 5 || size > 16 * 1024 * 1024) throw std::runtime_error("invalid zbackend packet length");
        const std::size_t padded = (size + 15) & ~std::size_t(15);
        std::vector<unsigned char> packet(padded);
        std::memcpy(packet.data(), first.data(), first.size());
        if (padded > 16) {
            recv_all(socket_, packet.data() + 16, padded - 16);
            in_->decrypt_with_chaining(packet.data() + 16, padded - 16);
        }
        packet.resize(size);
        return packet;
    }

    void authenticate(const std::vector<unsigned char>& digest) {
        const std::string login = narrow_utf8(login_);
        if (login.empty() || login.size() > 64) throw std::runtime_error("invalid zbackend login name");
        std::vector<unsigned char> packet(6 + login.size() + 1 + digest.size(), 0);
        packet[0] = 4;
        put_le32(packet.data() + 1, static_cast<std::uint32_t>(packet.size() - 5));
        std::memcpy(packet.data() + 6, login.data(), login.size());
        std::memcpy(packet.data() + 7 + login.size(), digest.data(), digest.size());
        send_packet(packet);
        const std::vector<unsigned char> reply = receive_packet();
        if (reply.size() < 23 || reply[0] != 4 || reply[9] != 1) {
            throw std::runtime_error("zbackend rejected the account login");
        }
        account_id_ = get_be32(reply.data() + 10);
        const char* name = reinterpret_cast<const char*>(reply.data() + 22);
        const std::size_t available = reply.size() - 22;
        const std::size_t length = strnlen(name, available);
        if (!account_id_ || length == available) throw std::runtime_error("zbackend returned an invalid identity");
        display_name_ = widen_utf8(std::string_view(name, length));
        if (display_name_.empty()) display_name_ = login_;

        // Complete the same two state transitions as the original client so
        // this is a presence-capable backend session, not merely an accepted
        // credential socket. The backend may interleave friend/presence
        // snapshots, so wait for the command-specific terminal packet.
        send_packet({16, 4, 0, 0, 0, 0x68, 0xaf, 0xa2, 0x09});
        for (;;) {
            const auto sync = receive_packet();
            if (!sync.empty() && sync[0] == 16) break;
        }
        send_packet({17, 5, 0, 0, 0, 2, 0x8d, 0x29, 0x37, 0xa1});
        for (;;) {
            const auto complete = receive_packet();
            if (!complete.empty() && complete[0] == 6) break;
        }
        std::wcout << L"Authenticated with zbackend as " << display_name_
                   << L" (account " << account_id_ << L"); presence synchronized\n";
    }

    void keep_alive() noexcept {
        try {
            while (!stopping_.load()) {
                for (int i = 0; i < 20 && !stopping_.load(); ++i)
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                if (stopping_.load()) break;
                send_packet({0, 0, 0, 0, 0});
                const auto reply = receive_packet();
                if (reply.size() != 5 || reply[0] != 0)
                    std::cout << "zbackend delivered packet type " << unsigned(reply[0]) << '\n';
            }
        } catch (const std::exception& error) {
            if (!stopping_.load()) std::cerr << "zbackend session: " << error.what() << '\n';
        }
    }

    SOCKET socket_ = INVALID_SOCKET;
    bool wsa_started_ = false;
    std::unique_ptr<AesDirection> in_;
    std::unique_ptr<AesDirection> out_;
    std::wstring login_;
    std::wstring display_name_;
    std::uint32_t account_id_ = 0;
    std::atomic_bool stopping_{false};
    std::thread worker_;
};

ZBackendClient::ZBackendClient(std::wstring endpoint, std::wstring login,
                               std::string digest_hex)
    : impl_(std::make_unique<Impl>(std::move(endpoint), std::move(login),
                                   std::move(digest_hex))) {}
ZBackendClient::~ZBackendClient() = default;
std::uint32_t ZBackendClient::account_id() const { return impl_->account_id_; }
const std::wstring& ZBackendClient::display_name() const { return impl_->display_name_; }
