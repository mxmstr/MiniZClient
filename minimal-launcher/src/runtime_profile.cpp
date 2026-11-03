#include "runtime_profile.h"

#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

constexpr std::string_view kRivalsActivationKeyHex =
    "62fb1baa79beb4492f02567f383095d6e349df14b9aea8582378f4b4484cd4af7"
    "1889c4025c07fabfc2d50491144f0b4b3bb9e044afb11b4ae1be2231b621e9f3"
    "143b17abab492e7f5dfcb6769e42fea900915589db930be5c8b19f2ab08f8386b"
    "f9e83abcaf1086f56cfc0a452fe2464b261826675df7d544d1c41dd3530312";

int hex_digit(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    value = static_cast<char>(std::tolower(static_cast<unsigned char>(value)));
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

std::vector<std::uint8_t> decode_hex(std::string_view value) {
    if (value.size() % 2) throw std::runtime_error("hex value has odd length");
    std::vector<std::uint8_t> result(value.size() / 2);
    for (std::size_t i = 0; i < result.size(); ++i) {
        const int high = hex_digit(value[i * 2]);
        const int low = hex_digit(value[i * 2 + 1]);
        if (high < 0 || low < 0) throw std::runtime_error("hex value contains a non-hex character");
        result[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return result;
}

std::string sha256(HANDLE file) {
    LARGE_INTEGER zero{};
    if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN))
        throw std::runtime_error("could not seek activation module");
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_size = 0;
    DWORD returned = 0;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                          reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size),
                          &returned, 0) < 0) {
        if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
        throw std::runtime_error("could not initialize SHA-256");
    }
    std::vector<std::uint8_t> object(object_size);
    if (BCryptCreateHash(algorithm, &hash, object.data(), object_size,
                         nullptr, 0, 0) < 0) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        throw std::runtime_error("could not create SHA-256 hash");
    }
    std::array<std::uint8_t, 64 * 1024> buffer{};
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) {
            BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0);
            throw std::runtime_error("could not read activation module for hashing");
        }
        if (!read) break;
        if (BCryptHashData(hash, buffer.data(), read, 0) < 0) {
            BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0);
            throw std::runtime_error("could not update SHA-256 hash");
        }
    }
    std::array<std::uint8_t, 32> digest{};
    const NTSTATUS status = BCryptFinishHash(
        hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) throw std::runtime_error("could not finish SHA-256 hash");
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (const auto byte : digest) {
        result.push_back(hex[byte >> 4]);
        result.push_back(hex[byte & 15]);
    }
    return result;
}

std::wstring module_name(HANDLE file) {
    std::wstring path(32768, L'\0');
    const DWORD length = GetFinalPathNameByHandleW(file, path.data(),
                                                   static_cast<DWORD>(path.size()),
                                                   FILE_NAME_NORMALIZED);
    if (!length || length >= path.size()) return {};
    path.resize(length);
    return std::filesystem::path(path).filename().wstring();
}

} // namespace

RuntimeProfile make_runtime_profile(const std::string& name,
                                    const std::string& activation_sha256) {
    if (name.empty()) return {};
    std::string normalized = name;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (normalized != "rivals" && normalized != "rivals-legacy-activation")
        throw std::runtime_error("Unknown compatibility profile: " + name);
    if (activation_sha256.size() != 64 ||
        std::any_of(activation_sha256.begin(), activation_sha256.end(),
                    [](char c) { return hex_digit(c) < 0; }))
        throw std::runtime_error("The Rivals activation profile requires a 64-hex activation-module-sha256.");
    std::string digest = activation_sha256;
    std::transform(digest.begin(), digest.end(), digest.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return {normalized, L"Activation.dll", digest, 0xC75E0};
}

bool apply_runtime_profile_module(const RuntimeProfile& profile,
                                  HANDLE process, HANDLE module_file,
                                  void* module_base) {
    if (profile.name.empty() || !module_file || module_file == INVALID_HANDLE_VALUE)
        return false;
    if (_wcsicmp(module_name(module_file).c_str(), profile.activation_module.c_str()) != 0)
        return false;
    const std::string actual_hash = sha256(module_file);
    if (actual_hash != profile.activation_sha256) {
        throw std::runtime_error("Activation.dll SHA-256 does not match the selected compatibility profile.");
    }

    const std::vector<std::uint8_t> replacement = decode_hex(kRivalsActivationKeyHex);
    constexpr std::array<std::uint8_t, 8> expected_prefix{
        0x6D, 0x9D, 0x6F, 0x88, 0xE7, 0x68, 0x45, 0x81};
    auto* target = static_cast<std::uint8_t*>(module_base) + profile.activation_key_rva;
    std::vector<std::uint8_t> before(replacement.size());
    SIZE_T read = 0;
    if (!ReadProcessMemory(process, target, before.data(), before.size(), &read) ||
        read != before.size())
        throw std::runtime_error("Could not read the profiled Activation.dll key.");
    if (before == replacement) return true;
    if (!std::equal(expected_prefix.begin(), expected_prefix.end(), before.begin()))
        throw std::runtime_error("Activation.dll key signature does not match the selected profile.");
    DWORD old_protection = 0;
    if (!VirtualProtectEx(process, target, replacement.size(), PAGE_READWRITE, &old_protection))
        throw std::runtime_error("Could not make the Activation.dll key writable.");
    SIZE_T written = 0;
    const bool wrote = WriteProcessMemory(process, target, replacement.data(),
                                          replacement.size(), &written) &&
                       written == replacement.size();
    DWORD ignored = 0;
    const bool restored = VirtualProtectEx(process, target, replacement.size(),
                                            old_protection, &ignored) != FALSE;
    if (!wrote || !restored)
        throw std::runtime_error("Could not apply the Activation.dll key profile.");
    std::cout << "Applied " << profile.name << " activation key profile to process "
              << GetProcessId(process) << '\n';
    return true;
}
