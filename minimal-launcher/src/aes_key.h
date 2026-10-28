
#pragma once

#include <bcrypt.h>

#include "common.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

class AesKey 
{

public:

    explicit AesKey(const std::array<unsigned char, 16>& bytes) 
    {
        NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_AES_ALGORITHM, nullptr, 0);
        
        if (status < 0) 
        {
            fail("BCryptOpenAlgorithmProvider(AES) failed");
        }

        status = BCryptSetProperty(
            algorithm_, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_ECB)),
            static_cast<ULONG>(sizeof(BCRYPT_CHAIN_MODE_ECB)), 0);
        
        if (status < 0)
        {
            fail("BCryptSetProperty(AES ECB) failed");
        }

        DWORD object_size = 0;
        DWORD copied = 0;
        status = BCryptGetProperty(algorithm_, BCRYPT_OBJECT_LENGTH,
                                   reinterpret_cast<PUCHAR>(&object_size),
                                   sizeof(object_size), &copied, 0);

        if (status < 0)
        {
            fail("BCryptGetProperty(AES object) failed");
        }

        key_object_.resize(object_size);

        status = BCryptGenerateSymmetricKey(
            algorithm_, &key_, key_object_.data(), object_size,
            const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0);
        
        if (status < 0)
        {
            fail("BCryptGenerateSymmetricKey failed");
        }
    }

    ~AesKey() 
    {
        if (key_) BCryptDestroyKey(key_);
        if (algorithm_) BCryptCloseAlgorithmProvider(algorithm_, 0);
    }

    AesKey(const AesKey&) = delete;
    AesKey& operator=(const AesKey&) = delete;

    std::vector<unsigned char> encrypt(std::string_view plaintext) const 
    {
        ULONG size = 0;
        NTSTATUS status = BCryptEncrypt(
            key_, reinterpret_cast<PUCHAR>(const_cast<char*>(plaintext.data())),
            static_cast<ULONG>(plaintext.size()), nullptr, nullptr, 0,
            nullptr, 0, &size, BCRYPT_BLOCK_PADDING);

        if (status < 0) 
        {
            fail("BCryptEncrypt(size) failed");
        }

        std::vector<unsigned char> result(size);
        status = BCryptEncrypt(
            key_, reinterpret_cast<PUCHAR>(const_cast<char*>(plaintext.data())),
            static_cast<ULONG>(plaintext.size()), nullptr, nullptr, 0,
            result.data(), static_cast<ULONG>(result.size()), &size,
            BCRYPT_BLOCK_PADDING);

        if (status < 0) 
        {
            fail("BCryptEncrypt failed");
        }

        result.resize(size);
        return result;
    }

    std::string decrypt(const std::vector<unsigned char>& ciphertext) const 
    {
        if (ciphertext.empty()) 
        {
            fail("empty LSX ciphertext");
        }

        ULONG size = 0;
        NTSTATUS status = BCryptDecrypt(
            key_, const_cast<PUCHAR>(ciphertext.data()),
            static_cast<ULONG>(ciphertext.size()), nullptr, nullptr, 0,
            nullptr, 0, &size, BCRYPT_BLOCK_PADDING);
        
        if (status < 0) 
        {
            fail("BCryptDecrypt(size) failed");
        }

        std::vector<unsigned char> result(size);
        status = BCryptDecrypt(
            key_, const_cast<PUCHAR>(ciphertext.data()),
            static_cast<ULONG>(ciphertext.size()), nullptr, nullptr, 0,
            result.data(), static_cast<ULONG>(result.size()), &size,
            BCRYPT_BLOCK_PADDING);
        
        if (status < 0) 
        {
            fail("BCryptDecrypt failed");
        }

        return std::string(reinterpret_cast<const char*>(result.data()), size);
    }

private:

    BCRYPT_ALG_HANDLE algorithm_ = nullptr;
    BCRYPT_KEY_HANDLE key_ = nullptr;
    std::vector<unsigned char> key_object_;

};