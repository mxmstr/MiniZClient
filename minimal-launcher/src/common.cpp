#include <windows.h>

#include <string>
#include <string_view>

#include "common.h"

[[noreturn]] void fail(const std::string& message, DWORD error) 
{
    throw std::runtime_error(message + " (Win32 " + std::to_string(error) + ")");
}

[[noreturn]] void fail(const std::wstring& message, DWORD error) 
{
    throw std::runtime_error(std::string(message.begin(), message.end()) + " (Win32 " + std::to_string(error) + ")");
}

std::string encode_utf8(std::wstring_view value) 
{
    const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                                            static_cast<int>(value.size()), nullptr, 0,
                                            nullptr, nullptr);

    if (length <= 0) throw std::runtime_error("EA ID is not valid Unicode.");

    std::string result(static_cast<std::size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                        static_cast<int>(value.size()), result.data(), length,
                        nullptr, nullptr);
    
    return result;
}

std::wstring decode_utf8(std::string_view text) 
{
    if (text.empty()) return {};

    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                            static_cast<int>(text.size()), nullptr, 0);

    if (length <= 0) throw std::runtime_error("ZData_Settings.zlo is not valid UTF-8.");

    std::wstring result(length, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                        static_cast<int>(text.size()), result.data(), length);

    return result;
}
