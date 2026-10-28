#include "pe_architecture.h"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::size_t kPeOffset = 0x80;
constexpr std::size_t kOptionalOffset = kPeOffset + 24;

void require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

void put_u16(std::vector<std::uint8_t>& image, std::size_t offset,
             std::uint16_t value)
{
    image[offset] = static_cast<std::uint8_t>(value);
    image[offset + 1] = static_cast<std::uint8_t>(value >> 8);
}

void put_u32(std::vector<std::uint8_t>& image, std::size_t offset,
             std::uint32_t value)
{
    image[offset] = static_cast<std::uint8_t>(value);
    image[offset + 1] = static_cast<std::uint8_t>(value >> 8);
    image[offset + 2] = static_cast<std::uint8_t>(value >> 16);
    image[offset + 3] = static_cast<std::uint8_t>(value >> 24);
}

std::vector<std::uint8_t> make_pe(std::uint16_t machine,
                                  std::uint16_t optional_magic,
                                  std::uint16_t optional_size)
{
    std::vector<std::uint8_t> image(kOptionalOffset + optional_size, 0);
    put_u16(image, 0, 0x5A4D);
    put_u32(image, 0x3C, static_cast<std::uint32_t>(kPeOffset));
    put_u32(image, kPeOffset, 0x00004550);
    put_u16(image, kPeOffset + 4, machine);
    put_u16(image, kPeOffset + 20, optional_size);
    if (optional_size >= 2) put_u16(image, kOptionalOffset, optional_magic);
    return image;
}

template <typename Action>
void require_rejected(Action&& action, std::string_view expected,
                      const char* message)
{
    try
    {
        action();
    }
    catch (const std::exception& error)
    {
        require(std::string_view(error.what()).find(expected) !=
                    std::string_view::npos,
                message);
        return;
    }
    throw std::runtime_error(message);
}

class TemporaryFile
{
public:
    TemporaryFile()
    {
        const auto suffix = std::chrono::steady_clock::now()
                                .time_since_epoch().count();
        path_ = std::filesystem::temp_directory_path() /
                ("zclient-pe-architecture-" + std::to_string(suffix) + ".exe");
    }

    ~TemporaryFile()
    {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
    }

    const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

} // namespace

int main()
{
    try
    {
        const auto i386 = make_pe(0x014C, 0x010B, 224);
        require(inspect_pe_architecture(i386, "synthetic I386") ==
                    PeArchitecture::i386,
                "I386 image was not recognized");
        require(std::string_view(pe_architecture_name(PeArchitecture::i386)) ==
                    "I386",
                "I386 name is incorrect");

        const auto amd64 = make_pe(0x8664, 0x020B, 240);
        require(inspect_pe_architecture(amd64, "synthetic AMD64") ==
                    PeArchitecture::amd64,
                "AMD64 image was not recognized");
        require(std::string_view(pe_architecture_name(PeArchitecture::amd64)) ==
                    "AMD64",
                "AMD64 name is incorrect");

        require_rejected(
            [] { (void)inspect_pe_architecture(
                     std::vector<std::uint8_t>(8), "truncated"); },
            "DOS header is truncated", "truncated DOS header was accepted");

        auto bad_dos = i386;
        bad_dos[0] = 0;
        require_rejected(
            [&] { (void)inspect_pe_architecture(bad_dos, "bad DOS"); },
            "DOS signature is missing", "bad DOS signature was accepted");

        auto outside_pe = i386;
        put_u32(outside_pe, 0x3C, 0xFFFFFFFFu);
        require_rejected(
            [&] { (void)inspect_pe_architecture(outside_pe, "outside PE"); },
            "PE header is outside", "out-of-range PE header was accepted");

        auto bad_pe = i386;
        bad_pe[kPeOffset] = 0;
        require_rejected(
            [&] { (void)inspect_pe_architecture(bad_pe, "bad PE"); },
            "PE signature is missing", "bad PE signature was accepted");

        const auto unsupported = make_pe(0xAA64, 0x020B, 240);
        require_rejected(
            [&] { (void)inspect_pe_architecture(unsupported, "ARM64"); },
            "0xAA64", "unsupported machine type was accepted");

        const auto wrong_i386_magic = make_pe(0x014C, 0x020B, 224);
        require_rejected(
            [&] { (void)inspect_pe_architecture(wrong_i386_magic,
                                                "wrong I386 magic"); },
            "expected 0x010B", "I386 PE32+ header was accepted");

        const auto wrong_amd64_magic = make_pe(0x8664, 0x010B, 240);
        require_rejected(
            [&] { (void)inspect_pe_architecture(wrong_amd64_magic,
                                                "wrong AMD64 magic"); },
            "expected 0x020B", "AMD64 PE32 header was accepted");

        const auto short_i386_header = make_pe(0x014C, 0x010B, 223);
        require_rejected(
            [&] { (void)inspect_pe_architecture(short_i386_header,
                                                "short I386 header"); },
            "smaller than", "undersized optional header was accepted");

        auto truncated_optional = amd64;
        truncated_optional.pop_back();
        require_rejected(
            [&] { (void)inspect_pe_architecture(truncated_optional,
                                                "truncated optional header"); },
            "optional header is truncated",
            "truncated optional header was accepted");

        TemporaryFile temporary;
        {
            std::ofstream output(temporary.path(), std::ios::binary);
            output.write(reinterpret_cast<const char*>(i386.data()),
                         static_cast<std::streamsize>(i386.size()));
            require(static_cast<bool>(output),
                    "could not write temporary PE test image");
        }
        require(inspect_pe_architecture(temporary.path()) ==
                    PeArchitecture::i386,
                "filesystem PE inspection failed");

        require_rejected(
            [] { (void)inspect_pe_architecture(
                     std::filesystem::path("missing-pe-architecture-test.exe")); },
            "Could not open PE image", "missing PE image was accepted");

        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "pe_architecture_test: " << error.what() << '\n';
        return 1;
    }
}
