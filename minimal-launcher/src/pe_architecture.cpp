#include "pe_architecture.h"

#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr std::uint16_t kDosSignature = 0x5A4D;
constexpr std::uint32_t kNtSignature = 0x00004550;
constexpr std::uint16_t kMachineI386 = 0x014C;
constexpr std::uint16_t kMachineAmd64 = 0x8664;
constexpr std::uint16_t kOptionalMagicPe32 = 0x010B;
constexpr std::uint16_t kOptionalMagicPe32Plus = 0x020B;

constexpr std::size_t kDosPeOffset = 0x3C;
constexpr std::size_t kMinimumDosHeaderSize = 0x40;
constexpr std::size_t kCoffHeaderSize = 20;
constexpr std::size_t kNtPrefixSize = 4 + kCoffHeaderSize;
constexpr std::size_t kPe32OptionalHeaderSize = 224;
constexpr std::size_t kPe32PlusOptionalHeaderSize = 240;

[[noreturn]] void invalid_pe(std::string_view description,
                             std::string_view reason)
{
    throw std::runtime_error(std::string(description) +
                             " is not a valid supported PE image: " +
                             std::string(reason));
}

std::uint16_t read_u16(std::span<const std::uint8_t> image,
                       std::size_t offset,
                       std::string_view description,
                       std::string_view field)
{
    if (offset > image.size() || sizeof(std::uint16_t) > image.size() - offset)
    {
        invalid_pe(description, std::string(field) + " is truncated");
    }

    return static_cast<std::uint16_t>(image[offset]) |
           static_cast<std::uint16_t>(image[offset + 1]) << 8;
}

std::uint32_t read_u32(std::span<const std::uint8_t> image,
                       std::size_t offset,
                       std::string_view description,
                       std::string_view field)
{
    if (offset > image.size() || sizeof(std::uint32_t) > image.size() - offset)
    {
        invalid_pe(description, std::string(field) + " is truncated");
    }

    return static_cast<std::uint32_t>(image[offset]) |
           static_cast<std::uint32_t>(image[offset + 1]) << 8 |
           static_cast<std::uint32_t>(image[offset + 2]) << 16 |
           static_cast<std::uint32_t>(image[offset + 3]) << 24;
}

std::string hexadecimal(std::uint16_t value)
{
    std::ostringstream text;
    text << "0x" << std::uppercase << std::hex << std::setw(4)
         << std::setfill('0') << value;
    return text.str();
}

void validate_optional_header(std::span<const std::uint8_t> image,
                              std::size_t optional_offset,
                              std::uint16_t declared_size,
                              std::uint16_t expected_magic,
                              std::size_t minimum_size,
                              std::string_view architecture,
                              std::string_view description)
{
    if (declared_size < minimum_size)
    {
        invalid_pe(description,
                   std::string(architecture) +
                       " optional header is smaller than the PE specification requires");
    }

    if (optional_offset > image.size() ||
        declared_size > image.size() - optional_offset)
    {
        invalid_pe(description, "optional header is truncated");
    }

    const std::uint16_t magic = read_u16(
        image, optional_offset, description, "optional-header magic");
    if (magic != expected_magic)
    {
        invalid_pe(description,
                   std::string(architecture) + " machine type has optional-header magic " +
                       hexadecimal(magic) + ", expected " +
                       hexadecimal(expected_magic));
    }
}

} // namespace

PeArchitecture inspect_pe_architecture(
    std::span<const std::uint8_t> image,
    std::string_view description)
{
    if (description.empty()) description = "PE image";
    if (image.size() < kMinimumDosHeaderSize)
    {
        invalid_pe(description, "DOS header is truncated");
    }
    if (read_u16(image, 0, description, "DOS signature") != kDosSignature)
    {
        invalid_pe(description, "DOS signature is missing");
    }

    const std::uint32_t pe_offset_u32 = read_u32(
        image, kDosPeOffset, description, "PE-header offset");
    const std::size_t pe_offset = static_cast<std::size_t>(pe_offset_u32);
    if (pe_offset < kMinimumDosHeaderSize ||
        pe_offset > image.size() ||
        kNtPrefixSize > image.size() - pe_offset)
    {
        invalid_pe(description, "PE header is outside the file");
    }
    if (read_u32(image, pe_offset, description, "PE signature") != kNtSignature)
    {
        invalid_pe(description, "PE signature is missing");
    }

    const std::size_t coff_offset = pe_offset + 4;
    const std::uint16_t machine = read_u16(
        image, coff_offset, description, "COFF machine type");
    const std::uint16_t optional_size = read_u16(
        image, coff_offset + 16, description, "optional-header size");
    const std::size_t optional_offset = pe_offset + kNtPrefixSize;

    switch (machine)
    {
    case kMachineI386:
        validate_optional_header(image, optional_offset, optional_size,
                                 kOptionalMagicPe32,
                                 kPe32OptionalHeaderSize,
                                 "I386", description);
        return PeArchitecture::i386;

    case kMachineAmd64:
        validate_optional_header(image, optional_offset, optional_size,
                                 kOptionalMagicPe32Plus,
                                 kPe32PlusOptionalHeaderSize,
                                 "AMD64", description);
        return PeArchitecture::amd64;

    default:
        invalid_pe(description,
                   "unsupported COFF machine type " + hexadecimal(machine));
    }
}

PeArchitecture inspect_pe_architecture(const std::filesystem::path& path)
{
    const std::string description = path.string();
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream)
    {
        throw std::runtime_error("Could not open PE image: " + description);
    }

    const std::streamoff end = stream.tellg();
    if (end < 0 || static_cast<std::uintmax_t>(end) >
                       std::numeric_limits<std::size_t>::max())
    {
        throw std::runtime_error("Could not determine PE image size: " +
                                 description);
    }

    std::vector<std::uint8_t> image(static_cast<std::size_t>(end));
    stream.seekg(0);
    if (!image.empty() &&
        !stream.read(reinterpret_cast<char*>(image.data()),
                     static_cast<std::streamsize>(image.size())))
    {
        throw std::runtime_error("Could not read PE image: " + description);
    }

    return inspect_pe_architecture(image, description);
}

const char* pe_architecture_name(PeArchitecture architecture) noexcept
{
    switch (architecture)
    {
    case PeArchitecture::i386:
        return "I386";
    case PeArchitecture::amd64:
        return "AMD64";
    }
    return "unknown";
}
