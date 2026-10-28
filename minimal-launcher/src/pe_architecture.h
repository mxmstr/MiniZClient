#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <string_view>

enum class PeArchitecture
{
    i386,
    amd64,
};

// Inspect a PE image without executing or mapping it. The span overload is
// exposed so callers can validate an image they have already read and so the
// parser can be tested without touching the filesystem.
[[nodiscard]] PeArchitecture inspect_pe_architecture(
    std::span<const std::uint8_t> image,
    std::string_view description = "PE image");

[[nodiscard]] PeArchitecture inspect_pe_architecture(
    const std::filesystem::path& path);

[[nodiscard]] const char* pe_architecture_name(
    PeArchitecture architecture) noexcept;
