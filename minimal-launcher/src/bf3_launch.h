#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

enum class Bf3LaunchMode
{
    none,
    singleplayer,
    multiplayer,
};

struct Bf3LaunchRequest
{
    Bf3LaunchMode mode = Bf3LaunchMode::none;
    std::wstring server_id;
};

Bf3LaunchMode parse_bf3_launch_mode(std::wstring_view value);
Bf3LaunchRequest parse_bf3_launch_url(std::wstring_view value);
void validate_bf3_launch(const Bf3LaunchRequest& request);
std::vector<std::wstring> make_bf3_launch_arguments(
    const Bf3LaunchRequest& request, std::uint64_t persona_id);

