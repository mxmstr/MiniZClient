#pragma once

#include <filesystem>
#include <cstdint>
#include <string>
#include <vector>

#include "bf3_launch.h"

namespace fs = std::filesystem;

struct Options 
{
    fs::path config;
    fs::path game;
    fs::path bootstrap;
    fs::path bootstrap_x86;
    fs::path injector_x86;
    fs::path lsx_shim;
    fs::path trace_game_dll;
    fs::path license_response;
    std::string license_signature;
    fs::path data_path;
    std::wstring frosty_pack;
    std::vector<std::wstring> game_arguments;
    Bf3LaunchRequest bf3_launch;
    std::wstring eaid;
    std::wstring content_id;
    std::wstring game_title;
    std::uint32_t game_id = 0;
    std::string game_executable;
    std::uint32_t module_id = 0;
    std::uint32_t game_module_id = 0;
    std::string activation_executable;
    std::uint32_t activation_module_id = 0;
    std::uint64_t account_id = 0;
    // ZClient's games-manager constructor stores this value at +0xB0 and
    // its opcode-2 handler returns it verbatim (in network byte order).
    std::uint32_t client_token = 0;
    std::wstring zbackend_endpoint;
    std::string zbackend_digest;
    std::string service_host;
    std::string lsx_host;
    bool local_game_network = false;
    bool lsx_log = true;
    bool breakaway = false;
};

Options parse_options(int argc, wchar_t** argv);
