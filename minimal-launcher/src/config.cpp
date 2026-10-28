#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <ws2tcpip.h>

#include <fstream>
#include <iostream>
#include <stdexcept>

#include "common.h"
#include "config.h"

namespace fs = std::filesystem;

namespace {

std::string routed_lan_ipv4() 
{
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) 
    {
        fail(L"Could not initialize Winsock to select the service host.");
    }
    
    SOCKET socket_handle = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_handle == INVALID_SOCKET) 
    {
        WSACleanup();
        fail(L"Could not create route-selection socket.");
    }
    
    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    destination.sin_port = htons(9);
    InetPtonA(AF_INET, "192.0.2.1", &destination.sin_addr);
    
    sockaddr_in local{};
    int local_size = sizeof(local);
    
    char text[INET_ADDRSTRLEN]{};
    const bool ok = connect(socket_handle, reinterpret_cast<sockaddr*>(&destination), sizeof(destination)) == 0 && 
                    getsockname(socket_handle, reinterpret_cast<sockaddr*>(&local), &local_size) == 0;
    if (ok) 
    {
        InetNtopA(AF_INET, &local.sin_addr, text, sizeof(text));
    }

    closesocket(socket_handle);
    WSACleanup();

    if (!ok || !text[0] || std::string_view(text).rfind("127.", 0) == 0) 
    {
        fail(L"Could not select a non-loopback IPv4 address; pass --service-host <IPv4>.");
    }

    return text;
}

std::wstring read_eaid(const fs::path& settings_path) 
{
    std::ifstream input(settings_path, std::ios::binary);
    if (!input) 
    {
        return {};
    }

    const std::string contents((std::istreambuf_iterator<char>(input)),
                               std::istreambuf_iterator<char>());
    constexpr std::string_view marker = "login=\"";
    std::size_t begin = 0;
    for (;;) 
    {
        begin = contents.find(marker, begin);
        if (begin == std::string::npos) 
        {
            return {};
        }

        // Match the XML attribute named "login", not the suffix of an
        // attribute such as autologin="false".
        if (begin == 0 || contents[begin - 1] == ' ' || contents[begin - 1] == '\t' ||
            contents[begin - 1] == '\r' || contents[begin - 1] == '\n' ||
            contents[begin - 1] == '<') 
        {
            break;
        }
        begin += marker.size();
    }

    const std::size_t value_begin = begin + marker.size();
    const std::size_t end = contents.find('"', value_begin);
    if (end == std::string::npos || end == value_begin) 
    {
        return {};
    }
    
    return decode_utf8(std::string_view(contents).substr(value_begin, end - value_begin));
}

std::wstring locate_eaid(const fs::path& launcher_asset_path) 
{
    fs::path directory = fs::absolute(launcher_asset_path).parent_path();
    
    for (int depth = 0; depth != 4 && !directory.empty(); ++depth) 
    {
        const std::wstring eaid = read_eaid(directory / L"ZData_Settings.zlo");
        if (!eaid.empty()) {
            return eaid;
        }
        
        const fs::path parent = directory.parent_path();
        if (parent == directory) {
            break;
        }
        
        directory = parent;
    }

    fail(L"EA ID was not specified and ZData_Settings.zlo could not be found; pass --eaid <name>.");
}

fs::path executable_asset(const wchar_t* name) 
{
    std::vector<wchar_t> path(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    
    if (!length || length >= path.size()) 
    {
        fail(L"GetModuleFileNameW(launcher) failed");
    }
    
    return fs::path(std::wstring(path.data(), length)).parent_path() / name;
}


std::uint32_t parse_u32(std::wstring_view value, std::string_view name) 
{
    std::size_t consumed = 0;
    const unsigned long parsed = std::stoul(std::wstring(value), &consumed, 0);
    
    if (consumed != value.size() || parsed == 0 || parsed > UINT32_MAX) 
    {
        fail(std::string(name) + " must be a nonzero uint32 value.");
    }
    
    return static_cast<std::uint32_t>(parsed);
}

std::string trim(std::string value) 
{
    const std::size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    
    const std::size_t last = value.find_last_not_of(" \t\r\n");
    value = value.substr(first, last - first + 1);
    
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') 
    {
        value = value.substr(1, value.size() - 2);
    }
    
    return value;
}

void apply_config_value(Options& options, std::string key, const std::string& raw_value,
                        const fs::path& directory) 
{
    std::transform(key.begin(), key.end(), key.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    
    const std::wstring value = decode_utf8(trim(raw_value));
    const auto path_value = [&] {
        fs::path path(value);
        return path.is_absolute() ? path : directory / path;
    };
    const auto narrow_value = [&] { return encode_utf8(value); };

    if (key == "game")                          options.game = path_value();
    else if (key == "bootstrap")                options.bootstrap = path_value();
    else if (key == "bootstrap-x86")            options.bootstrap_x86 = path_value();
    else if (key == "injector-x86")             options.injector_x86 = path_value();
    else if (key == "lsx-shim")                 options.lsx_shim = path_value();
    else if (key == "trace-game-dll")           options.trace_game_dll = path_value();
    else if (key == "license-response")          options.license_response = path_value();
    else if (key == "license-signature")         options.license_signature = narrow_value();
    else if (key == "data-path")                options.data_path = path_value();
    else if (key == "frosty-pack")              options.frosty_pack = value;
    else if (key == "game-arg")                 options.game_arguments.push_back(value);
    else if (key == "bf3-mode")
    {
        options.bf3_launch.mode = parse_bf3_launch_mode(value);
        if (options.bf3_launch.mode != Bf3LaunchMode::multiplayer)
            options.bf3_launch.server_id.clear();
    }
    else if (key == "bf3-server-id")            options.bf3_launch.server_id = value;
    else if (key == "bf3-launch-url")           options.bf3_launch = parse_bf3_launch_url(value);
    else if (key == "eaid")                     options.eaid = value;
    else if (key == "account-id") 
    {
        std::size_t consumed = 0;
        const unsigned long long parsed = std::stoull(value, &consumed, 0);
        if (consumed != value.size() || parsed == 0) 
        {
            fail(L"account-id must be a nonzero uint64 value.");
        }
        options.account_id = static_cast<std::uint64_t>(parsed);
    }
    else if (key == "content-id")               options.content_id = value;
    else if (key == "game-title")               options.game_title = value;
    else if (key == "game-id")                  options.game_id = parse_u32(value, "game-id");
    else if (key == "game-executable")          options.game_executable = narrow_value();
    else if (key == "module-id")                options.module_id = parse_u32(value, "module-id");
    else if (key == "game-module-id")           options.game_module_id = parse_u32(value, "game-module-id");
    else if (key == "activation-executable")    options.activation_executable = narrow_value();
    else if (key == "activation-module-id")     options.activation_module_id = parse_u32(value, "activation-module-id");
    else if (key == "client-token")             options.client_token = parse_u32(value, "client-token");
    else if (key == "zbackend")                 options.zbackend_endpoint = value;
    else if (key == "zbackend-digest")          options.zbackend_digest = narrow_value();
    else if (key == "service-host")             options.service_host = narrow_value();
    else if (key == "lsx-host")                 options.lsx_host = narrow_value();
    else if (key == "lsx-log") 
    {
        if (value == L"true" || value == L"1") options.lsx_log = true;
        else if (value == L"false" || value == L"0") options.lsx_log = false;
        else fail(L"lsx-log must be true or false.");
    }
    else if (key == "breakaway") options.breakaway = (value == L"true" || value == L"1");
    else fail("Unknown config key: " + key);
}

void load_config(Options& options, const fs::path& path) 
{
    std::ifstream input(path, std::ios::binary);
    if (!input) 
    {
        fail("Could not open config file: " + path.string());
    }

    std::string line;
    std::size_t number = 0;
    while (std::getline(input, line)) 
    {
        ++number;
        const std::string cleaned = trim(line);
        
        if (cleaned.empty() || cleaned.front() == '#' || cleaned.front() == ';') 
        {
            continue;
        }
        
        const std::size_t equals = cleaned.find('=');
        if (equals == std::string::npos) 
        {
            fail("Invalid config line " + std::to_string(number) + " (expected key=value).");
        }

        apply_config_value(options, trim(cleaned.substr(0, equals)),
                           cleaned.substr(equals + 1), fs::absolute(path).parent_path());
    }
}

} // namespace


Options parse_options(int argc, wchar_t** argv) 
{
    Options options;

    enum class Argument {
        unknown,
        config, game, bootstrap, bootstrap_x86, injector_x86, lsx_shim, trace_game_dll,
        license_response, license_signature,
        data_path, frosty_pack, game_arg, bf3_mode, bf3_server_id,
        bf3_launch_url, eaid, content_id, game_title,
        game_id, game_executable, module_id, game_module_id,
        activation_executable, activation_module_id, account_id, client_token,
        zbackend, zbackend_digest, service_host, lsx_host, lsx_log, no_lsx_log,
        breakaway, manual_map, separator, help
    };

    const auto classify_argument = [](std::wstring_view value) {
        struct Entry {
            std::wstring_view name;
            Argument argument;
        };
        static constexpr Entry entries[] = {
            {L"--config", Argument::config},
            {L"--game", Argument::game},
            {L"--bootstrap", Argument::bootstrap},
            {L"--bootstrap-x86", Argument::bootstrap_x86},
            {L"--injector-x86", Argument::injector_x86},
            {L"--lsx-shim", Argument::lsx_shim},
            {L"--trace-game-dll", Argument::trace_game_dll},
            {L"--license-response", Argument::license_response},
            {L"--license-signature", Argument::license_signature},
            {L"--data-path", Argument::data_path},
            {L"-dataPath", Argument::data_path},
            {L"--frosty-pack", Argument::frosty_pack},
            {L"--game-arg", Argument::game_arg},
            {L"--bf3-mode", Argument::bf3_mode},
            {L"--bf3-server-id", Argument::bf3_server_id},
            {L"--bf3-launch-url", Argument::bf3_launch_url},
            {L"--eaid", Argument::eaid},
            {L"--content-id", Argument::content_id},
            {L"--game-title", Argument::game_title},
            {L"--game-id", Argument::game_id},
            {L"--game-executable", Argument::game_executable},
            {L"--module-id", Argument::module_id},
            {L"--game-module-id", Argument::game_module_id},
            {L"--activation-executable", Argument::activation_executable},
            {L"--activation-module-id", Argument::activation_module_id},
            {L"--account-id", Argument::account_id},
            {L"--client-token", Argument::client_token},
            {L"--zbackend", Argument::zbackend},
            {L"--zbackend-digest", Argument::zbackend_digest},
            {L"--service-host", Argument::service_host},
            {L"--lsx-host", Argument::lsx_host},
            {L"--lsx-log", Argument::lsx_log},
            {L"--no-lsx-log", Argument::no_lsx_log},
            {L"--breakaway", Argument::breakaway},
            {L"--manual-map", Argument::manual_map},
            {L"--", Argument::separator},
            {L"--help", Argument::help},
            {L"-h", Argument::help},
        };

        for (const Entry& entry : entries) {
            if (value == entry.name) return entry.argument;
        }
        return Argument::unknown;
    };
    
    for (int i = 1; i < argc; ++i) 
    {
        if (std::wstring_view(argv[i]) == L"--") 
        {
            break;
        }
        
        if (std::wstring_view(argv[i]) == L"--config") 
        {
            if (i + 1 >= argc) fail(L"--config requires a file path.");
            options.config = fs::absolute(argv[++i]);
        }
    }
    
    if (options.config.empty()) 
    {
        const fs::path default_config = executable_asset(L"MiniZClient.conf");
        if (fs::is_regular_file(default_config)) 
        {
            options.config = default_config;
        }
    }
    
    if (!options.config.empty()) 
    {
        load_config(options, options.config);
    }
    
    for (int i = 1; i < argc; ++i) 
    {
        const std::wstring_view argument(argv[i]);
        switch (classify_argument(argument)) 
        {
            case Argument::config:
                if (i + 1 >= argc) break;
                ++i;
                continue;
            case Argument::game:
                if (i + 1 >= argc) break;
                options.game = argv[++i];
                continue;
            case Argument::bootstrap:
                if (i + 1 >= argc) break;
                options.bootstrap = argv[++i];
                continue;
            case Argument::bootstrap_x86:
                if (i + 1 >= argc) break;
                options.bootstrap_x86 = argv[++i];
                continue;
            case Argument::injector_x86:
                if (i + 1 >= argc) break;
                options.injector_x86 = fs::absolute(argv[++i]);
                continue;
            case Argument::lsx_shim:
                if (i + 1 >= argc) break;
                options.lsx_shim = fs::absolute(argv[++i]);
                continue;
            case Argument::trace_game_dll:
                if (i + 1 >= argc) break;
                options.trace_game_dll = fs::absolute(argv[++i]);
                continue;
            case Argument::license_response:
                if (i + 1 >= argc) break;
                options.license_response = fs::absolute(argv[++i]);
                continue;
            case Argument::license_signature: {
                if (i + 1 >= argc) break;
                const std::wstring value(argv[++i]);
                options.license_signature.assign(value.begin(), value.end());
                continue;
            }
            case Argument::data_path:
                if (i + 1 >= argc) break;
                options.data_path = argv[++i];
                continue;
            case Argument::frosty_pack:
                if (i + 1 >= argc) break;
                options.frosty_pack = argv[++i];
                continue;
            case Argument::game_arg:
                if (i + 1 >= argc) break;
                options.game_arguments.emplace_back(argv[++i]);
                continue;
            case Argument::bf3_mode:
                if (i + 1 >= argc) break;
                options.bf3_launch.mode = parse_bf3_launch_mode(argv[++i]);
                if (options.bf3_launch.mode != Bf3LaunchMode::multiplayer)
                    options.bf3_launch.server_id.clear();
                continue;
            case Argument::bf3_server_id:
                if (i + 1 >= argc) break;
                options.bf3_launch.server_id = argv[++i];
                continue;
            case Argument::bf3_launch_url:
                if (i + 1 >= argc) break;
                options.bf3_launch = parse_bf3_launch_url(argv[++i]);
                continue;
            case Argument::eaid:
                if (i + 1 >= argc) break;
                options.eaid = argv[++i];
                continue;
            case Argument::content_id:
                if (i + 1 >= argc) break;
                options.content_id = argv[++i];
                if (options.content_id.empty()) {
                    fail(L"--content-id must not be empty.");
                }
                continue;
            case Argument::game_title:
                if (i + 1 >= argc) break;
                options.game_title = argv[++i];
                continue;
            case Argument::game_id:
                if (i + 1 >= argc) break;
                options.game_id = parse_u32(argv[++i], "--game-id");
                continue;
            case Argument::game_executable:
                if (i + 1 >= argc) break;
                options.game_executable = encode_utf8(argv[++i]);
                continue;
            case Argument::module_id:
                if (i + 1 >= argc) break;
                options.module_id = parse_u32(argv[++i], "--module-id");
                continue;
            case Argument::game_module_id:
                if (i + 1 >= argc) break;
                options.game_module_id = parse_u32(argv[++i], "--game-module-id");
                continue;
            case Argument::activation_executable:
                if (i + 1 >= argc) break;
                options.activation_executable = encode_utf8(argv[++i]);
                continue;
            case Argument::activation_module_id:
                if (i + 1 >= argc) break;
                options.activation_module_id = parse_u32(argv[++i], "--activation-module-id");
                continue;
            case Argument::account_id: {
                if (i + 1 >= argc) break;
                const std::wstring value(argv[++i]);
                std::size_t consumed = 0;
                const unsigned long long parsed = std::stoull(value, &consumed, 0);
                if (consumed != value.size() || parsed == 0) {
                    fail(L"--account-id must be a nonzero uint64 value.");
                }
                options.account_id = static_cast<std::uint64_t>(parsed);
                continue;
            }
            case Argument::client_token:
                if (i + 1 >= argc) break;
                options.client_token = parse_u32(argv[++i], "--client-token");
                continue;
            case Argument::zbackend:
                options.zbackend_endpoint = L"127.0.0.1:48385";
                if (i + 1 < argc && std::wstring_view(argv[i + 1]).rfind(L"--", 0) != 0) {
                    options.zbackend_endpoint = argv[++i];
                }
                continue;
            case Argument::zbackend_digest: {
                if (i + 1 >= argc) break;
                const std::wstring value(argv[++i]);
                options.zbackend_digest.assign(value.begin(), value.end());
                continue;
            }
            case Argument::service_host: {
                if (i + 1 >= argc) break;
                const std::wstring value(argv[++i]);
                options.service_host.assign(value.begin(), value.end());
                continue;
            }
            case Argument::lsx_host: {
                if (i + 1 >= argc) break;
                const std::wstring value(argv[++i]);
                options.lsx_host.assign(value.begin(), value.end());
                continue;
            }
            case Argument::lsx_log:
                options.lsx_log = true;
                continue;
            case Argument::no_lsx_log:
                options.lsx_log = false;
                continue;
            case Argument::breakaway:
                options.breakaway = true;
                continue;
            case Argument::manual_map:
                // Retained for compatibility with earlier launch commands. Direct
                // mapping is now the only bootstrap path.
                continue;
            case Argument::separator:
                while (++i < argc) {
                    options.game_arguments.emplace_back(argv[i]);
                }
                break;
            case Argument::help:
                std::wcout << L"Usage: zclient_minimal_launcher [--config file] [--game game.exe] "
                            L"[--bootstrap loader.dll] "
                            L"[--bootstrap-x86 CLoaderx32.dll] "
                            L"[--injector-x86 zclient_injector32.exe] "
                            L"[--lsx-shim ZClient.LsxShim64.dll] "
                            L"[--trace-game-dll ZClient.GameTrace64.dll] "
                            L"[--license-response response.bin --license-signature base64] "
                            L"[--frosty-pack name | --data-path directory] "
                            L"[--game-arg value] [-- game arguments...] "
                            L"[--bf3-mode sp|mp [--bf3-server-id id] | "
                            L"--bf3-launch-url url] "
                            L"[--eaid name] [--account-id id] [--content-id id] "
                            L"[--game-title title] [--game-id id] [--game-executable name] "
                            L"[--module-id id] [--game-module-id id] "
                            L"[--activation-executable name --activation-module-id id] "
                            L"[--client-token id] "
                            L"[--zbackend [host:port] --zbackend-digest 32hex] "
                            L"[--service-host Blaze-IPv4] [--lsx-host local-IPv4] "
                            L"[--lsx-log | --no-lsx-log] "
                            L"[--breakaway]\n";
                ExitProcess(0);
            case Argument::unknown:
                break;
        }

        if (classify_argument(argument) != Argument::separator) 
        {
            fail(L"Unknown or incomplete command-line option.");
        }

        break;
    }

    std::vector<std::string> missing;
    if (options.game.empty()) missing.emplace_back("game");
    if (options.content_id.empty()) missing.emplace_back("content-id");
    if (options.game_title.empty()) missing.emplace_back("game-title");
    if (!options.game_id) missing.emplace_back("game-id");
    if (options.game_executable.empty()) missing.emplace_back("game-executable");
    if (!options.module_id) missing.emplace_back("module-id");
    if (!options.game_module_id) missing.emplace_back("game-module-id");
    if (!options.client_token) missing.emplace_back("client-token");
    if (options.activation_executable.empty() != (options.activation_module_id == 0)) 
    {
        fail(L"activation-executable and activation-module-id must be supplied together.");
    }
    if (options.license_response.empty() != options.license_signature.empty())
    {
        fail(L"license-response and license-signature must be supplied together.");
    }
    validate_bf3_launch(options.bf3_launch);

    if (!missing.empty()) 
    {
        std::string message = "Missing required game settings:";
        for (const auto& name : missing) message += " " + name;
        message += ". Supply them on the command line or with --config <file>.";
        fail(message);
    }

    options.game = fs::absolute(options.game);
    std::transform(options.game_executable.begin(), options.game_executable.end(),
                   options.game_executable.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    std::transform(options.activation_executable.begin(), options.activation_executable.end(),
                   options.activation_executable.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });

    if (!options.data_path.empty() && !options.frosty_pack.empty()) 
    {
        fail("Use either --frosty-pack or --data-path, not both.");
    }
    if (!options.frosty_pack.empty()) 
    {
        const fs::path pack_name(options.frosty_pack);
        if (pack_name.has_parent_path() || pack_name == L"." || pack_name == L"..") 
        {
            fail("--frosty-pack must be a pack name, not a path.");
        }
        options.data_path = options.game.parent_path() / L"ModData" / pack_name;
    }
    if (!options.data_path.empty()) 
    {
        options.data_path = fs::absolute(options.data_path).lexically_normal();
        if (!fs::is_directory(options.data_path)) 
        {
            fail("Frosty data path does not exist or is not a directory: " + options.data_path.string());
        }
        const fs::path manifest = options.data_path / L"Update" / L"Patch" /
                                  L"Data" / L"mods.json";
        const fs::path legacy_manifest = manifest.parent_path() / L"mods.txt";
        if (!fs::is_regular_file(manifest) && !fs::is_regular_file(legacy_manifest)) 
        {
            fail(
                "The selected directory is not a generated Frosty pack "
                "(Update\\Patch\\Data\\mods.json is missing): " +
                options.data_path.string());
        }
    }
    if (options.bootstrap.empty()) 
    {
        options.bootstrap = executable_asset(L"CLoaderx64.dll");
    }
    if (options.bootstrap_x86.empty()) 
    {
        options.bootstrap_x86 = executable_asset(L"CLoaderx32.dll");
    }
    if (options.injector_x86.empty())
    {
        options.injector_x86 = executable_asset(L"zclient_injector32.exe");
    }
    if (options.lsx_shim.empty()) 
    {
        options.lsx_shim = executable_asset(L"ZClient.LsxShim64.dll");
    }
    if (options.eaid.empty()) 
    {
        options.eaid = locate_eaid(options.bootstrap);
    }

    const std::string local_host = routed_lan_ipv4();
    if (options.service_host.empty()) options.service_host = local_host;
    if (options.lsx_host.empty()) options.lsx_host = local_host;
    options.local_game_network = options.service_host == local_host;
    
    const auto validate_host = [](std::string_view option, const std::string& host) 
    {
        in_addr address{};
        if (InetPtonA(AF_INET, host.c_str(), &address) != 1 ||
            (ntohl(address.S_un.S_addr) >> 24) == 127) {
            fail(std::string(option) + " must be a non-loopback IPv4 address.");
        }
    };
    validate_host("--service-host", options.service_host);
    validate_host("--lsx-host", options.lsx_host);

    if (!options.zbackend_endpoint.empty() && options.zbackend_digest.empty()) 
    {
        wchar_t digest[64]{};
        const DWORD length = GetEnvironmentVariableW(L"ZBACKEND_DIGEST", digest,
                                                       static_cast<DWORD>(std::size(digest)));
        if (length && length < std::size(digest)) 
        {
            options.zbackend_digest.assign(digest, digest + length);
        } 
        else 
        {
            fail("--zbackend requires --zbackend-digest <32hex> or ZBACKEND_DIGEST.");
        }
    }
    
    if (!options.zbackend_endpoint.empty() && options.account_id != 0) 
    {
        fail("--account-id cannot be combined with --zbackend; the backend supplies the account ID.");
    }
    
    return options;
}
