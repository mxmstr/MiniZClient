#pragma once

#include <windows.h>

#include "common.h"

#include <filesystem>
#include <cstdint>
#include <string>
#include <vector>

struct ManualMapResult {
    std::uintptr_t zlo_context;
    std::uintptr_t exit_probe;
    std::uintptr_t terminate_probe;
    std::uintptr_t child_inject_probe;
};

struct ExitProbeData {
    std::uint32_t exit_code;
    std::uint32_t triggered;
    std::uint64_t process_handle;
    std::uint64_t caller_status;
    std::uint64_t entry_rax;
    std::uint64_t stack[8];
    // Child-injection diagnostics.  These remain zero for the generic exit
    // and terminate probes.
    std::uint32_t child_last_error;
    std::uint32_t child_payload_size;
};

ManualMapResult manual_map_zclient_loader(
    HANDLE process, HANDLE primary_thread, DWORD process_id,
    const std::filesystem::path& image_path, const std::string& service_host,
    const std::string& lsx_host, const std::string& instance_name,
    const std::filesystem::path& preload_dll = {});

// Prepare the raw PE payload placed in Global\\ZClient_CLoaderx64 for CLoader's
// child-process injector. Routing changes must be applied to the file
// representation before it is published.
std::vector<std::uint8_t> prepare_zclient_loader_image(
    const std::filesystem::path& image_path, const std::string& service_host,
    const std::string& instance_name);

std::vector<std::uint8_t> prepare_zclient_loader_names_only(
    const std::filesystem::path& image_path, const std::string& instance_name);

void patch_game_blaze_redirector(HANDLE process,
                                 const std::string& service_host);
void patch_cmain_lsx_redirect(HANDLE process,
                              const std::string& service_host);
