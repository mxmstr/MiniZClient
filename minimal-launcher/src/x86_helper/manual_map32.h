#pragma once

#include <windows.h>

#include <cstdint>
#include <filesystem>
#include <string>

struct ManualMap32Options {
    std::filesystem::path loader;
    std::filesystem::path preload_dll;
    std::string instance_name;
    std::string service_host;
};

struct ManualMap32Result {
    std::uint32_t loader_base = 0;
    std::uint32_t zlo_context = 0;
};

// The caller must create the target with CREATE_SUSPENDED. This routine
// briefly resumes its primary thread through an entry gate so normal WOW64
// loader initialization can finish, maps CLoaderx32, invokes DllMain/ZLO, and
// finally releases the executable entry point.
ManualMap32Result manual_map_zclient_loader32(
    HANDLE process, HANDLE primary_thread, DWORD process_id,
    const ManualMap32Options& options);

