#pragma once

#include <windows.h>

#include <cstdint>
#include <string>

struct RuntimeProfile {
    std::string name;
    std::wstring activation_module;
    std::string activation_sha256;
    std::uintptr_t activation_key_rva = 0;
};

RuntimeProfile make_runtime_profile(const std::string& name,
                                    const std::string& activation_sha256);

// Returns true only when the event names and hashes a profiled module and the
// validated replacement was applied (or was already present).
bool apply_runtime_profile_module(const RuntimeProfile& profile,
                                  HANDLE process, HANDLE module_file,
                                  void* module_base);
