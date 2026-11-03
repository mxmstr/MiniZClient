#include "runtime_profile.h"

#include <iostream>
#include <stdexcept>

int main() {
    try {
        const std::string digest(64, 'a');
        const RuntimeProfile profile = make_runtime_profile("rivals", digest);
        if (profile.activation_module != L"Activation.dll" ||
            profile.activation_sha256 != digest ||
            profile.activation_key_rva != 0xC75E0) {
            throw std::runtime_error("Rivals profile fields are incorrect");
        }
        bool rejected = false;
        try { (void)make_runtime_profile("rivals", "abcd"); }
        catch (const std::exception&) { rejected = true; }
        if (!rejected) throw std::runtime_error("short activation hash was accepted");
        rejected = false;
        try { (void)make_runtime_profile("unknown-title", digest); }
        catch (const std::exception&) { rejected = true; }
        if (!rejected) throw std::runtime_error("unknown profile was accepted");
        std::cout << "runtime profile validation passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
