#include "bf3_launch.h"

#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

} // namespace

int main()
{
    try
    {
        const auto sp = make_bf3_launch_arguments(
            {Bf3LaunchMode::singleplayer, {}}, 123456);
        require(sp.size() == 9, "unexpected SP argument count");
        require(sp[1] == L"SP", "SP mode missing");
        require(sp[6] == L"State_ResumeCampaign", "SP state missing");
        require(sp[8].find(L"personaref=\"123456\"") != std::wstring::npos,
                "SP persona substitution missing");

        const auto mp = make_bf3_launch_arguments(
            {Bf3LaunchMode::multiplayer, L"14609"}, 789);
        require(mp[1] == L"MP", "MP mode missing");
        require(mp[6] == L"State_ClaimReservation", "MP state missing");
        require(mp[8].find(L"gameid=\"14609\"") != std::wstring::npos,
                "MP server ID missing");

        const auto from_url = parse_bf3_launch_url(
            L"http://localhost:5080/ZLO/run?game=Z.BF3&cmd="
            L"-webMode%20MP%20-requestStateParams%20%22%3Cdata%20"
            L"gameid%3D%5C%2214609%5C%22%3E%3C%2Fdata%3E%22");
        require(from_url.mode == Bf3LaunchMode::multiplayer,
                "URL MP mode not detected");
        require(from_url.server_id == L"14609", "URL server ID not detected");

        bool rejected = false;
        try
        {
            (void)parse_bf3_launch_url(
                L"http://example.com:5080/ZLO/run?game=Z.BF3&cmd=-webMode%20SP");
        }
        catch (const std::exception&)
        {
            rejected = true;
        }
        require(rejected, "non-local BF3 launch URL was accepted");
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "bf3_launch_test: " << error.what() << '\n';
        return 1;
    }
}
