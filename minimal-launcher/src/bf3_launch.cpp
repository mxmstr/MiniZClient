#include "bf3_launch.h"

#include <algorithm>
#include <cwctype>
#include <stdexcept>
#include <utility>

namespace {

constexpr std::wstring_view kZloToken = L"WAHAHA_IMMA_ZLO_TOKEN";

std::wstring lowercase(std::wstring_view value)
{
    std::wstring result(value);
    std::transform(result.begin(), result.end(), result.begin(),
                   [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
    return result;
}

int hex_digit(wchar_t ch)
{
    if (ch >= L'0' && ch <= L'9') return ch - L'0';
    ch = static_cast<wchar_t>(std::towlower(ch));
    if (ch >= L'a' && ch <= L'f') return ch - L'a' + 10;
    return -1;
}

std::wstring percent_decode(std::wstring_view value)
{
    std::wstring result;
    result.reserve(value.size());

    for (std::size_t index = 0; index < value.size(); ++index)
    {
        const wchar_t ch = value[index];
        if (ch == L'+')
        {
            result.push_back(L' ');
            continue;
        }
        if (ch != L'%')
        {
            result.push_back(ch);
            continue;
        }
        if (index + 2 >= value.size())
            throw std::runtime_error("Invalid percent escape in BF3 launch URL.");

        const int high = hex_digit(value[index + 1]);
        const int low = hex_digit(value[index + 2]);
        if (high < 0 || low < 0)
            throw std::runtime_error("Invalid percent escape in BF3 launch URL.");

        // Battlelog's command templates contain ASCII. Reject non-ASCII bytes
        // instead of silently interpreting an incomplete UTF-8 sequence.
        const int decoded = (high << 4) | low;
        if (decoded > 0x7f)
            throw std::runtime_error("BF3 launch URL contains a non-ASCII escape.");
        result.push_back(static_cast<wchar_t>(decoded));
        index += 2;
    }

    return result;
}

std::wstring query_value(std::wstring_view query, std::wstring_view wanted)
{
    for (std::size_t begin = 0; begin <= query.size();)
    {
        const std::size_t end = query.find(L'&', begin);
        const std::wstring_view field = query.substr(
            begin, end == std::wstring_view::npos ? query.size() - begin : end - begin);
        const std::size_t equals = field.find(L'=');
        const std::wstring name = lowercase(percent_decode(field.substr(0, equals)));
        if (name == wanted)
        {
            return equals == std::wstring_view::npos
                ? std::wstring{}
                : percent_decode(field.substr(equals + 1));
        }
        if (end == std::wstring_view::npos) break;
        begin = end + 1;
    }
    return {};
}

std::wstring parse_server_id(std::wstring_view command)
{
    const std::wstring folded = lowercase(command);
    const std::size_t marker = folded.find(L"gameid=");
    if (marker == std::wstring::npos) return {};

    std::size_t cursor = marker + 7;
    if (cursor < command.size() && command[cursor] == L'\\') ++cursor;
    if (cursor < command.size() && command[cursor] == L'\"') ++cursor;

    const std::size_t begin = cursor;
    while (cursor < command.size() && std::iswdigit(command[cursor])) ++cursor;
    if (cursor == begin)
        throw std::runtime_error("BF3 multiplayer launch URL has an invalid gameid.");
    return std::wstring(command.substr(begin, cursor - begin));
}

} // namespace

Bf3LaunchMode parse_bf3_launch_mode(std::wstring_view value)
{
    const std::wstring folded = lowercase(value);
    if (folded == L"sp" || folded == L"singleplayer")
        return Bf3LaunchMode::singleplayer;
    if (folded == L"mp" || folded == L"multiplayer")
        return Bf3LaunchMode::multiplayer;
    if (folded == L"none" || folded.empty())
        return Bf3LaunchMode::none;
    throw std::runtime_error("bf3-mode must be sp, mp, or none.");
}

Bf3LaunchRequest parse_bf3_launch_url(std::wstring_view value)
{
    const std::size_t query_begin = value.find(L'?');
    if (query_begin == std::wstring_view::npos)
        throw std::runtime_error("BF3 launch URL has no query string.");

    const std::wstring endpoint = lowercase(value.substr(0, query_begin));
    if (endpoint != L"http://localhost:5080/zlo/run" &&
        endpoint != L"http://127.0.0.1:5080/zlo/run")
    {
        throw std::runtime_error(
            "BF3 launch URL must target http://localhost:5080/ZLO/run.");
    }

    const std::wstring_view query = value.substr(query_begin + 1);
    if (lowercase(query_value(query, L"game")) != L"z.bf3")
        throw std::runtime_error("BF3 launch URL does not identify game Z.BF3.");

    const std::wstring command = query_value(query, L"cmd");
    const std::wstring folded_command = lowercase(command);
    Bf3LaunchRequest request;
    if (folded_command.find(L"-webmode sp") != std::wstring::npos)
    {
        request.mode = Bf3LaunchMode::singleplayer;
    }
    else if (folded_command.find(L"-webmode mp") != std::wstring::npos)
    {
        request.mode = Bf3LaunchMode::multiplayer;
        request.server_id = parse_server_id(command);
    }
    else
    {
        throw std::runtime_error("BF3 launch URL cmd has no supported -webMode.");
    }

    validate_bf3_launch(request);
    return request;
}

void validate_bf3_launch(const Bf3LaunchRequest& request)
{
    if (request.mode == Bf3LaunchMode::none)
    {
        if (!request.server_id.empty())
            throw std::runtime_error("bf3-server-id requires bf3-mode=mp.");
        return;
    }

    if (request.mode == Bf3LaunchMode::singleplayer)
    {
        if (!request.server_id.empty())
            throw std::runtime_error("bf3-server-id cannot be used with bf3-mode=sp.");
        return;
    }

    if (request.server_id.empty())
        throw std::runtime_error("bf3-mode=mp requires bf3-server-id.");
    if (request.server_id.size() > 20 ||
        !std::all_of(request.server_id.begin(), request.server_id.end(),
                     [](wchar_t ch) { return std::iswdigit(ch) != 0; }) ||
        std::all_of(request.server_id.begin(), request.server_id.end(),
                    [](wchar_t ch) { return ch == L'0'; }))
    {
        throw std::runtime_error("bf3-server-id must be a nonzero decimal number.");
    }
}

std::vector<std::wstring> make_bf3_launch_arguments(
    const Bf3LaunchRequest& request, std::uint64_t persona_id)
{
    validate_bf3_launch(request);
    if (request.mode == Bf3LaunchMode::none) return {};
    if (persona_id == 0)
        throw std::runtime_error("A nonzero account/persona ID is required for BF3.");

    const std::wstring mode = request.mode == Bf3LaunchMode::singleplayer ? L"SP" : L"MP";
    const std::wstring state = request.mode == Bf3LaunchMode::singleplayer
        ? L"State_ResumeCampaign"
        : L"State_ClaimReservation";

    std::wstring state_parameters = L"<data ";
    if (request.mode == Bf3LaunchMode::multiplayer)
    {
        state_parameters += L"putinsquad=\"true\" gameid=\"" + request.server_id +
                            L"\" role=\"soldier\" ";
    }
    state_parameters += L"personaref=\"" + std::to_wstring(persona_id) +
                        L"\" levelmode=\"" + lowercase(mode) +
                        L"\" logintoken=\"" + std::wstring(kZloToken) + L"\"></data>";

    return {
        L"-webMode", mode,
        L"-Origin_NoAppFocus",
        L"-loginToken", std::wstring(kZloToken),
        L"-requestState", state,
        L"-requestStateParams", std::move(state_parameters),
    };
}

