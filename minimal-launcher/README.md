# Minimal ZClient launcher

This standalone launcher creates an EA game suspended, maps the recovered
CLoader, hosts the upstream ZClient pipe and an OriginSDK LSX service, then
resumes the game. It does not require `ZI.exe`.

## Build

```powershell
cmake -S . -B build -G Ninja -DCMAKE_CXX_COMPILER=clang-cl
cmake --build build
```

The x64 build automatically creates a small native Win32 helper with the Visual
Studio 2022 Win32 toolchain and copies it beside the launcher. The launcher
looks for `CLoaderx64.dll`, `CLoaderx32.dll`, `zclient_injector32.exe`, and
`ZClient.LsxShim64.dll` beside its executable unless their paths are configured.

Native x64 games are mapped directly by the launcher and use the process-local
LSX shim. Native Win32 games are mapped by `zclient_injector32.exe`; the x64
parent remains responsible for the pipe, process job, identity, and LSX service.
This same-architecture split is required because a 64-bit process cannot reuse
its DLL addresses or native thread context to initialize imports in a WOW64
target safely.

## Game configuration

Game identity is not built into the launcher. These settings are required,
either in a config file or as command-line options:

- `game`: path to the game executable
- `game-title`: title reported by the local LSX service
- `content-id`: EA offer/content ID
- `game-id`: numeric ZClient game ID
- `game-executable`: executable filename used by the ZClient pipe lookup
- `module-id`: CLoader module selector
- `game-module-id`: executable-specific selector
- `client-token`: ZClient protocol token

Run Need for Speed Rivals using the preserved settings:

```powershell
.\build\zclient_minimal_launcher.exe --config ..\rivals.conf --eaid player-one
```

Edit `game` in `rivals.conf` for the local installation. Config uses one
`key=value` setting per line; blank lines and lines beginning with `#` or `;`
are ignored. Relative file paths are resolved relative to the config file.
Command-line options override config values regardless of where `--config`
appears. `game-arg` may be repeated in a config file.

When `--config` is omitted, the launcher automatically loads
`MiniZClient.conf` from the directory containing the launcher executable if
that file exists. An explicit `--config` always takes precedence.

The required settings also have matching CLI flags. For example:

```powershell
.\build\zclient_minimal_launcher.exe `
  --game "D:\Games\Example\Example.exe" `
  --game-title "Example Game" --content-id EXAMPLE-OFFER --game-id 7 `
  --game-executable example.exe --module-id 0x12345678 `
  --game-module-id 0x87654321 --client-token 0xA0000001 `
  --eaid player-one
```

For a game with an activation child, configure both `activation-executable` and
`activation-module-id`. Omitting either is an error.

Use `--help` for all options. Useful optional settings include `bootstrap`,
`bootstrap-x86`, `injector-x86`, `lsx-shim`, `service-host`, `lsx-host`, `account-id`,
`zbackend`, `zbackend-digest`, `data-path`, `frosty-pack`, `game-arg`, and
`breakaway`.

Games that use the legacy Origin activation client can replay a previously
captured, signed `/licenses` response. Configure both values together:

```ini
license-response=../../captured-license/response.bin
license-signature=MC0CFQB3eqvbXF8bPsAVDxMGlg4QnXPC+QIUiP2XpL+5bzBfdsE0fvMqPK+dycI=
```

The launcher then serves the opaque response at `127.0.0.1:5080` with the
required `Content-Type`, `X-Signature`, and `X-ZLO` headers. The signed response
is machine/license specific; use it only with the machine and title for which
it was captured. The equivalent command-line options are `--license-response`
and `--license-signature`.

LSX shim logging is enabled by default. Set `lsx-log=false` in the config file
or pass `--no-lsx-log` to prevent creation of `ZClient.LsxShim-<pid>.log`.
Use `lsx-log=true` or `--lsx-log` to enable it explicitly; command-line toggles
override the config setting.

For Need for Speed Most Wanted 2012, the LSX `GetAuthToken` response uses
CMain's legacy `WAHAHA_IMMA_ZLO_TOKEN` sentinel. The title accepts the local
`ZLOCAL1` identity during its injected startup login but requires the legacy
sentinel when Autolog is manually reconnected from the pause menu.

If `eaid` is omitted, the launcher searches nearby directories for
`ZData_Settings.zlo`. A standalone EA ID maps deterministically to the numeric
LSX user/persona ID; `--account-id` can override it. With `--zbackend`, the
backend supplies the identity and `--account-id` is not allowed.

The backend digest can be passed with `--zbackend-digest` or stored in the
`ZBACKEND_DIGEST` environment variable. To use a Blaze backend on another LAN
machine, pass `--service-host <IPv4>`.

Repeat `--game-arg` or put arguments after `--`. `--data-path` (and Frosty's
native `-dataPath`) forwards a generated Frosty data directory. `--frosty-pack`
resolves a pack below the configured game's `ModData` directory. The launcher
checks for `Update\Patch\Data\mods.json` or the legacy `mods.txt` marker.

## Battlefield 3 Battlelog launch

BF3 normally waits for Battlelog to call ZClient's local `/ZLO/run` endpoint.
The launcher can now generate that handoff itself, after its account identity
is known and before `bf3.exe` is created. No browser or listener on port 5080
is needed.

Start the campaign with:

```powershell
.\build\zclient_minimal_launcher.exe --config .\build\bf3.conf --bf3-mode sp
```

Start multiplayer with the Battlelog reservation/game ID shown in the server
launch URL:

```powershell
.\build\zclient_minimal_launcher.exe --config .\build\bf3.conf `
  --bf3-mode mp --bf3-server-id 14609
```

The launcher's `game-id` remains the ZClient game identity (`11` for BF3).
`bf3-server-id` is the separate, per-server Battlelog reservation ID.

A captured shim URL can be passed directly instead. Quote it in PowerShell so
that its `&` characters are not interpreted:

```powershell
.\build\zclient_minimal_launcher.exe --config .\build\bf3.conf `
  --bf3-launch-url 'http://localhost:5080/ZLO/run?game=Z.BF3&cmd=...'
```

The equivalent config keys are `bf3-mode=sp|mp`, `bf3-server-id=<id>`, and
`bf3-launch-url=<url>`. A URL is validated as a local BF3 endpoint and reduced
to the supported SP or MP launch profile. The `%ZID%` placeholder is replaced
with the launcher's numeric account/persona ID. Use `account-id` when a backend
requires a specific ID; otherwise the launcher derives a stable local ID from
the EA ID.

BF3 is a Win32 executable. During its launch the parent listens for LSX on the
legacy port `8216` at a per-launcher address inside Windows' `127.0.0.0/8`
loopback range, while the Win32 helper holds BF3 at an entry gate, maps
`CLoaderx32.dll`, initializes CMain, redirects CMain's LSX callback to the
matching instance address, and only then releases the game entry point. This
keeps the fixed CMain port while allowing simultaneous Win32 game instances to
use separate LSX services, EA IDs, account IDs, and authentication tokens.

For Win32 launches with a configured activation child, the initial injector
locates only CMain's activation routine before releasing the game entry point.
The pipe host also identifies the activation process from the executable path
in its CMain opcode-2 request and starts a second lightweight monitor there.
This covers titles that load `Activation.dll` in either the game process or the
activation UI process.

The monitor waits for `Activation.dll` to load, reads the relocated 128-byte
DSA public key from CMain, copies it to the validated Activation key location,
and sets CMain's one-time activation state marker. It then detaches immediately.
No WinHTTP or scanner breakpoints are installed, and normal builds do not watch
exceptions or write crash dumps.
