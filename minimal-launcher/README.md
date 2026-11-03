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
Studio 2022 Win32 toolchain, builds the shared LSX shim for both architectures,
and copies them beside the launcher. The launcher
looks for `CLoaderx64.dll`, `CLoaderx32.dll`, `zclient_injector32.exe`, and
`ZClient.LsxShim64.dll` beside its executable unless their paths are configured.
`ZClient.LsxShim32.dll` is also published beside the launcher for the emerging
CLoader/CMain-free Win32 path.

Native x64 games are mapped directly by the launcher and use the process-local
LSX shim. Native Win32 games are mapped by `zclient_injector32.exe`; the x64
parent remains responsible for the pipe, process job, identity, and LSX service.
This same-architecture split is required because a 64-bit process cannot reuse
its DLL addresses or native thread context to initialize imports in a WOW64
target safely.

The LSX shim supports an internal standalone mode selected with the inherited
`ZCLIENT_LSX_STANDALONE=1` environment variable. In this mode it enables its
network hooks as soon as its local LSX listener and early identity hooks are
ready, without waiting for CLoader/CMain to signal it. The launcher does not
select it on the legacy bootstrap path. With `--no-zlo-runtime`, the launcher
injects only the architecture-matched LSX shim, waits for its listener and
network hooks, applies a Blaze redirect when the title contains a known
hostname, and releases the suspended entry point. It does not map CLoader,
host the ZClient pipe, or create the CMain marker.

The first local instance prefers OriginSDK's discovery port 3216. If that port
is already occupied, later instances bind an ephemeral loopback port and their
process-local hooks redirect OriginSDK's 3216/6176/8216 connections to the
correct per-instance LSX listener.

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

For the CLoader/CMain-free path, add `no-zlo-runtime=true` to the config or pass
`--no-zlo-runtime`. The legacy-only `game-executable`, `module-id`,
`game-module-id`, and `client-token` values are then optional. Native x64 uses
`ZClient.LsxShim64.dll`; Win32 uses `ZClient.LsxShim32.dll` through
`zclient_injector32.exe`. Override the latter with `lsx-shim-x86=...` or
`--lsx-shim-x86 ...` when needed.

```powershell
.\build\Release\zclient_minimal_launcher.exe `
  --config ..\rivals.conf --no-zlo-runtime --eaid player-one
```

The shim-only launcher also debugs the created process tree. Each descendant is
reported before its entry point runs and receives the matching x86 or x64 shim
before execution continues. This replaces CLoader's child injector without
patching `CreateProcess` inside the game.

Legacy Rivals activation can be enabled with a fail-closed title profile:

```ini
no-zlo-runtime=true
compatibility-profile=rivals
activation-module-sha256=<SHA-256 of the local Activation.dll>
```

Obtain the value with `Get-FileHash .\Activation.dll -Algorithm SHA256`.

The profile recognizes only `Activation.dll`, verifies the complete file hash
from the loader event, validates the original key prefix at RVA `0xC75E0`, and
then installs the recovered 128-byte DSA key. Unknown hashes and signatures
abort the launch. The replacement key is built into the launcher; neither
`CMainx32.dll` nor a scan of CMain memory is required.

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

The LSX `GetAuthToken` response retains the recovered ZLO
`WAHAHA_IMMA_ZLO_TOKEN` prefix required by older OriginSDK titles. Local
launches append the private `ZLOCAL1` EAID token and configured numeric account
ID so simultaneous instances authenticate to Blaze as distinct users. The
backend continues to accept the exact fixed sentinel for older launchers.

The standalone Rivals profile reproduces both certificate paths used by the
original runtime. CryptoAPI trust errors are cleared only for a chain that
contains both a ZLO issuer (`ZCertMaker` or `admin@zlofenix.org`) and a
`gosredirector` identity. Rivals' embedded DirtySSL path verifies its parsed
certificate through `BCryptVerifySignature`; for this title CMain replaced
that call with `STATUS_SUCCESS`, so the shim applies the same replacement only
inside a standalone Rivals process. No certificate is installed into a
Windows trust store.

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
