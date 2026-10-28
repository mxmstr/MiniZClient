# Native Win32 initial-process injector

This directory is intentionally not wired into the top-level build yet. It is
the architecture-matched helper needed when the x64 launcher creates an x86
game such as Battlefield 3.

The x64 launcher remains responsible for the ZClient pipe, CLoader shared-image
mappings, environment, job object, and target lifetime. It creates the game
with `CREATE_SUSPENDED`, then starts this Win32 helper with the target PID/TID.
The helper opens those handles, lets the WOW64 loader stop at an x86 entry gate,
maps `CLoaderx32.dll`, calls its `DllMain` and `ZLO` export, releases the gate,
and exits. The parent should treat a nonzero helper exit code as injection
failure and terminate the still-owned target.

Example helper command:

```text
zclient_injector32.exe --pid 1234 --tid 5678 \
  --loader C:\path\CLoaderx32.dll --instance 0000ABC \
  --service-host 192.168.1.20
```

Build this source in a separate Win32 CMake/toolchain invocation. A CMake
target cannot switch an existing x64 MSVC/clang-cl generator to Win32 on a
per-target basis. The eventual top-level build can use an `ExternalProject`
sub-build or produce the helper from a separate `build-x86` preset.

Important remaining integration work:

- The helper patches the per-launch namespace but does not yet patch the
  current CLoaderx32 DNS/connect hook constants. Those signatures/RVAs must be
  recorded independently from the x64 loader before LAN routing is complete.
- A real `ZClient.LsxShim32.dll` is still needed for private per-process LSX and
  local multiplayer network isolation. The current shim has PE64 parsing and
  x64-only export detours. Until it is ported, omit `--preload` and host the LSX
  service externally on the legacy endpoint, or expect LSX initialization to
  remain incomplete.
- The helper has not been run against BF3 yet. Test the entry gate first, then
  DllMain/ZLO without a preload, before enabling a Win32 LSX shim.

