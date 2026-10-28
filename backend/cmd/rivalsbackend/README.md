# Rivals Go backend

This server is a native Go replacement for `rivals-asi/coordinator.py`. It
implements the authenticated HTTP protocol consumed by `ZClient.Rivals.asi`,
including schema-free HEAT2/TDF packet preservation, public-session matching,
roster assignment, forwarded GameManager state, queued notifications,
acknowledgement cursors, leave handling, and peer expiry.

It also exposes the TLS/Blaze endpoint expected by NFS14 on the selected LAN
IPv4 address at port 4531. That endpoint replays the captured successful ZClient
initialization exchange, while rewriting each response correlation ID to match
the live client request. A fresh certificate containing the advertised LAN IPv4
address is created when the server starts.

The companion TLS/Blaze redirector listens on that LAN address at port 47127. It advertises
the automatically detected LAN IPv4 address and secure Blaze port 4531. Override
that address with `-advertise-host <IPv4>` when routing requires it.

Build and run it from the `ZClient` directory:

```powershell
go build -o build/rivals-backend.exe ./cmd/rivalsbackend
./build/rivals-backend.exe -token "replace-with-a-16-character-token"
```

Configure every participating client with the same endpoint and token:

```ini
[Rivals]
Enabled=1
CoordinatorHost=192.168.4.199
CoordinatorPort=48386
Token=replace-with-a-16-character-token
```

Options corresponding to the Python coordinator are available as
`-lan-addresses` and `-peer-hosted`. The default listen address is
`0.0.0.0:48386` and the default inactive-peer lifetime is 90 seconds. Use
`-blaze-listen` to change the game-facing endpoint or `-disable-blaze` to run
only the ASI matchmaking coordinator. `-redirector-listen` changes the TLS/Blaze
bootstrap address, `-advertise-host` controls the address returned to the game,
and `-disable-redirector` disables it.

The replay corpus represents the traced NFS14/PC `mxmstr` startup path. Unknown
or out-of-order requests are logged; no request is forwarded to EA services.

## Need for Speed Most Wanted 2012 protocol probe

The `nfs13-probe` profile terminates the SSL 3.0 redirector and secure Blaze
connections used by the PC DVD 1.0 build. The decrypted connection is bridged
to the full Blaze replay handler so repeated authentication receives the same
personalized login/session bundle as initial authentication:

```powershell
go run ./cmd/rivalsbackend -profile nfs13-probe `
  -advertise-host 192.168.4.199 -capture nfs13_blaze_capture.jsonl
```

With `-nfs13-rewrite-preauth`, the rewritten pre-auth configuration also
advertises a local Autolog base URL at the selected LAN address on port 48386.
The profile serves the initial `RoadData` server-manifest request there and
logs the method, path, query, and body size of every follow-on request. The
current manifest is intentionally minimal: it enables the server and supplies
the required `allow` and `bundles` objects so the remaining bundle names and
schemas can be recovered from live PC DVD 1.0 traffic without contacting EA.

## Dead Space 3 protocol replay

The same executable can host a separate Dead Space 3 development profile. It
provides the trusted legacy TLS redirector and a Blaze endpoint that replays
the captured DS3 startup transcript. Live request correlations are substituted
into captured responses, and the original pipelined response/notification
order is preserved:

```powershell
go run ./cmd/rivalsbackend -profile ds3-probe `
  -advertise-host 192.168.0.10 -capture ds3_blaze_capture.jsonl
```

Dead Space 3 sends an SSL 3.0 ClientHello to the redirector. The DS3 profile
therefore requires the private SSL3-enabled OpenSSL 1.0.2u runtime at
`build\openssl-ssl3\openssl-ds3-pipe.exe`. This build includes the Windows
redirected-stdin fix required to carry binary Blaze replies from the backend
into the TLS connection. The backend verifies the version before it
opens the redirector and also verifies the patch marker, so a stale stock
1.0.2 binary cannot silently complete the handshake without forwarding the
reply. It will not fall back to a system or Git OpenSSL. An
alternate private build can be selected with `ZCLIENT_SSL3_OPENSSL`; it must
identify itself as OpenSSL 1.0.2 and contain the redirected-stdin patch. This obsolete runtime is used only as the
redirector TLS termination process and does not change Windows or system-wide
TLS settings. The redirector reproduces ZClient's SSL-record split: byte zero
of the Fire2 response (the leading zero of its two-byte body length) is written
as one record, followed by the remaining 62 response bytes. The patched sidecar
acknowledges both `SSL_write` calls so that pipe buffering cannot merge them.
It also disables OpenSSL's legacy CBC empty-fragment mitigation. That
otherwise inserts a third 32-byte record which OpenSSL clients ignore but DS3's
DirtySSL exposes as invalid plaintext. The resulting application-record bodies
match the real service at 32 bytes for the zero prefix and 96 bytes for the
Fire2 response. The captured redirector response sets `SECU=0`, so the DS3
profile uses ZClient's captured fixed local-proxy port 48482 as a plaintext
Fire2 listener. It binds that listener to `0.0.0.0` by default so both the
redirector's literal `localhost` address and CLoader's LAN redirect can reach
it; requests and replayed replies on that port are recorded in the
configured JSONL capture. Unknown or
out-of-order requests are logged and receive an empty correlated success so
new protocol traffic remains observable. The redirector request and response
are recorded separately beside it with `_redirector` inserted before the file
extension (for example, `ds3_blaze_capture_redirector.jsonl`).

Point the minimal launcher's `service-host` at the advertised address. The
capture includes raw frames and decoded TDF fields. The embedded transcript is
generated from a real ZClient format-4 recorder session with
`cmd/ds3replaygen`; the next implementation milestone is replacing the replayed
GameManager flow with stateful matchmaking handlers.

The minimal launcher identifies each client through a `ZLOCAL1` authentication
token derived from its `--eaid`. The Blaze service personalizes login/session
frames, assigns stable per-name IDs, sends public matchmaking setup through the
same shared registry used by the ASI coordinator, and pushes player-added and
game-state notifications directly to connected Blaze clients. Each simultaneous
client must therefore use a different `--eaid`.
