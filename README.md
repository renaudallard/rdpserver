<h1 align="center">rdpserver</h1>

<p align="center">
  <b>A native Remote Desktop Protocol server for Linux and BSD</b><br/>
  <em>Windows-style login over RDP &middot; no VNC in the stack &middot; greenfield C</em>
</p>

<p align="center">
  <a href="./LICENSE">
    <img src="https://img.shields.io/badge/license-BSD--2--Clause-blue.svg?style=flat-square" alt="License"/>
  </a>
  <img src="https://img.shields.io/badge/language-C-blue.svg?style=flat-square" alt="C"/>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20OpenBSD-success.svg?style=flat-square" alt="Linux | OpenBSD"/>
  <img src="https://img.shields.io/badge/status-alpha-orange.svg?style=flat-square" alt="alpha"/>
  <img src="https://img.shields.io/badge/deps-OpenSSL%20%2B%20libX11%20%2B%20libx264-informational.svg?style=flat-square" alt="OpenSSL + libX11 + libx264"/>
</p>

---

`rdpserver` is a Remote Desktop Protocol server written from scratch in C.
It implements the RDP wire format directly — **no FreeRDP, no Xvnc, no
intermediate VNC protocol anywhere** — and presents a real graphical
login screen over RDP before any user session exists. Once you sign in,
the server spawns a fresh per-user X11 session for you, exactly like
the Remote Desktop service on Windows.

Two daemons and one user-mode helper cooperate behind a privilege-
separation boundary:

```
TCP/3389 ── TLS ──> rdpd (root)
                     │  X.224 / MCS / RDP wire / greeter / CLIPRDR
                     ▼
                     rdp-sessionmgr (root)
                     │  PAM (Linux) or bsd_auth (OpenBSD)
                     │  fork + setresuid + exec
                     ▼
                     rdp-session (user)
                        Xvfb + xterm + XShm capture + XTest input
```

The greeter is painted with RDP fast-path bitmap updates over a CPU
framebuffer; an embedded 8×16 PSF font renders the labels and typed
text. After auth, a backend RPC shuttles pixel frames from
`rdp-session` to `rdpd` and input events the other way.

> **Status: alpha.** Verified end-to-end against `xfreerdp` between a
> Linux client and an OpenBSD daemon.  Not yet deployment-hardened on
> a real workload.  See [`docs/SECURITY.md`](./docs/SECURITY.md) for
> the trust model.

## Features

- **Native RDP wire protocol** — TPKT (RFC 1006), X.224 Class 0, T.125 MCS, BER + GCC PER, security header, MS-RDPELE licensing, capability negotiation, finalization, fast-path output and input.  No FreeRDP runtime.
- **Windows-style greeter** — TLS-only handshake, then a server-painted login dialog (centred panel, Username + Password fields with masking, Login button, status line).  Tab cycles focus, Enter submits, Backspace deletes, Esc cancels.  US-layout scancode → ASCII map; per-LCID layouts are next.
- **Real PAM / bsd_auth** — `rdp-sessionmgr` is a separate privileged daemon.  Linux/FreeBSD/NetBSD use PAM via the `login` service by default (override with `-S rdpd` + an `/etc/pam.d/rdpd` stack); OpenBSD calls `auth_userokay(3)` and links `-lutil`.  Failed auth turns the greeter status line red; the password is `mlock`'d and `explicit_bzero`'d immediately after.
- **Per-user X session** — on successful login the session manager forks, `initgroups` + `setresgid` + `setresuid` to the target user, exec's `rdp-session`, which spawns `Xvfb :N -screen 0 WxHx24 -nolisten tcp -noreset` and an `xterm` for it.  Frames flow back via a `SOCK_STREAM` socketpair handed in via `SCM_RIGHTS`.
- **MIT-SHM capture, XTest injection** — root-window pixels grabbed via `XShmGetImage` (falls back to `XGetImage`), input replayed via `XTestFakeKeyEvent` and `XTestFakeButtonEvent`.  PC/AT scancode + 8 maps directly to evdev keycodes on a stock Xvfb.
- **Bidirectional clipboard** — MS-RDPECLIP static virtual channel, text formats (CF_UNICODETEXT).  Copy in the remote `xterm` and paste in your local clipboard; copy locally and paste in `xterm`.  `XFixesSelectSelectionInput` watches the X CLIPBOARD selection and the worker bridges to the RDP channel via the backend RPC.
- **Clean disconnect** — properly framed MCS Disconnect Provider Ultimatum (X.224 DT + TPKT, no Send-Data nesting), Shutdown Request answered with Shutdown Denied so clients send a graceful MCS Disconnect, `SO_KEEPALIVE` + `TCP_KEEPIDLE/INTVL/CNT` on accepted sockets so half-open TCP is detected within ~2 minutes.
- **Hardened build** — `-Werror -Wall -Wextra -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual -Wundef -Wformat=2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now,-z,noexecstack` by default.  `./configure --enable-sanitizers` swaps in `-fsanitize=address,undefined`.  An in-tree fuzzer (`make fuzz`) drives 9 parsers with random bytes; 2.1 million iterations across three seeds under ASan + UBSan, zero crashes, zero UB.
- **OpenBSD `pledge(2)`** — `rdpd` worker pledges `stdio inet unix`; `rdp-sessionmgr` pledges `stdio rpath wpath cpath unix sendfd recvfd proc exec id getpw dpath fattr`; `rdp-session` pledges `stdio rpath wpath cpath unix proc`.  On non-OpenBSD the calls compile to a no-op via the `compat.h` shim.  Linux seccomp-bpf and FreeBSD capsicum are detected at configure time; wiring them is the next hardening item.
- **One configure script, two OSes** — hand-rolled POSIX `sh` (no autotools, no CMake).  Probes for libtls or OpenSSL, PAM or bsd_auth, getrandom or arc4random, epoll or kqueue, pledge / unveil / capsicum / seccomp, X11 dev libs, `Xvfb` path.  Builds clean under both bmake and GNU make.

## What works today vs not yet

| | Status | Notes |
| --- | --- | --- |
| TLS, MCS connect, channel join | ✓ | |
| Demand Active / Confirm Active / finalization | ✓ | |
| Fast-path Bitmap Update output (24bpp, tiled) | ✓ | |
| Fast-path input (scancode, mouse, sync, Unicode) | ✓ | |
| Server-painted greeter + PAM/bsd_auth | ✓ | |
| Per-user Xvfb + xterm session | ✓ | |
| CLIPRDR clipboard, bidirectional, text formats | ✓ | |
| Clean disconnect, Shutdown Request, TCP keepalive | ✓ | |
| NLA / CredSSP / NTLMv2 | partial | Wire framework only; needs a hash backend (winbind, sssd) to validate without a cleartext side-channel.  The daemon doesn't advertise PROTOCOL_HYBRID; `xfreerdp /sec:nla` is rejected cleanly. |
| RDPGFX / H.264 (AVC420) | ✓ | Server opens the GraphicsPipeline DRDYNVC channel, exchanges RDPGFX caps (v8.1), creates a surface, and streams frames as AVC420 WireToSurface1 PDUs encoded via libx264 (ultrafast/zerolatency, CRF 32).  Large frames are split across ZGFX segments and channel PDU fragments.  Verified end-to-end with xfreerdp 3.x on Linux and OpenBSD. |
| Audio output (RDPSND / MS-RDPEA) | ✓ negotiation | Format negotiation (PCM 16-bit stereo 44.1 kHz) on the `rdpsnd` static channel.  xfreerdp sees "audio formats supported."  Actual PCM streaming from PulseAudio/sndio capture is the next step. |
| Drive / printer / serial redirection | ✗ | |
| Session reconnect (auto-reconnect cookie) | ✓ infra | Save Session Info PDU with ARC cookie, Client Info ARC parser, sessmgr SUSPEND/RESUME ops, conn.c reconnect path. Works on clean disconnect; SIGKILL resilience needs sessmgr-retained fd (next item). |
| Dynamic resize (RDPEDISP via DRDYNVC) | ✓ | xfreerdp with `/dynamic-resolution`: server accepts Display Control Channel, sends Deactivate-All + re-Demand-Active at new geometry, rdp-session resizes Xvfb via xrandr. Apps survive the resize. |
| Multi-monitor | ✗ | |
| Native Xorg DDX (xrdpdev-style), Wayland backend | ✗ | The backend interface accommodates a future native module. |

## Supported clients

The protocol is the standard one (MS-RDPBCGR, MS-RDPECLIP), so any
RDP client should work.  Live-tested against:

| Client | Notes |
| --- | --- |
| `xfreerdp` (FreeRDP 3.x) | Primary test client.  `xfreerdp /v:host:3389 /cert:ignore /size:1024x768 +clipboard`. |
| Microsoft `mstsc.exe` | Should work; not yet exercised. |
| Microsoft Remote Desktop (macOS / iOS / Android) | Same wire protocol; not yet exercised. |
| Remmina | Uses FreeRDP under the hood; should work. |
| `rdesktop` (legacy) | Older PDU shapes; not yet exercised. |

## Build

```sh
./configure
make
```

The hand-rolled `configure` probes the host and writes `config.mk` +
`src/include/config.h`.  Useful flags:

| Flag | Effect |
| --- | --- |
| `--prefix=PATH` | Install prefix (default `/usr/local`). |
| `--with-tls=libtls\|openssl` | Force a TLS backend; default `auto`. |
| `--with-auth=pam\|bsd_auth` | Force an auth backend; default `auto`. |
| `--enable-debug` | `-O0 -g3`, no `NDEBUG`. |
| `--enable-sanitizers` | `-fsanitize=address,undefined`; drops `_FORTIFY_SOURCE`.  Implies `--enable-debug`. |
| `--disable-hardening` | Drops `-fPIE`, `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, and the relro/now link flags. |

Targets `make`, `make regress`, `make fuzz`, `make clean`, `make
distclean`, `make install`.  Builds clean under GNU make (Linux) and
bmake (OpenBSD).

### Dependencies

| | Linux | OpenBSD |
| --- | --- | --- |
| TLS | OpenSSL 1.1+/3.x | LibreSSL (base) |
| Auth | libpam | bsd_auth (base + `-lutil`) |
| X11 | `libx11-dev`, `libxdamage-dev`, `libxtst-dev`, `libxfixes-dev`, `libxext-dev` | base X11 (`/usr/X11R6`) |
| H.264 | `libx264-dev` | `pkg_add x264` |
| X server | `xvfb` | `xvfb` package (or base) |
| Optional clipboard helper for tests | `xclip` | `pkg_add xclip` |

## Run

The two daemons run separately.  For development:

```sh
# Terminal 1 (or via doas / sudo): the privileged session broker
doas ./src/sessionmgr/rdp-sessionmgr -f -d \
    -s /tmp/sessmgr.sock \
    -X $(pwd)/src/session/rdp-session

# Terminal 2: the RDP listener (root only needed for port 3389)
./src/daemon/rdpd -f -d -p 13389 -S /tmp/sessmgr.sock

# Terminal 3: any RDP client
xfreerdp /v:127.0.0.1:13389 /cert:ignore /size:1024x768 +clipboard
```

`rdpd` and `rdp-sessionmgr` install to `$PREFIX/sbin` via `make
install`.  A sample `/etc/pam.d/rdpd` lives in
[`contrib/pam.d/rdpd`](./contrib/pam.d/rdpd).

## Project layout

```
src/include/      public headers + backend vtable + generated config.h
src/common/       buffers, I/O, log, mem, rand, str, utf16, BER, PER
src/wire/         RDP wire protocol: tpkt, x224, mcs, sec header,
                  license, capset, share-control PDUs, fast-path
src/sec/          TLS (OpenSSL/LibreSSL); NLA framework (cssp, ntlm,
                  nla_crypto, nla)
src/channels/     CLIPRDR, DRDYNVC, RDPSND, RDPGFX
src/greeter/      embedded font, paint primitives, keymap, dialog
                  state machine
src/daemon/       rdpd main + per-connection state machine
src/sessionmgr/   rdp-sessionmgr broker, PAM and bsd_auth backends,
                  worker-side client library
src/session/      rdp-session per-user helper, Xvfb spawn, MIT-SHM
                  capture, XTest injection, X11 clipboard bridge
src/backend/      backend RPC (HELLO / FRAME / INPUT / CLIP / BYE)
regress/common/   unit tests for the helpers
regress/wire/     unit tests for the wire encoders
regress/fuzz/     in-tree mini-fuzzer (9 parsers)
regress/integ/    Python integration test driving the daemon through
                  Channel Join
tools/            mkfont.py (PSF -> C array), add_license.sh,
                  test helpers
docs/             ARCHITECTURE.md, PROTOCOL.md, SECURITY.md, ROADMAP.md,
                  man pages (rdpd.8, rdpd.conf.5, rdp-sessionmgr.8,
                  rdp-session.8)
contrib/          PAM stack, systemd unit, rc.d scripts, example config
```

## Tests

```sh
make regress           # unit tests, returns 0 on success
make fuzz              # 5000-iter smoke pass over each parser
./regress/integ/connect_test.py    # drives a live daemon through MCS
```

Unit tests run cleanly under `--enable-sanitizers` with no leaks or UB
diagnostics.  The fuzzer has logged 2.1 million random-byte iterations
across the 9 parsers (tpkt, x224, ber, per, mcs, cliprdr, fp_input,
cssp, ntlm) under ASan + UBSan without a single crash.

## Security model

See [`docs/SECURITY.md`](./docs/SECURITY.md) for the trust model,
process layout, `pledge` promise sets, and the explanation of why NLA
is currently a framework-only feature.

## Contributing

Bug reports and patches welcome via
[GitHub Issues](https://github.com/renaudallard/rdpserver/issues)
and pull requests.  Security issues: email `renaud@allard.it`
directly; do not file a public issue.

## License

BSD 2-Clause.  See [`LICENSE`](./LICENSE).  The full text is also
stamped at the top of every `.c` and `.h` source file.
