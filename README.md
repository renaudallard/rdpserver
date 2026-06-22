<p align="center">
  <img src="rdpserver-logo-dark.svg" alt="rdpserver" width="440"/>
</p>

<p align="center">
  <a href="./LICENSE">
    <img src="https://img.shields.io/badge/license-BSD--2--Clause-blue.svg?style=flat-square" alt="License"/>
  </a>
  <img src="https://img.shields.io/badge/language-C-blue.svg?style=flat-square" alt="C"/>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20OpenBSD%20%7C%20macOS-success.svg?style=flat-square" alt="Linux | OpenBSD | macOS"/>
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
                     │  X.224 / MCS / NLA (CredSSP/NTLMv2) / RDP wire
                     │  CLIPRDR / RDPGFX / RDPSND / RDPDR
                     ▼
                     rdp-sessionmgr (root)
                     │  PAM (Linux) or bsd_auth (OpenBSD)
                     │  auto-caches NT hashes for NLA
                     │  fork + setresuid + exec
                     ▼
                     rdp-session (user)
                        Xvfb + xterm + XShm capture + XTest input
```

The greeter is painted with RDP fast-path bitmap updates over a CPU
framebuffer; an embedded 8x16 PSF font renders the labels and typed
text. After auth, `rdp-session` captures frames and streams raw
pixels over the backend RPC socket to `rdpd`, which encodes them
with H.264 (libx264) and wraps the bitstream in RDPGFX AVC420 PDUs
when the client negotiated the graphics pipeline (otherwise it
sends fast-path bitmap updates).

> **Status: alpha.** Verified end-to-end against `xfreerdp`,
> Microsoft `mstsc.exe` (Windows 11), Microsoft Remote Desktop
> (macOS and Android).  NLA/CredSSP works with all Microsoft clients.
> See [`docs/SECURITY.md`](./docs/SECURITY.md) for the trust model.

## Features

- **Native RDP wire protocol** — TPKT (RFC 1006), X.224 Class 0, T.125 MCS, BER + GCC PER, security header, MS-RDPELE licensing, capability negotiation, finalization, fast-path output and input.  No FreeRDP runtime.
- **Windows-style greeter** — TLS-only handshake, then a server-painted login dialog (centred panel, Username + Password fields with masking, Login button, status line).  Tab cycles focus, Enter submits, Backspace deletes, Esc cancels.  The greeter follows the client's keyboard layout (LCID) for US, UK, French, Belgian, German, and Swiss keyboards (ASCII letters and digits only; AltGr, dead keys, and accented characters are unavailable at the login field because of the ASCII bitmap font), falling back to US for other layouts.  The logged-in session follows the client's keyboard layout (LCID) in full.
- **Real PAM / bsd_auth** — `rdp-sessionmgr` is a separate privileged daemon.  Linux/FreeBSD/NetBSD use PAM via the `login` service by default (override with `-S rdpd` + an `/etc/pam.d/rdpd` stack); OpenBSD calls `auth_userokay(3)` and links `-lutil`.  Failed auth turns the greeter status line red; the password is `mlock`'d and `explicit_bzero`'d immediately after.
- **Per-user X session** — on successful login the session manager forks, `initgroups` + `setresgid` + `setresuid` to the target user, exec's `rdp-session`, which spawns `Xvfb :N -screen 0 WxHx24 -nolisten tcp -noreset` and an `xterm` for it.  Frames flow back via a `SOCK_STREAM` socketpair handed in via `SCM_RIGHTS`.
- **MIT-SHM capture, XTest injection** — root-window pixels grabbed via `XShmGetImage` (falls back to `XGetImage`), input replayed via `XTestFakeKeyEvent` and `XTestFakeButtonEvent`.  PC/AT scancode + 8 maps directly to evdev keycodes; the session's Xvfb keyboard layout is set from the client's reported layout (LCID) via `setxkbmap` (US fallback for unknown layouts), so those keycodes produce the client's characters (e.g. an AZERTY client types correctly).  Unicode keystrokes (fast-path Unicode events, e.g. on-screen keyboards and non-US text) are injected by remapping a spare keycode to the target keysym and faking a press/release.
- **Bidirectional clipboard** — MS-RDPECLIP static virtual channel, text (CF_UNICODETEXT), HTML, and image formats.  Copy in the remote `xterm` and paste in your local clipboard; copy locally and paste in `xterm`.  `XFixesSelectSelectionInput` watches the X CLIPBOARD selection and the worker bridges to the RDP channel via the backend RPC.  HTML is mapped both ways between the X `text/html` target and the registered Windows `HTML Format` (the worker adds/strips the CF_HTML `Version`/`StartFragment` envelope; the registered format name is matched in the format list and its dynamic id learned per session).  Images are carried between the X `image/bmp` target and the Windows `CF_DIB`/`CF_DIBV5` formats by a zero-dependency BMP conversion (the worker prepends or strips the 14-byte `BITMAPFILEHEADER`).  Files are copied in both directions over the X `text/uri-list` target and the Windows `FileGroupDescriptorW`/`FILECONTENTS` PDUs: a file copied in the Linux session is offered to the client and streamed on demand, and a file copied in the client and pasted into the session is downloaded into a per-session temp directory (created with `mkdtemp` under `$XDG_RUNTIME_DIR`, `$TMPDIR`, or `/tmp`) and exposed to the local app as `file://` URIs.  Because the descriptor file names come from the client and are untrusted, every name is sanitized before use (back-slashes folded to slashes, components split and any empty, `.`, or `..` component or absolute path rejected) so a paste can never write outside that temp directory; the directory is removed on the next paste, an owner change, or session close.  Large transfers are handled end to end: inbound channel fragments are reassembled, the X selection is read past the 16 KiB property limit (including the `INCR` protocol) and written back in chunks, bounded at 4 MiB, and a pasted file is downloaded in successive ranges (capped at 256 MiB per file).
- **RemoteApp / seamless windows (MS-RDPERP / RAIL)** — when a client connects in RemoteApp mode (xfreerdp `/app:...`, mstsc `remoteapplicationmode:i:1`) it sets the `INFO_RAIL` flag in the Client Info PDU, and the server advertises the RAIL and WINDOW capability sets, opens the `rail` static virtual channel, completes the `TS_RAIL_ORDER` handshake, answers the client status, and acknowledges Execute requests with an Execute Result.  Each session window is then reported to the client as a Window Information Order (new, size/position update, delete) so the client paints it as a borderless seamless window on its own desktop instead of a full remote desktop.  On the Wayland backend (`rdp-session -W`) each xdg_shell toplevel keeps its natural size and a cascade position and is tracked as its own RAIL window; on the Xvfb backend the session is presented as a single whole-desktop seamless window.  The window-order byte layout is validated against the FreeRDP decoder by the `rail` regress test.
- **Clean disconnect** — properly framed MCS Disconnect Provider Ultimatum (X.224 DT + TPKT, no Send-Data nesting), Shutdown Request answered with Shutdown Denied so clients send a graceful MCS Disconnect, `SO_KEEPALIVE` + `TCP_KEEPIDLE/INTVL/CNT` on accepted sockets so half-open TCP is detected within ~2 minutes.
- **Hardened build** — `-Werror -Wall -Wextra -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual -Wundef -Wformat=2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie -Wl,-z,relro,-z,now,-z,noexecstack` by default.  `./configure --enable-sanitizers` swaps in `-fsanitize=address,undefined`.  An in-tree fuzzer (`make fuzz`) drives 10 parsers with random bytes under ASan + UBSan, zero crashes, zero UB; the original nine saw 2.1 million iterations across three seeds, and the GFX caps-advertise parser four million more across four seeds.
- **OpenBSD `pledge(2)`** — `rdpd` worker pledges `stdio inet unix rpath wpath cpath sendfd recvfd`; `rdp-sessionmgr` pledges `stdio rpath wpath cpath unix sendfd recvfd proc exec id getpw dpath fattr`; `rdp-session` pledges `stdio rpath wpath cpath unix proc`.  On non-OpenBSD the calls compile to a no-op via the `compat.h` shim.  Linux seccomp-bpf sandbox is wired and allowlists the required syscalls.
- **One configure script, two OSes** — hand-rolled POSIX `sh` (no autotools, no CMake).  Probes for libtls or OpenSSL, PAM or bsd_auth, getrandom or arc4random, epoll or kqueue, pledge / unveil / capsicum / seccomp, X11 dev libs, `Xvfb` path.  Builds clean under both bmake and GNU make.

## What works today vs not yet

| | Status | Notes |
| --- | --- | --- |
| TLS, MCS connect, channel join | ✓ | TLS 1.2 or 1.3 (1.3 preferred, 1.2 floor).  By default a self-signed development certificate is generated; an operator can serve a real certificate with `rdpd -c cert -k key` (the cert must load or the daemon exits, so a bad path fails loudly instead of silently serving the untrusted self-signed one). |
| Demand Active / Confirm Active / finalization | ✓ | |
| Fast-path Bitmap Update output (24bpp, tiled) | ✓ | Each 64x64 tile is interleaved-RLE compressed (the same codec as the bitmap cache) and sent compressed whenever that is smaller than the raw rows; incompressible tiles and any rectangle beyond the 64x64 codec limit fall back to raw pixels, so a frame is never enlarged.  The interleaved-RLE codec emits a 24bpp stream, which a client only decodes in a 24bpp session (mstsc negotiates 32bpp and rejects it with a protocol error while accepting the equivalent raw bitmap), so compression is used only for clients whose preferred colour depth is 24bpp; other clients receive raw bitmaps.  Small updates are sent as a single fragment; a bitmap update too large for one fast-path PDU is split into FIRST/NEXT/LAST fragments honoring the client's MultifragmentUpdate MaxRequestSize (16KB safe default when absent). |
| Fast-path input (scancode, mouse, sync, Unicode) | ✓ | Scancode and mouse forwarded to the session; Unicode events forwarded and injected via a spare-keycode keysym remap; sync (Caps/Num/Scroll Lock state) is forwarded and applied to the session keyboard via the XKB lock modifiers. |
| Keyboard layout (per-LCID) | ✓ | The client's keyboard layout (the Windows LCID in the GCC client core data) selects the session keymap, so non-US users get the right characters: scancodes are injected as raw keycodes that the session keymap interprets. On the Xvfb backend `setxkbmap` is run with the LCID mapped to an XKB layout and variant (a 23-entry table); on the Wayland backend (`-W`) the same mapping builds an `xkb_keymap` set on the wlroots seat keyboard. The greeter login screen has its own scancode-to-ASCII map covering US, UK, French (AZERTY), German/Swiss (QWERTZ) and Spanish; other layouts fall back to US (letters and digits stay correct on any QWERTY layout). |
| Multitouch / pen input (MS-RDPEI) | ✓ | The worker opens the `Microsoft::Windows::RDS::Input` dynamic channel, sends SC_READY, and on the client's CS_READY receives touch and pen frames; the contacts (id, x, y, flags, pressure) are forwarded to the session as `RDP_BE_INPUT_TOUCH`.  The channel reassembly uses its own buffer so a fragmented touch packet cannot corrupt an interleaved GFX or audio frame.  On the Wayland backend the contacts drive a real `wl_touch` device (`wlr_seat` touch down/motion/up), so multi-finger gestures and pen reach the session apps.  On Xvfb (the default) and Xorg DDX there is no virtual multitouch device, so the primary contact is emulated as a single left pointer via XTEST.  In `-D` DDX mode touch is not forwarded.  Offered to every client that opens the channel. |
| Color mouse-cursor forwarding | ✓ | The real session cursor is captured from the session X server via XFixes and forwarded to the client as a fast-path New Pointer (32bpp ARGB) update, gated on the client's pointer caps.  Large-pointer clients receive cursors up to roughly 60x60 (the single fast-path PDU limit); other clients get the cursor nearest-neighbour scaled to fit 32x32.  The hotspot is scaled to match, and larger cursors are scaled down.  A cursor identical to one already sent is transmitted as a Cached Pointer Update referencing the client's pointer cache instead of re-sending the bitmap, bounded by the client's advertised pointer cache size.  Clients without color-pointer support keep the default system pointer. |
| Server-painted greeter + PAM/bsd_auth | ✓ | |
| Per-user Xvfb + xterm session | ✓ | |
| Client time zone redirection | ✓ | The `TS_TIME_ZONE_INFORMATION` from the Client Info PDU is decoded into a POSIX `TZ` string (the angle-bracket numeric form plus `Mm.w.d` DST rules, e.g. `<-05>5<-04>4,M3.2.0/2,M11.1.0/2`), passed to the session over the spawn channel, and exported into the session environment so the session clock and apps show the client's local time.  Self-contained: no Windows-to-IANA table, faithful to exactly what the client sent. |
| CLIPRDR clipboard, bidirectional, text + HTML + image + file formats | ✓ | `HTML Format` mapped to X `text/html`; `CF_DIB`/`CF_DIBV5` mapped to X `image/bmp`; files mapped to X `text/uri-list` via `FileGroupDescriptorW` + `FILECONTENTS`, both directions. |
| RemoteApp / seamless windows (MS-RDPERP / RAIL) | ✓ | Client-driven via the `INFO_RAIL` flag (xfreerdp `/app:...`, mstsc `remoteapplicationmode:i:1`); no server flag.  The server advertises the RAIL + WINDOW caps, opens the `rail` channel, runs the handshake, acks Execute, and emits Window Information Orders (new / size / delete).  On the Wayland backend (`-W`) each toplevel is a separate seamless window at its own cascade position; on Xvfb the whole desktop is one seamless window.  The order encoding is byte-validated against the FreeRDP decoder by the `rail` regress; live end-to-end rendering against xfreerdp `/app` and mstsc is being verified. |
| Clean disconnect, Shutdown Request, TCP keepalive | ✓ | When the session backend exits, the server sends a Set Error Info PDU (logged-off) so the client shows a reason instead of a silently dropped connection; the same PDU reports a server-denied reason when a session cannot be started.  To a client that advertises `RNS_UD_CS_SUPPORT_HEARTBEAT_PDU` the server sends a Heartbeat PDU every 30 seconds on the MCS message channel, so an idle session is not dropped by the client's connection-health check. |
| Output suppression (Suppress Output / Refresh Rect) | ✓ | When the client minimizes it sends `SUPPRESS_OUTPUT`; the server then drains backend frames without encoding or sending them, saving CPU and bandwidth on a backgrounded session, and resumes on the next allow-updates or `REFRESH_RECT`. |
| NLA / CredSSP / NTLMv2 | ✓ | Full CredSSP v6 flow with NTLMv2 verification.  NT hashes are auto-cached by the session manager on first successful authentication, so no manual setup is needed.  Microsoft clients (mstsc, macOS, Android) connect via NLA directly.  Credentials are extracted from TSPasswordCreds and verified via PAM/bsd_auth. |
| RDPGFX / H.264 (AVC420, AVC444) | ✓ | `rdp-session` sends raw frames over the backend socket; the `rdpd` worker encodes them with libx264 and wraps the bitstream in RDPGFX AVC420 WireToSurface1 PDUs.  CapsAdvertise negotiation selects the best AVC-capable version the client supports (v10.x preferred, v8.1 fallback).  FrameAcknowledge flow control prevents overwhelming the client decoder.  xfreerdp, which advertises v8.1 with AVC420_ENABLED, is always offered AVC.  Microsoft clients (mstsc, macOS Windows App) advertise AVC only by omitting AVC_DISABLED from a v10.x capset; offering them AVC is opt-in via `rdpd -V` and off by default, because such a client may advertise AVC yet be unable to decode it (for example a Microsoft client on a host with no GPU), in which case it tears down the graphics channel and ends the session rather than falling back.  With `rdpd -4` (which implies `-V`) the server offers AVC444 to those same v10.x AVC clients in place of AVC420: full 4:4:4 chroma is carried in a second H.264 stream (RFX_AVC444_BITMAP_STREAM, codec 0x000E), so coloured text and thin high-contrast edges stay sharp where AVC420's 4:2:0 chroma subsampling blurs them, at roughly twice the encode cost.  When AVC is not offered the client is served fast-path bitmap.  Fragmented DRDYNVC messages are reassembled. |
| Network auto-detection (MS-RDPBCGR) | ✓ | With `rdpd -N` (off by default) the server runs connect-time Network Characteristics Detection on the MCS message channel after the Client Info PDU: an RTT Measure Request round-trip, then a Bandwidth Measure Start/Payload/Stop burst whose result the client times back.  The measured bandwidth caps the libx264 peak bitrate (85% of the link, clamped to 1-30 Mbps) so the constant-quality stream cannot overrun a slow WAN link, while a fast link is allowed a higher ceiling.  Gated on the client advertising `RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT`. |
| Audio output (RDPSND / MS-RDPEA) | ✓ | PCM 16-bit stereo 44.1 kHz streamed via SNDC_WAVE2 PDUs; also advertises G.711 A-law, and with `rdpd -W` prefers A-law (half the wire bandwidth) when the client supports it.  PulseAudio on Linux (auto-creates a per-session null sink), sndio on OpenBSD.  Audio from apps playing in the session is captured and forwarded to the RDP client in real time. |
| Audio input / microphone (MS-RDPEAI) | ✓ | The worker opens the `AUDIO_INPUT` dynamic virtual channel and runs the SNDIN negotiation (Version, Formats, Open), offering PCM 16-bit stereo 44.1 kHz; the client's captured microphone PCM arrives as SNDIN Data PDUs and is forwarded to the session as `RDP_BE_AUDIO_INPUT` chunks (bounded at 64 KiB).  On Linux `rdp-session` presents that PCM as a real capture source named `rdp_microphone` (a PulseAudio `module-pipe-source` it loads and feeds over a per-session FIFO), so applications in the session can select the client's microphone as their input.  The `AUDIO_INPUT` reassembly uses its own buffer so a fragmented microphone packet cannot corrupt an interleaved GFX frame.  A client that does not redirect a microphone simply produces no data; the source is best-effort and a missing PulseAudio never breaks the session.  Offered by default; suppress with `rdpd -m`. |
| Camera redirection (MS-RDPECAM) | ✓ | With `rdpd -C` (off by default, since a camera is privacy-sensitive) the worker opens the `RDCamera_Device_Enumerator` control channel, agrees a protocol version, and when the client announces a camera opens a per-device channel and drives it: ActivateDevice, StreamList, MediaTypeList, then it selects an uncompressed format (NV12, I420, YUY2 or RGB) whose frame fits the channel, starts the stream, and pulls frames one credit at a time (a SampleRequest per SampleResponse).  Each frame is forwarded to the session as an `RDP_BE_CAMERA` message and written, without decoding, to a v4l2loopback `/dev/videoN` output device, so applications in the session see the client's webcam.  A camera unplug closes the device channel so a replug re-opens it, and an oversized or malformed device name is rejected.  The camera channels each reassemble fragmented PDUs with their own buffer so an interleaved GFX frame cannot corrupt an in-progress video frame.  Best-effort: `v4l2loopback` must be provisioned on the host (the pledged session cannot `modprobe`), and with no loopback device present the session runs normally without a virtual camera.  Off by default; enable with `rdpd -C`.  The MS-RDPECAM wire format is validated byte for byte against the FreeRDP reference and the full negotiation is unit-tested; a live end-to-end frame test is pending a host with `v4l2loopback`. |
| Persistent bitmap cache (MS-RDPBCGR) | ✓ | With `rdpd -B` (off by default) the server advertises the Bitmap Cache Host Support capability (the server-to-client cap; the Rev2 cap is client-to-server and is never sent by a server) and ingests the client's Persistent Key List PDU at connect, pre-seeding the slots the client already holds on disk.  The cached-tile drawing orders are sent only to a client that announced both MemBlt order support and a Bitmap Cache Rev2 cap in its Confirm Active; a client whose bitmap cache is off is served the compressed bitmap updates instead, so it is never sent orders it would reject.  On the fast-path bitmap path each 64x64 tile is keyed (FNV-1a) and looked up in the per-connection cache: a hit recalls the cached tile with a MemBlt drawing order alone; a miss stores it with a Cache Bitmap Rev2 secondary order (interleaved RLE compressed, falling back to nothing larger than the raw tile) before the MemBlt blits it, both carried in one fast-path Orders update.  The three caches hold 120, 120 and 336 slots; a miss prefers an empty slot so persistent entries survive until the cache is full, then evicts round-robin.  This saves re-sending repeated tiles (window chrome, text, backgrounds) on the legacy bitmap path and has no effect on a GFX or AVC session, which never reaches this path.  Verified live against xfreerdp (cache hit/miss orders decoded and rendered correctly); the encodings are also byte-validated against the FreeRDP reference (order, bmpcache and bitmap_rle regress). |
| Drive / printer / serial redirection | ✓ | RDPDR channel with capability exchange, device enumeration, and IRP dispatch for drive file I/O.  Supports Create, Read, Write, Close, QueryDirectory, QueryInformation, and SetInformation IRPs with completion tracking.  The session can request file operations on client drives via the backend protocol; the worker relays them as IRPs and forwards completions back.  On Linux the announced client drives are presented inside the session as a real file system at `~/RemoteDrive` via a raw `/dev/fuse` mount (no libfuse dependency): `rdp-sessionmgr` opens `/dev/fuse` and mounts it before dropping privileges, and `rdp-session` speaks the FUSE kernel protocol on the inherited fd, translating browse, read, write, and namespace operations (lookup, getattr, setattr, opendir, readdir, open, read, write, create, mknod, mkdir, unlink, rmdir, rename) into RDPDR IRPs.  File metadata (real size and timestamps) is fetched with QueryInformation; writing, truncating, and timestamp updates are forwarded with Write and SetInformation, so the mount is read-write.  Creating files and directories opens them with disposition FILE_CREATE; deleting opens with DELETE and FILE_DELETE_ON_CLOSE then sets FileDispositionInformation; renaming sets FileRenameInformation (same-device only, cross-device rename returns EXDEV so the kernel falls back to copy plus delete).  The mount is torn down when the session process exits.  This Linux backend has been validated against a live mount (stat, ls, cat, write/read-back, mkdir, and unlink over a real `/dev/fuse` mount), in addition to the protocol-level unit test.  OpenBSD has a second wire backend that speaks the kernel's own `fusebuf` protocol on `/dev/fuse0` (correlated by uuid, native `struct stat` attributes and directory records) and reuses the same protocol-agnostic core, so the same read and write operations are supported there.  Because `mount(2)`/`unmount(2)` are root-only and forbidden by `pledge`, `rdp-sessionmgr` forks an unpledged root mount-helper at startup (before pledging and before dropping privileges); the pledged daemon delegates each per-session mount/unmount to it over a socketpair with a single fixed-size request struct and receives the `/dev/fuse0` descriptor back via `SCM_RIGHTS`.  The helper creates the mountpoint with `O_NOFOLLOW`/`O_DIRECTORY` and mounts it by an `fchdir`-pinned `"."` so a user-planted symlink cannot redirect a root mount.  The OpenBSD device cannot be made non-blocking and has no `poll` support, so the backend gates each read on an `EVFILT_READ` kqueue probe and reads one `fusebuf` per wakeup.  This backend has been validated against a live OpenBSD mount (stat, ls, cat, and write/read-back over a real `fusefs`), in addition to the protocol-level unit test.  On macOS the FUSE path compiles to a no-op and drive operations remain available only through the backend protocol.  **Printer redirection** exposes each client-redirected printer (announced over RDPDR) as a CUPS print queue inside the session: when the worker sees a printer device it forwards the parsed name and driver to `rdp-session`, which sanitizes the name into a CUPS queue name (`rdp-` prefix, with non `[A-Za-z0-9_-]` characters mapped to `_`) and runs `lpadmin` to create a RAW queue whose device URI points at a per-session `AF_UNIX` socket.  A tiny dependency-free CUPS backend, `rdp-cups-backend`, is invoked by the system cupsd for each job: it reads the spool, connects to the session socket, and forwards the bytes.  `rdp-session` reads the spool off that socket (bounded at 4 MiB) and relays it to the worker as an `RDP_BE_PRINT_JOB`, which drives the MS-RDPEPC IRP sequence to print on the client's printer.  Printer redirection is strictly best-effort: if `lpadmin` is missing or a queue cannot be created (for example the session user is not a CUPS administrator), it is logged and skipped and the session is unaffected.  Queues are removed and the socket unlinked when the session exits.  This has been validated end to end against a live cupsd (queue created, a file printed with `lp`, and the spool received by the worker with the right device id and bytes). |
| Session reconnect (auto-reconnect cookie) | ✓ | Save Session Info PDU with ARC cookie, sessmgr SUSPEND/RESUME ops with fd passing.  Sessmgr retains a dup of the backend fd at spawn time and auto-suspends on worker death, so sessions survive worker SIGKILL.  Dead fds are validated at resume and reaped by sweep.  Once the session activates the server also sends a TS_LOGON_INFO_VERSION_2 logon notification carrying the session id, domain, and user name. |
| Dynamic resize (RDPEDISP via DRDYNVC) | ✓ | xfreerdp with `/dynamic-resolution`: the server opens the Display Control channel (MS-RDPEDISP) and advertises its monitor limits (DISPLAYCONTROL_CAPS), then on a client layout request sends Deactivate-All + re-Demand-Active at new geometry and rdp-session resizes Xvfb via xrandr. Apps survive the resize. On a GFX (AVC420/Progressive) session the RDPGFX surface is recreated at the new size (RESET_GRAPHICS + CreateSurface + MapSurface, with a fresh keyframe) so the accelerated output tracks the resize. |
| Multi-monitor | ✓ | Parses CS_MONITOR from the GCC handshake, computes bounding box across up to 16 monitors.  RDPEDISP handles dynamic monitor layout changes mid-session.  The session runs at the combined resolution. |
| Native Xorg DDX driver | ✓ | `rdpserverdev_drv.so` renders to a POSIX shm framebuffer inside Xorg, reports dirty regions via the Damage extension over a control socket.  rdp-session mmaps the framebuffer and sends only changed regions to rdpd.  Use `-D` flag to select DDX mode instead of Xvfb. |
| Wayland backend | ✓ | wlroots-based headless compositor with xdg_shell, embedded in rdp-session via `-W` flag.  Wayland-native apps connect directly; framebuffer captured from client surface buffers.  Requires libwlroots 0.18+. |

## Supported clients

The protocol is the standard one (MS-RDPBCGR, MS-RDPECLIP), so any
RDP client should work.  Live-tested against:

| Client | Notes |
| --- | --- |
| `xfreerdp` (FreeRDP 3.x) | Primary test client.  `xfreerdp /v:host:3389 /cert:ignore /size:1024x768 +clipboard /sec:nla`. |
| Microsoft `mstsc.exe` (Windows 11) | Verified working via NLA.  Served fast-path bitmap by default; RDPGFX AVC (v10.x) is available with `rdpd -V` for hosts whose clients have a working H.264 decoder. |
| Microsoft Remote Desktop (macOS) | Verified working via NLA.  Connects directly without greeter. |
| Microsoft Remote Desktop (Android) | Verified working via NLA. |
| Remmina | Uses FreeRDP under the hood; should work. |
| `rdesktop` (legacy) | Older PDU shapes; not yet exercised. |

## Acceleration conditions

Graphics are sent as H.264 / AVC420 frames over the RDPGFX graphics pipeline when the client negotiates it; otherwise the server falls back to fast-path bitmap updates.  Whether AVC is offered depends on what the client advertises in its GFX `CapsAdvertise` and on the `rdpd -V` flag:

| Client GFX advertise | `rdpd -V` | Server offers | Result |
| --- | --- | --- | --- |
| v8.1 with `AVC420_ENABLED` (xfreerdp) | off or on | AVC420 (always) | H.264 accelerated |
| v10.x without `AVC_DISABLED` (mstsc, macOS) | off (default) | nothing | fast-path bitmap |
| v10.x without `AVC_DISABLED` (mstsc, macOS) | on | AVC420 (v10.2) | accelerated only if the client can decode H.264 |
| v10.x with `AVC_DISABLED` (e.g. Android) | off or on | nothing | fast-path bitmap |
| no GFX channel advertised | n/a | n/a | fast-path bitmap |

`xfreerdp` sets the v8.1 `AVC420_ENABLED` flag, so it is always offered AVC.  Microsoft clients (mstsc, macOS) signal AVC only by omitting `AVC_DISABLED` from a v10.x capset; offering them AVC is opt-in via `rdpd -V` and **off by default**.  A v10.x client can advertise AVC yet be unable to decode it (for example a Microsoft client on a host with no GPU), in which case it tears down the graphics channel with a `0xd06` error and ends the session instead of falling back to bitmap.  With the default off, those clients get bitmap and render normally; only xfreerdp, which keeps the session alive when the GFX channel closes, recovers gracefully when AVC is declined mid-session.

Whichever version is chosen, the server confirms only a version the client actually advertised, and only after its libx264 encoder opens.  If no advertised version is usable, or the encoder cannot start, it sends no `CapsConfirm` and the client falls back to bitmap rather than waiting for frames that never arrive.  The `CapsConfirm` carries the capsData length the confirmed version requires (16 bytes for v10.1, 4 bytes for every other version), matching the Windows and FreeRDP servers.

`rdpd -4` upgrades the AVC offered to v10.x clients from AVC420 (4:2:0 chroma) to **AVC444** (full 4:4:4 chroma).  AVC444 keeps the main 4:2:0 H.264 stream and adds a second H.264 stream carrying the chroma samples 4:2:0 throws away (`RFX_AVC444_BITMAP_STREAM`, codec id `0x000E`), which the client recombines into 4:4:4.  The win is sharp coloured text and thin high-contrast edges, which 4:2:0 chroma subsampling blurs; the cost is roughly double the encode work and bandwidth.  It applies to exactly the same v10.x clients as `-V` and so implies it; xfreerdp gets AVC444 too when it advertises a v10.x capset.  Off by default.

As an alternative to AVC, `rdpd -P` offers **RFX Progressive** (MS-RDPEGFX `RFX_PROGRESSIVE`) to GFX-capable clients that are not given AVC.  It is a CPU-decodable wavelet codec that needs no client GPU (the same codec the Microsoft server uses for its GPU-less sessions), so it can accelerate mstsc, macOS, and Android clients without the `0xd06` teardown.  Off by default; the per-frame WireToSurface2 codec id selects it, so enabling it never changes clients that receive AVC.

For an accelerated session to work end to end:

- The server encodes with **libx264** on the CPU; there is no GPU encode path.  Frames are rounded to even dimensions for 4:2:0.  The bitstream is pinned to H.264 **Main profile** (CABAC entropy coding) to match the Windows server.
- Large keyframes (GFX PDUs over 64 KB) are split into ZGFX multipart segments, without which the client decoder tears down the channel.
- The first frame to a freshly created RDPGFX surface is forced to an IDR keyframe (rather than waiting for the periodic 60-frame keyframe), so the client never has to decode a P-frame referencing surface data it discarded on reset.
- The client must have a working H.264 decoder.  `xfreerdp` uses libavcodec (and can GPU-decode via VA-API/VDPAU/NVDEC or VideoToolbox); Microsoft clients need a GPU decoder.

See [`rdpd(8)`](./docs/man/rdpd.8) for the `-V` flag.

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

### CUPS printer backend

Printer redirection needs the small `rdp-cups-backend` helper (built by
`make` as `src/session/rdp-cups-backend`) installed into the system cupsd
backend directory.  `make install` does **not** do this, because that
directory is root owned and outside `$(PREFIX)`; install it by hand,
root owned and mode 0755:

```sh
sudo install -o root -g root -m 0755 \
    src/session/rdp-cups-backend /usr/lib/cups/backend/rdp
```

(On OpenBSD the directory is `/usr/local/libexec/cups/backend`.)  Two
deployment requirements for redirection to actually create queues and
print:

  * The session user must be allowed to add CUPS queues, i.e. be a member
    of the CUPS `SystemGroup` (commonly `lpadmin`); otherwise `lpadmin`
    returns *Forbidden* and redirection is skipped (the session is
    unaffected).
  * A system cupsd runs print backends as the `lp` user, not the session
    user, so the per-session print socket must live somewhere that user
    can reach.  The module places it in `$XDG_RUNTIME_DIR` when that is
    set, falling back to `$TMPDIR` then `/tmp`, and creates the socket
    mode 0666; a private `$XDG_RUNTIME_DIR` (mode 0700) blocks the `lp`
    backend, so for a system cupsd use a runtime dir reachable by `lp`
    (or a per-user cupsd).

Without the backend installed, jobs queue but never reach the client; the
rest of the session is unaffected.

### Dependencies

| | Linux | OpenBSD | macOS |
| --- | --- | --- | --- |
| TLS | OpenSSL 1.1+/3.x | LibreSSL (base) | `brew install openssl@3` |
| Auth | libpam | bsd_auth (base + `-lutil`) | PAM (system) |
| X11 | `libx11-dev`, `libxdamage-dev`, `libxtst-dev`, `libxfixes-dev`, `libxext-dev` | base X11 (`/usr/X11R6`) | XQuartz (`/opt/X11`) |
| H.264 | `libx264-dev` | `pkg_add x264` | `brew install x264` |
| X server | `xvfb` | `xvfb` package (or base) | XQuartz |
| Audio (optional) | `libpulse-dev` | sndio (base) | CoreAudio (system) |
| DDX driver (optional) | `xserver-xorg-dev` | Xorg SDK | XQuartz SDK |

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
Systemd unit files are in
[`contrib/systemd/`](./contrib/systemd/)
and OpenBSD rc.d scripts in
[`contrib/rc.d/`](./contrib/rc.d/).

## Project layout

```
src/include/      public headers + backend vtable + generated config.h
src/common/       buffers, I/O, log, mem, rand, str, utf16, BER, PER
src/wire/         RDP wire protocol: tpkt, x224, mcs, sec header,
                  license, capset, share-control PDUs, fast-path
src/sec/          TLS (OpenSSL/LibreSSL); NLA framework (cssp, ntlm,
                  nla_crypto, nla)
src/channels/     CLIPRDR, DRDYNVC, RDPSND, RDPGFX
src/ddx/          native Xorg DDX video driver module
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
diagnostics.  The fuzzer has logged millions of random-byte iterations
across the 10 parsers (tpkt, x224, ber, per, mcs, cliprdr, fp_input,
cssp, ntlm, rdpgfx) under ASan + UBSan without a single crash.

## Security model

See [`docs/SECURITY.md`](./docs/SECURITY.md) for the trust model,
process layout, `pledge` promise sets, and the explanation of why NLA
is currently a framework-only feature.

The NLA token file (`.tok`) is opened with `O_EXCL` to prevent
creation races, unlinked immediately after open to prevent a second
worker from reading the same token, and protected by a random 16-byte
nonce that must be presented with the `NLA_AUTH` session manager
command. The NTLM challenge timestamp is written in little-endian
byte order for correctness on big-endian hosts. The seccomp-bpf
sandbox allowlists `unlinkat` and `renameat` for token file cleanup.
AV pair construction and sealed-message buffers are bounds-checked
to prevent stack overflows.

`rdp-sessionmgr` rate-limits failed authentication per source IP: after
5 failures within 60 seconds, further attempts from that IP are
rejected without touching the auth backend until the window passes, and
a successful login clears the counter. Because every worker
authenticates through the one session manager, the limit is enforced
centrally across all connections. The worker passes the client IP to
the manager in the AUTH request.

## Contributing

Bug reports and patches welcome via
[GitHub Issues](https://github.com/renaudallard/rdpserver/issues)
and pull requests.  Security issues: email `renaud@allard.it`
directly; do not file a public issue.

## License

BSD 2-Clause.  See [`LICENSE`](./LICENSE).  The full text is also
stamped at the top of every `.c` and `.h` source file.
