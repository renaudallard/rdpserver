# rdpserver roadmap

This document tracks what is done and what is left.  See also
`/home/r/.claude/plans/make-a-plan-to-nested-anchor.md` for the
original architectural plan.

## Done

### Phase 0 — Skeleton

- `configure` script probes libtls/openssl, pam/bsd_auth, getrandom/
  arc4random, epoll/kqueue, strlcpy/reallocarray/explicit_bzero, and
  the OpenBSD/FreeBSD safety primitives (pledge/unveil/capsicum).
- `Makefile` + `GNUmakefile` build with `-Werror -Wall -Wextra
  -Wshadow -Wstrict-prototypes -fstack-protector-strong`.
- `src/common/`: buf, io, log, mem, rand, str, utf16, ber, per.
- `src/wire/`: tpkt, x224, mcs, sec, license, capset, rdp_pdu,
  fastpath, input.
- `src/sec/`: tls (OpenSSL wrapper with self-signed cert generation).
- `src/daemon/`: rdpd (accept + fork worker), conn (state machine).
- Man pages, regress harness, integration test.

### Phase A — "It connects"

Implemented and verified via `regress/integ/connect_test.py`:

- TPKT framing (RFC 1006).
- X.224 Class 0 CR/CC + RDP_NEG_REQ / RDP_NEG_RSP.
- TLS server-side handshake with self-signed cert.
- MCS Connect Initial parse (extracts desktop dimensions and
  channel list) and Connect Response build.
- Erect Domain → Attach User → Channel Join sequence.
- Client Info PDU parse (Security header + INFO_PACKET).
- License "Valid Client" PDU emit.
- Demand Active build (all mandatory capability sets present,
  drawing orders zeroed, GLYPH_SUPPORT_NONE, Bitmap rev2 empty,
  Multifragment 0xFFFF, LargePointer 96x96).
- Confirm Active parse.
- Finalization handshake: Synchronize, Control Cooperate, Granted
  Control, Font Map.

### Phase B — basic frame output

- Fast-Path Bitmap Update encoder (24bpp raw, bottom-up rows, 4-px
  width padding, 64×64 tiling).  Solid teal background painted after
  activation.
- Fast-Path Synchronize and System Pointer Default.

### Phase C — basic input

- Fast-Path Input parser (scancode, mouse, MouseX, sync, Unicode).
- Input events logged at debug level.
- Slow-path PDUTYPE2_INPUT accepted and discarded.

### Phase H (partial) — clean disconnect

- MCS Disconnect Provider Ultimatum inbound and outbound.
- Worker exits cleanly on disconnect.

## Not yet done

### Phase D — greeter (skeleton in `src/greeter/`)

The greeter is the user-visible "Windows-style login" deliverable.
Until it exists, the daemon paints a solid colour and logs input.
What's left:

- Embed a bitmap font (Spleen 8×16; check OpenBSD-friendly licence).
- Glyph rendering via `MultiOpaqueRect`.
- Dialog layout: full-screen background, centred panel, username
  and password edit fields, login button, status line.
- Keymap tables: US, GB, DE, FR, BE, NL, ES, IT, JP (LCID → xkb).
- State machine INIT → TYPING_USER → TYPING_PASS → SUBMITTING →
  (OK | FAIL) → DONE.
- Password buffer mlock + explicit_bzero on transition.

### Phase E — sessionmgr (skeleton in `src/sessionmgr/`)

Privileged session broker daemon.

- AF_UNIX seqpacket socket at `/var/run/rdpserver/sessmgr.sock`.
- Two ops: `AUTH user pass`, `SPAWN uid`.
- PAM (Linux/FreeBSD/NetBSD) or `auth_userokay(3)` (OpenBSD).
- `pam_open_session` with pam_systemd on Linux; setusercontext on
  the BSDs.
- Token-bucket rate limit on failed auth.

### Phase F — rdp-session (skeleton in `src/session/`)

Per-user helper, unprivileged.

- Spawn Xvfb on a free DISPLAY.
- XDamage + XShm capture loop.
- XTest input injection.
- Spawn `~/.xsession` or xterm fallback.
- Backend RPC framing (the side that pairs with daemon/backend_client).

### Phase G — CLIPRDR (skeleton in `src/channels/cliprdr.c`)

- CHANNEL_PDU_HEADER reassembly.
- CLIPRDR PDUs: Monitor Ready, Clip Caps, Format List/Response,
  Format Data Request/Response.
- X11 bridge via XFixes selection-notify on CLIPBOARD.
- v1 formats: CF_UNICODETEXT, CF_TEXT, CF_OEMTEXT.

### Phase I — hardening sweep

- Build under ASan/UBSan/MSan in CI.
- 24 CPU-hours of libFuzzer per parser (tpkt, x224, mcs, per, ber,
  cliprdr, glyph_cache, eventually cssp/ntlm).
- Multi-OS CI matrix: Linux glibc + musl, OpenBSD-current, FreeBSD
  14, NetBSD 10.
- `pledge`/`unveil` on OpenBSD; `cap_enter` on FreeBSD; seccomp-bpf
  allow-list on Linux.

### Phase J — NLA (skeleton in `src/sec/nla.c`)

- CredSSP TSRequest (DER).
- SPNEGO selecting NTLMSSP.
- NTLMv2 NEGOTIATE/CHALLENGE/AUTHENTICATE.
- After TSPasswordCreds decrypts, hand cleartext to sessionmgr.
- `pubKeyAuth` step enforced.

### Beyond v1

- Native `xrdpdev`-style Xorg DDX module for direct framebuffer
  access (no Xvfb shadow).
- Wayland backend (embedded compositor or PipeWire-based).
- Audio (MS-RDPEA).
- Drive/printer/serial redirection.
- RemoteFX / RDPGFX with H.264.
- Multi-monitor.
- Dynamic resize.
- Session reconnect / disconnect-and-reattach.

## Testing

Unit tests run via `make regress`.  The integration test
`regress/integ/connect_test.py` drives the daemon through CR/CC,
TLS handshake, MCS Connect Initial/Response, Attach User Confirm,
and one Channel Join Confirm.  Live interop testing against
`xfreerdp` and `mstsc.exe` is the next verification milestone but
requires those clients (not installed on the current dev box).
