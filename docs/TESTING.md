# Client Interop Testing

## Primary test client

`xfreerdp` (FreeRDP 3.x) is the primary test client:

    xfreerdp /v:host:3389 /cert:ignore /size:1024x768 +clipboard /drive:test,/tmp

All features are verified against xfreerdp on both Linux and OpenBSD.

## Additional clients to verify

### mstsc.exe (Windows 10/11)

    mstsc.exe /v:host:3389

Test checklist:
- [ ] TLS handshake completes
- [ ] NLA authentication works (requires rdp-passwd entry)
- [ ] Greeter displays and accepts credentials
- [ ] Desktop session starts with visible xterm
- [ ] Keyboard input (scancode mapping)
- [ ] Mouse input (click, move, scroll)
- [ ] Clipboard copy/paste bidirectional
- [ ] Dynamic resize on window resize
- [ ] Clean disconnect and reconnect

### Microsoft Remote Desktop (macOS / iOS / Android)

Same test checklist as mstsc.exe. Additionally verify:
- [ ] Touch input maps to mouse events (mobile)
- [ ] High-DPI scaling works (macOS Retina)

### Remmina (Linux)

Uses FreeRDP under the hood. Test:
- [ ] Connection via GUI with server address, user, password
- [ ] Clipboard integration
- [ ] Dynamic resolution

### rdesktop (legacy)

Older PDU shapes. May need compatibility:
- [ ] Basic TLS connection (no NLA)
- [ ] Greeter login
- [ ] Desktop display
- [ ] Keyboard and mouse

## Running tests

Start the server:

    doas ./src/sessionmgr/rdp-sessionmgr -f -d \
        -s /tmp/sessmgr.sock \
        -X $(pwd)/src/session/rdp-session

    ./src/daemon/rdpd -f -d -p 3389 -S /tmp/sessmgr.sock

Connect from each client and work through the checklist.
