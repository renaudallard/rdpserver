# rdpserver Makefile (POSIX / bmake compatible).
#
# Reads config.mk written by ./configure.  Run ./configure first.

.SUFFIXES: .c .o

include config.mk

# Common library objects.
COMMON_OBJS = \
	src/common/buf.o \
	src/common/io.o \
	src/common/log.o \
	src/common/mem.o \
	src/common/rand.o \
	src/common/str.o \
	src/common/utf16.o \
	src/common/ber.o \
	src/common/per.o

COMMON_LIB = src/common/libcommon.a

# Wire library objects.
WIRE_OBJS = \
	src/wire/tpkt.o \
	src/wire/x224.o \
	src/wire/mcs.o \
	src/wire/sec.o \
	src/wire/license.o \
	src/wire/capset.o \
	src/wire/rdp_pdu.o \
	src/wire/fastpath.o \
	src/wire/input.o \
	src/wire/h264enc.o \
	src/wire/progressive.o

WIRE_LIB = src/wire/libwire.a

# Security library objects.  NLA pieces (cssp, ntlm, nla_crypto, nla)
# are always compiled so the parsers stay code-reachable; the
# negotiate-time advertise of PROTOCOL_HYBRID is gated by an rdpd
# flag instead.
SEC_OBJS = src/sec/tls.o \
	src/sec/nla.o \
	src/sec/nla_crypto.o \
	src/sec/ntlm.o \
	src/sec/cssp.o
SEC_LIB  = src/sec/libsec.a

# Greeter objects.
GREETER_OBJS = \
	src/greeter/font.o \
	src/greeter/keymap.o \
	src/greeter/paint.o \
	src/greeter/greeter.o

GREETER_LIB = src/greeter/libgreeter.a

# Sessionmgr backend object is chosen by configure (writes SESSMGR_AUTH_OBJ
# into config.mk based on whether PAM or bsd_auth was detected).
SESSMGR_CLIENT_OBJ = src/sessionmgr/client.o
SESSMGR_DAEMON_OBJ = src/sessionmgr/sessionmgr.o $(SESSMGR_AUTH_OBJ)

# Static virtual channels.
CHANNELS_OBJS = src/channels/cliprdr.o src/channels/drdynvc.o src/channels/rdpsnd.o \
	src/channels/rdpgfx.o src/channels/rdpdr.o
CHANNELS_LIB  = src/channels/libchannels.a

# Backend RPC: shared between rdpd worker and rdp-session.
BACKEND_OBJS = src/backend/proto.o
BACKEND_LIB  = src/backend/libbackend.a

# Per-user session helper (X11).  The drive redirection core (fuse_drive.o)
# is always linked; the wire backend object (FUSE_BACKEND_OBJ) is the Linux
# raw /dev/fuse one, the OpenBSD fusebuf one, or empty, as configure chose.
SESSION_OBJS = src/session/rdp_session.o src/session/clip_x11.o \
	src/session/fuse_drive.o $(FUSE_BACKEND_OBJ) \
	$(WAYLAND_OBJ) $(AUDIO_OBJ)
SESSION_PROG = src/session/rdp-session

# Daemon objects.
RDPD_OBJS = src/daemon/rdpd.o src/daemon/conn.o src/daemon/sandbox.o $(SESSMGR_CLIENT_OBJ) \
	$(BACKEND_OBJS) $(CHANNELS_OBJS)

PROGS = src/daemon/rdpd src/sessionmgr/rdp-sessionmgr $(SESSION_PROG)

REGRESS_PROGS = \
	regress/common/buf_test \
	regress/common/io_test \
	regress/common/str_test \
	regress/common/utf16_test \
	regress/common/ber_test \
	regress/common/per_test \
	regress/wire/tpkt_test \
	regress/wire/x224_test \
	regress/wire/mcs_test \
	regress/wire/capset_test \
	regress/wire/rdp_pdu_test \
	regress/wire/rdpdr_test \
	regress/wire/cliprdr_test \
	$(FUSE_REGRESS) \
	$(OBSD_FUSE_REGRESS)

FUZZ_PROG = regress/fuzz/fuzz_parsers

# DDX video driver module (optional, needs xorg-server SDK).
DDX_OBJS = src/ddx/rdpserverdev.o
DDX_SO   = src/ddx/rdpserverdev_drv.so

all: $(PROGS) $(DDX_TARGET)

$(COMMON_LIB): $(COMMON_OBJS)
	ar rcs $@ $(COMMON_OBJS)

$(WIRE_LIB): $(WIRE_OBJS)
	ar rcs $@ $(WIRE_OBJS)

$(SEC_LIB): $(SEC_OBJS)
	ar rcs $@ $(SEC_OBJS)

$(GREETER_LIB): $(GREETER_OBJS)
	ar rcs $@ $(GREETER_OBJS)

src/wire/h264enc.o: src/wire/h264enc.c
	$(CC) $(CFLAGS) $(X264_CFLAGS) -c -o $@ src/wire/h264enc.c

src/daemon/rdpd: $(RDPD_OBJS) $(GREETER_LIB) $(WIRE_LIB) $(SEC_LIB) $(COMMON_LIB)
	$(CC) $(LDFLAGS) -o $@ $(RDPD_OBJS) \
		$(GREETER_LIB) $(WIRE_LIB) $(SEC_LIB) $(COMMON_LIB) \
		$(TLS_LIBS) $(X264_LIBS)

src/sessionmgr/rdp-sessionmgr: $(SESSMGR_DAEMON_OBJ) $(COMMON_LIB)
	$(CC) $(LDFLAGS) -o $@ $(SESSMGR_DAEMON_OBJ) $(COMMON_LIB) \
		$(AUTH_LIBS) $(TLS_LIBS)

$(BACKEND_LIB): $(BACKEND_OBJS)
	ar rcs $@ $(BACKEND_OBJS)

$(CHANNELS_LIB): $(CHANNELS_OBJS)
	ar rcs $@ $(CHANNELS_OBJS)

src/ddx/rdpserverdev.o: src/ddx/rdpserverdev.c
	$(CC) $(CFLAGS) $(XORG_CFLAGS) -fPIC -c -o $@ src/ddx/rdpserverdev.c

$(DDX_SO): $(DDX_OBJS)
	$(CC) -shared -o $@ $(DDX_OBJS)

src/session/wayland_comp.o: src/session/wayland_comp.c
	$(CC) $(CFLAGS) $(WLROOTS_CFLAGS) -Isrc/session/protocols -c -o $@ src/session/wayland_comp.c

src/session/rdp_session.o: src/session/rdp_session.c src/session/kbdmap.h
	$(CC) $(CFLAGS) $(X11_CFLAGS) $(X264_CFLAGS) -DRDP_XVFB_PATH=\"$(XVFB_PATH)\" \
		-c -o $@ src/session/rdp_session.c

src/session/clip_x11.o: src/session/clip_x11.c
	$(CC) $(CFLAGS) $(X11_CFLAGS) -c -o $@ src/session/clip_x11.c

$(SESSION_PROG): $(SESSION_OBJS) $(BACKEND_LIB) $(WIRE_LIB) $(COMMON_LIB)
	$(CC) $(LDFLAGS) -o $@ $(SESSION_OBJS) $(BACKEND_LIB) $(WIRE_LIB) $(COMMON_LIB) \
		$(X11_LIBS) $(X264_LIBS) $(AUDIO_LIBS) $(WLROOTS_LIBS)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

# Regress.  Each test program is a single .c linked with libcommon.
regress: $(REGRESS_PROGS)
	@fail=0; \
	for t in $(REGRESS_PROGS); do \
		printf 'regress: %s ... ' $$t; \
		if ./$$t >/dev/null 2>&1; then echo ok; \
		else echo FAIL; fail=1; ./$$t 2>&1 | sed 's/^/    /'; \
		fi; \
	done; \
	exit $$fail

regress/common/buf_test: regress/common/buf_test.o $(COMMON_LIB)
	$(CC) $(LDFLAGS) -o $@ regress/common/buf_test.o $(COMMON_LIB)

regress/common/io_test: regress/common/io_test.o $(COMMON_LIB)
	$(CC) $(LDFLAGS) -o $@ regress/common/io_test.o $(COMMON_LIB)

regress/common/str_test: regress/common/str_test.o $(COMMON_LIB)
	$(CC) $(LDFLAGS) -o $@ regress/common/str_test.o $(COMMON_LIB)

regress/common/utf16_test: regress/common/utf16_test.o $(COMMON_LIB)
	$(CC) $(LDFLAGS) -o $@ regress/common/utf16_test.o $(COMMON_LIB)

regress/common/ber_test: regress/common/ber_test.o $(COMMON_LIB)
	$(CC) $(LDFLAGS) -o $@ regress/common/ber_test.o $(COMMON_LIB)

regress/common/per_test: regress/common/per_test.o $(COMMON_LIB)
	$(CC) $(LDFLAGS) -o $@ regress/common/per_test.o $(COMMON_LIB)

regress/wire/tpkt_test: regress/wire/tpkt_test.o $(WIRE_LIB) $(COMMON_LIB)
	$(CC) $(LDFLAGS) -o $@ regress/wire/tpkt_test.o $(WIRE_LIB) $(COMMON_LIB)

regress/wire/x224_test: regress/wire/x224_test.o $(WIRE_LIB) $(COMMON_LIB)
	$(CC) $(LDFLAGS) -o $@ regress/wire/x224_test.o $(WIRE_LIB) $(COMMON_LIB)

regress/wire/mcs_test: regress/wire/mcs_test.o $(WIRE_LIB) $(COMMON_LIB)
	$(CC) $(LDFLAGS) -o $@ regress/wire/mcs_test.o $(WIRE_LIB) $(COMMON_LIB)

regress/wire/capset_test: regress/wire/capset_test.o $(WIRE_LIB) $(COMMON_LIB)
	$(CC) $(LDFLAGS) -o $@ regress/wire/capset_test.o $(WIRE_LIB) $(COMMON_LIB)

regress/wire/rdp_pdu_test: regress/wire/rdp_pdu_test.o $(WIRE_LIB) $(COMMON_LIB)
	$(CC) $(LDFLAGS) -o $@ regress/wire/rdp_pdu_test.o $(WIRE_LIB) $(COMMON_LIB)

# Built with ASan + UBSan (where the toolchain supports them, via
# $(TEST_SAN); empty on OpenBSD) to catch out-of-bounds in the IRP builders.
# rdpdr.o and the common log object are recompiled so the instrumentation
# covers the code under test.
regress/wire/rdpdr_test: regress/wire/rdpdr_test.c src/channels/rdpdr.c \
		src/common/log.c
	$(CC) $(CFLAGS) $(TEST_SAN) -Isrc/include \
		-o $@ regress/wire/rdpdr_test.c src/channels/rdpdr.c \
		src/common/log.c

# CLIPRDR channel reassembly test.  cliprdr.c is recompiled with the test;
# $(TEST_SAN) covers the attacker-controlled fragment-length bounds.
regress/wire/cliprdr_test: regress/wire/cliprdr_test.c src/channels/cliprdr.c \
		src/common/buf.c src/common/utf16.c
	$(CC) $(CFLAGS) $(TEST_SAN) -Isrc/include \
		-o $@ regress/wire/cliprdr_test.c src/channels/cliprdr.c \
		src/common/buf.c src/common/utf16.c

# Drive read-path FUSE protocol test.  The protocol agnostic core
# (fuse_drive.c) and the Linux raw /dev/fuse backend (fuse_drive_linux.c)
# are recompiled together with -DRDP_FUSE_TEST so the dispatch is callable
# on in-memory buffers; $(TEST_SAN) covers the untrusted FSCC/read decode
# where supported.
regress/wire/fuse_drive_test: regress/wire/fuse_drive_test.c \
		src/session/fuse_drive.c src/session/fuse_drive_linux.c \
		src/common/io.c src/common/log.c
	$(CC) $(CFLAGS) $(TEST_SAN) -DRDP_FUSE_TEST \
		-Isrc/include \
		-o $@ regress/wire/fuse_drive_test.c \
		src/session/fuse_drive.c src/session/fuse_drive_linux.c \
		src/common/io.c src/common/log.c

# Drive read and write fusebuf protocol test (OpenBSD).  The core (fuse_drive.c)
# and the OpenBSD fusebuf backend (fuse_drive_obsd.c) are recompiled together
# with -DRDP_FUSE_TEST so the dispatch is callable on in-memory buffers, the
# same way the Linux test works.  The OpenBSD toolchain ships no ASan/UBSan
# runtime, so the sanitizers the Linux rule uses are omitted here.
regress/wire/fuse_drive_obsd_test: regress/wire/fuse_drive_obsd_test.c \
		src/session/fuse_drive.c src/session/fuse_drive_obsd.c \
		src/common/io.c src/common/log.c
	$(CC) $(CFLAGS) -DRDP_FUSE_TEST \
		-Isrc/include \
		-o $@ regress/wire/fuse_drive_obsd_test.c \
		src/session/fuse_drive.c src/session/fuse_drive_obsd.c \
		src/common/io.c src/common/log.c

# Live validation of the OpenBSD fusebuf backend against the REAL kernel.
# NOT part of `regress` (it needs root and a working /dev/fuse0): build it by
# hand and run it under doas:
#   gmake regress/integ/obsd_fuse_live
#   doas ./regress/integ/obsd_fuse_live
# It links the drive core and the OpenBSD backend with a mock RDPDR FS, mounts
# a real fusefs at a temp dir, and drives stat/ls/cat/write over it.
regress/integ/obsd_fuse_live: regress/integ/obsd_fuse_live.c \
		src/session/fuse_drive.c src/session/fuse_drive_obsd.c \
		src/common/io.c src/common/log.c
	$(CC) $(CFLAGS) -Isrc/include \
		-o $@ regress/integ/obsd_fuse_live.c \
		src/session/fuse_drive.c src/session/fuse_drive_obsd.c \
		src/common/io.c src/common/log.c

# Live validation of the Linux raw /dev/fuse backend against the REAL kernel.
# NOT part of `regress` (it needs root and a working /dev/fuse): build it by
# hand and run it under sudo:
#   make regress/integ/linux_fuse_live
#   sudo ./regress/integ/linux_fuse_live
# It links the drive core and the Linux backend with a mock RDPDR FS, mounts a
# real fuse fs at a temp dir, and drives stat/ls/cat/write/mkdir/unlink over it.
# Built with -DRDP_FUSE_TEST (same as the unit test) so HAVE_FUSE is honoured.
regress/integ/linux_fuse_live: regress/integ/linux_fuse_live.c \
		src/session/fuse_drive.c src/session/fuse_drive_linux.c \
		src/common/io.c src/common/log.c
	$(CC) $(CFLAGS) -DRDP_FUSE_TEST -Isrc/include \
		-o $@ regress/integ/linux_fuse_live.c \
		src/session/fuse_drive.c src/session/fuse_drive_linux.c \
		src/common/io.c src/common/log.c

# Live validation of the X11 clipboard bridge (clip_x11.c) against a REAL X
# server (Xvfb) using the real xclip as the cooperating X client.  NOT part of
# `regress` (it spawns Xvfb): build it by hand and run it:
#   make regress/integ/clip_x11_live
#   ./regress/integ/clip_x11_live
# It links clip_x11.c with the backend framing and a harness that plays both
# the session main loop and the worker.  It exercises the size-robustness
# paths (bytes_after read loop, INCR reader, chunked PropModeAppend write) in
# both directions for small and ~1 MiB text.  xclip ships even 1 MiB directly
# (BIG-REQUESTS), so a dedicated case drives the INCR reader with the harness's
# own INCR selection owner.  Built with $(TEST_SAN) where the toolchain
# supports it so leaks/UAF/UB in the clipboard code are caught.
regress/integ/clip_x11_live: regress/integ/clip_x11_live.c \
		src/session/clip_x11.c src/backend/proto.c \
		src/common/io.c src/common/log.c
	$(CC) $(CFLAGS) $(TEST_SAN) $(X11_CFLAGS) -Isrc/include \
		-DXVFB_PATH=\"$(XVFB_PATH)\" \
		-o $@ regress/integ/clip_x11_live.c \
		src/session/clip_x11.c src/backend/proto.c \
		src/common/io.c src/common/log.c \
		$(X11_LIBS)

regress/fuzz/fuzz_parsers: regress/fuzz/fuzz_parsers.o \
		$(WIRE_LIB) $(CHANNELS_LIB) $(SEC_LIB) $(COMMON_LIB)
	$(CC) $(LDFLAGS) -o $@ regress/fuzz/fuzz_parsers.o \
		$(WIRE_LIB) $(CHANNELS_LIB) $(SEC_LIB) $(COMMON_LIB) \
		$(TLS_LIBS)

fuzz: $(FUZZ_PROG)
	@./$(FUZZ_PROG) all 5000

clean:
	rm -f $(COMMON_OBJS) $(COMMON_LIB)
	rm -f $(WIRE_OBJS) $(WIRE_LIB)
	rm -f $(SEC_OBJS) $(SEC_LIB)
	rm -f $(GREETER_OBJS) $(GREETER_LIB)
	rm -f $(SESSMGR_DAEMON_OBJ) $(SESSMGR_CLIENT_OBJ)
	rm -f src/sessionmgr/auth_pam.o src/sessionmgr/auth_bsdauth.o
	rm -f $(BACKEND_OBJS) $(BACKEND_LIB)
	rm -f $(CHANNELS_OBJS) $(CHANNELS_LIB)
	rm -f $(SESSION_OBJS) $(SESSION_PROG)
	rm -f $(RDPD_OBJS) $(PROGS)
	rm -f $(DDX_OBJS) $(DDX_SO)
	rm -f regress/common/*.o regress/wire/*.o $(REGRESS_PROGS)

distclean: clean
	rm -f config.mk src/include/config.h
	rm -rf tmp/configure.*

install: all
	mkdir -p $(DESTDIR)$(PREFIX)/sbin
	mkdir -p $(DESTDIR)$(MANDIR)/man5
	mkdir -p $(DESTDIR)$(MANDIR)/man8
	cp src/daemon/rdpd $(DESTDIR)$(PREFIX)/sbin/rdpd
	cp src/sessionmgr/rdp-sessionmgr $(DESTDIR)$(PREFIX)/sbin/rdp-sessionmgr
	cp docs/man/rdpd.8 $(DESTDIR)$(MANDIR)/man8/rdpd.8
	cp docs/man/rdpd.conf.5 $(DESTDIR)$(MANDIR)/man5/rdpd.conf.5
	cp docs/man/rdp-sessionmgr.8 $(DESTDIR)$(MANDIR)/man8/rdp-sessionmgr.8
	cp docs/man/rdp-session.8 $(DESTDIR)$(MANDIR)/man8/rdp-session.8

.PHONY: all clean distclean install regress
