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
	src/wire/input.o

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

# Static virtual channels (CLIPRDR for now).
CHANNELS_OBJS = src/channels/cliprdr.o
CHANNELS_LIB  = src/channels/libchannels.a

# Backend RPC: shared between rdpd worker and rdp-session.
BACKEND_OBJS = src/backend/proto.o
BACKEND_LIB  = src/backend/libbackend.a

# Per-user session helper (X11).
SESSION_OBJS = src/session/rdp_session.o src/session/clip_x11.o
SESSION_PROG = src/session/rdp-session

# Daemon objects.
RDPD_OBJS = src/daemon/rdpd.o src/daemon/conn.o $(SESSMGR_CLIENT_OBJ) \
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
	regress/wire/capset_test

FUZZ_PROG = regress/fuzz/fuzz_parsers

all: $(PROGS)

$(COMMON_LIB): $(COMMON_OBJS)
	ar rcs $@ $(COMMON_OBJS)

$(WIRE_LIB): $(WIRE_OBJS)
	ar rcs $@ $(WIRE_OBJS)

$(SEC_LIB): $(SEC_OBJS)
	ar rcs $@ $(SEC_OBJS)

$(GREETER_LIB): $(GREETER_OBJS)
	ar rcs $@ $(GREETER_OBJS)

src/daemon/rdpd: $(RDPD_OBJS) $(GREETER_LIB) $(WIRE_LIB) $(SEC_LIB) $(COMMON_LIB)
	$(CC) $(LDFLAGS) -o $@ $(RDPD_OBJS) \
		$(GREETER_LIB) $(WIRE_LIB) $(SEC_LIB) $(COMMON_LIB) \
		$(TLS_LIBS)

src/sessionmgr/rdp-sessionmgr: $(SESSMGR_DAEMON_OBJ) $(COMMON_LIB)
	$(CC) $(LDFLAGS) -o $@ $(SESSMGR_DAEMON_OBJ) $(COMMON_LIB) \
		$(AUTH_LIBS)

$(BACKEND_LIB): $(BACKEND_OBJS)
	ar rcs $@ $(BACKEND_OBJS)

$(CHANNELS_LIB): $(CHANNELS_OBJS)
	ar rcs $@ $(CHANNELS_OBJS)

src/session/rdp_session.o: src/session/rdp_session.c
	$(CC) $(CFLAGS) $(X11_CFLAGS) -DRDP_XVFB_PATH=\"$(XVFB_PATH)\" \
		-c -o $@ src/session/rdp_session.c

src/session/clip_x11.o: src/session/clip_x11.c
	$(CC) $(CFLAGS) $(X11_CFLAGS) -c -o $@ src/session/clip_x11.c

$(SESSION_PROG): $(SESSION_OBJS) $(BACKEND_LIB) $(COMMON_LIB)
	$(CC) $(LDFLAGS) -o $@ $(SESSION_OBJS) $(BACKEND_LIB) $(COMMON_LIB) \
		$(X11_LIBS)

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
