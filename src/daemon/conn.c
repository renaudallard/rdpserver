/*
 * Copyright (c) 2026 Renaud Allard <renaud@allard.it>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 */
/*
 * conn.c -- per-connection RDP state machine.
 *
 * Sequence:
 *   1. Read X.224 Connection Request, send Connection Confirm (PROTOCOL_SSL).
 *   2. TLS server handshake.
 *   3. Read MCS Connect Initial; send Connect Response.
 *   4. Read Erect Domain Request, Attach User Request -> send Attach User Confirm.
 *   5. Loop Channel Join Request/Confirm for the I/O channel + each virtual channel.
 *   6. Read Client Info PDU (over the I/O channel, security flag SEC_INFO_PKT).
 *   7. Send Server License Error PDU (STATUS_VALID_CLIENT).
 *   8. Send Demand Active PDU; read Confirm Active PDU.
 *   9. Finalization handshake: Synchronize, Control Cooperate, Control Request,
 *      Font List, Font Map.
 *  10. Send a fast-path Synchronize + System Pointer + a single bitmap update
 *      with a solid colour so the client window shows something.  Loop reading
 *      input until disconnect.
 *
 * All reads/writes go through the TLS handle once step 2 completes.  Up to
 * that point we read/write the raw TCP fd.
 */

#include "conn.h"

#include "../include/compat.h"
#include "../include/rdp_log.h"

#include "../common/io.h"
#include "../common/rand.h"
#include "../sec/tls.h"
#include "../wire/tpkt.h"
#include "../wire/x224.h"
#include "../wire/mcs.h"
#include "../wire/sec.h"
#include "../wire/license.h"
#include "../wire/capset.h"
#include "../wire/bmpcache.h"
#include "../wire/order.h"
#include "../wire/bitmap_rle.h"
#include "../wire/rdp_pdu.h"
#include "../wire/fastpath.h"
#include "../greeter/greeter.h"
#include "../sessionmgr/sessionmgr.h"
#include "../backend/proto.h"
#include "../backend/proto_api.h"
#include "../channels/cliprdr.h"
#include "../channels/drdynvc.h"
#include "../sec/nla.h"
#include "../sec/nla_crypto.h"
#include "../common/str.h"
#include "sandbox.h"
#include "../channels/rdpdr.h"
#include "../channels/rdpsnd.h"
#include "../channels/sndin.h"
#include "../channels/rdpei.h"
#include "../channels/cam.h"
#include "../channels/rdpgfx.h"
#include "../channels/autodetect.h"
#include "../channels/rail.h"
#include "../wire/h264enc.h"
#include "../wire/avc444.h"
#include "../wire/progressive.h"
#include "../common/utf16.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <poll.h>
#include <time.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

static uint32_t
ld32_safe(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
		| ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define RDP_CONN_BUF       0x4000
#define RDP_CONN_SHARE_ID  0x000103EAu
#define NTHASH_PATH        "/etc/rdpserver/nthashes"

/* Read one TPKT frame from the raw socket (pre-TLS). */
static ssize_t
read_tpkt_raw(int fd, uint8_t *buf, size_t cap)
{
	return rdp_tpkt_read(fd, buf, cap);
}

/* Read one TPKT frame over TLS. */
static ssize_t
read_tpkt_tls(struct rdp_tls *t, uint8_t *buf, size_t cap)
{
	struct rdp_tpkt h;
	ssize_t r;
	size_t body;

	if (cap < 4) { errno = EINVAL; return -1; }
	r = rdp_tls_read_full(t, buf, 4);
	if (r == 0) return 0;
	if (r < 4) return -1;
	if (rdp_tpkt_parse_hdr(&h, buf) < 0) { errno = EPROTO; return -1; }
	if (h.length > cap) { errno = EMSGSIZE; return -1; }
	body = (size_t)h.length - 4;
	if (body > 0) {
		r = rdp_tls_read_full(t, buf + 4, body);
		if (r < (ssize_t)body) return -1;
	}
	return (ssize_t)h.length;
}

/* Send a TPKT frame over TLS. */
static int
write_tpkt_tls(struct rdp_tls *t, uint8_t *buf, size_t len)
{
	if (rdp_tpkt_encode_hdr(buf, (uint16_t)len) < 0) return -1;
	return rdp_tls_write_full(t, buf, len) == (ssize_t)len ? 0 : -1;
}

/* Wrap a body (X.224 DT + MCS Send Data Indication + payload) for the
 * given channel into a TPKT frame in `out` and write to TLS. */
static int
send_send_data(struct rdp_tls *t,
		uint16_t user_id, uint16_t channel_id,
		const uint8_t *payload, size_t payload_len)
{
	uint8_t buf[RDP_CONN_BUF];
	ssize_t hdr_n, mcs_n;
	size_t total;

	hdr_n = rdp_x224_build_dt(buf + 4, sizeof buf - 4);
	if (hdr_n < 0) return -1;
	mcs_n = rdp_mcs_build_send_data_indication(buf + 4 + hdr_n,
		sizeof buf - 4 - hdr_n,
		user_id, channel_id, payload, payload_len);
	if (mcs_n < 0) return -1;
	total = 4 + (size_t)hdr_n + (size_t)mcs_n;
	return write_tpkt_tls(t, buf, total);
}

/* Wrap a raw MCS PDU (e.g. Disconnect Provider Ultimatum, not a
 * Send Data Request) in X.224 DT + TPKT and write it.  Send Data
 * already has its own helper above. */
static int
send_mcs_raw(struct rdp_tls *t, const uint8_t *mcs, size_t mcs_len)
{
	uint8_t buf[64];
	ssize_t hdr_n;
	size_t total;

	if (mcs_len > sizeof buf - 4 - 3) return -1;
	hdr_n = rdp_x224_build_dt(buf + 4, sizeof buf - 4);
	if (hdr_n < 0) return -1;
	memcpy(buf + 4 + hdr_n, mcs, mcs_len);
	total = 4 + (size_t)hdr_n + mcs_len;
	return write_tpkt_tls(t, buf, total);
}

/* Parse a TPKT frame already in buf[0..len) to extract the MCS payload
 * (assuming X.224 DT framing).  Returns offsets/lengths via out params. */
static int
strip_tpkt_x224(const uint8_t *buf, size_t len,
		const uint8_t **mcs_out, size_t *mcs_len_out)
{
	ssize_t dt;

	if (len < 4 + 3) return -1;
	dt = rdp_x224_parse_dt(buf + 4, len - 4);
	if (dt < 0) return -1;
	*mcs_out = buf + 4 + (size_t)dt;
	*mcs_len_out = len - 4 - (size_t)dt;
	return 0;
}

/* Connect-time network auto-detection (MS-RDPBCGR).  Runs after the
 * Client Info PDU and before licensing, only when the client advertised
 * support and the operator enabled it.  Measures RTT and link bandwidth
 * over the MCS message channel and returns the bandwidth in kilobits per
 * second, 0 when it could not measure (so the caller keeps the default
 * bitrate), or -1 on a transport error (the caller should drop the
 * connection because the stream may be mid-frame). */
#define AUTODETECT_TIMEOUT_MS  5000
#define AUTODETECT_PROBE_CHUNK 8192   /* one bandwidth payload, 4-aligned */
#define AUTODETECT_PROBE_COUNT 4      /* 32 KiB total probe */
#define AUTODETECT_PROBE_BYTES ((uint32_t)AUTODETECT_PROBE_CHUNK * AUTODETECT_PROBE_COUNT)
#define AUTODETECT_KBPS_MAX    30000  /* peak bitrate ceiling (kbps) */
/* sequenceNumbers are protocol-informational only (responses are matched
 * by message type, not echoed seq). */
#define AUTODETECT_SEQ_RTT     0x23
#define AUTODETECT_SEQ_BW      0x24
#define AUTODETECT_SEQ_RESULT  0x25

/* Send one autodetect request payload on the message channel, wrapping it
 * in a security header with SEC_AUTODETECT_REQ. */
static int
autodetect_send(struct rdp_tls *t, uint16_t user_id, uint16_t chan,
		const uint8_t *ad, size_t ad_len)
{
	uint8_t body[RDP_CONN_BUF];
	if (ad_len + RDP_SEC_HDR_LEN > sizeof body) return -1;
	if (rdp_sec_build_header(body, sizeof body,
		RDP_SEC_AUTODETECT_REQ) < 0) return -1;
	memcpy(body + RDP_SEC_HDR_LEN, ad, ad_len);
	return send_send_data(t, user_id, chan, body,
		RDP_SEC_HDR_LEN + ad_len);
}

/* Heartbeat PDU period and the missed-heartbeat warning/reconnect counts the
 * server advertises to the client (MS-RDPBCGR 2.2.16.1). */
#define HEARTBEAT_PERIOD_S      30u
#define HEARTBEAT_WARN_COUNT     3u
#define HEARTBEAT_RECONN_COUNT   5u

/* Send a server Heartbeat PDU on the MCS message channel so a client that
 * advertised support keeps the connection alive while the session is idle.
 * The body is reserved(1) + period(1) + count1(1) + count2(1) after the
 * SEC_HEARTBEAT security header. */
static int
send_heartbeat(struct rdp_tls *t, uint16_t user_id, uint16_t chan)
{
	uint8_t body[RDP_SEC_HDR_LEN + 4];
	if (rdp_sec_build_header(body, sizeof body, RDP_SEC_HEARTBEAT) < 0)
		return -1;
	body[RDP_SEC_HDR_LEN + 0] = 0;                       /* reserved */
	body[RDP_SEC_HDR_LEN + 1] = HEARTBEAT_PERIOD_S;      /* period */
	body[RDP_SEC_HDR_LEN + 2] = HEARTBEAT_WARN_COUNT;    /* count1 */
	body[RDP_SEC_HDR_LEN + 3] = HEARTBEAT_RECONN_COUNT;  /* count2 */
	return send_send_data(t, user_id, chan, body, sizeof body);
}

/* Wait for and parse one autodetect response on the message channel.
 * Returns 0 on success, 1 on a clean timeout (no bytes consumed), -1 on a
 * transport or protocol error. */
static int
autodetect_recv(struct rdp_tls *t, uint16_t chan,
		struct rdp_autodetect_rsp *rsp)
{
	uint8_t buf[2048];
	const uint8_t *mcs_p, *payload;
	size_t mcs_len, payload_len;
	uint16_t uid, cid;
	uint32_t sec_flags;
	ssize_t n, sh;
	struct pollfd pfd;
	int pr;

	/* poll() only sees the raw socket; if OpenSSL already holds decrypted
	 * bytes from a coalesced record, read them rather than wrongly time
	 * out (which would desync the next read). */
	if (rdp_tls_pending(t) == 0) {
		pfd.fd = rdp_tls_fd(t);
		pfd.events = POLLIN;
		pfd.revents = 0;
		do { pr = poll(&pfd, 1, AUTODETECT_TIMEOUT_MS); }
		while (pr < 0 && errno == EINTR);
		if (pr == 0) return 1;     /* nothing arrived; skip cleanly */
		if (pr < 0) return -1;
	}
	n = read_tpkt_tls(t, buf, sizeof buf);
	if (n <= 0) return -1;
	if (strip_tpkt_x224(buf, (size_t)n, &mcs_p, &mcs_len) != 0)
		return -1;
	if (rdp_mcs_parse_send_data_request(mcs_p, mcs_len, &uid, &cid,
		&payload, &payload_len) < 0)
		return -1;
	if (cid != chan)
		return -1;
	sh = rdp_sec_parse_header(payload, payload_len, &sec_flags);
	if (sh < 0 || (sec_flags & RDP_SEC_AUTODETECT_RSP) == 0)
		return -1;
	return rdp_autodetect_parse_response(payload + (size_t)sh,
		payload_len - (size_t)sh, rsp);
}

static int
do_autodetect(struct rdp_tls *t, uint16_t user_id, uint16_t chan,
		const char *peer)
{
	uint8_t ad[16 + AUTODETECT_PROBE_CHUNK];
	struct rdp_autodetect_rsp rsp;
	struct timespec t0, t1;
	ssize_t adn;
	int rc, i;
	uint32_t rtt_ms, kbps;

	/* RTT: time the round-trip of one RTT Measure Request. */
	adn = rdp_autodetect_build_rtt_request(ad, sizeof ad,
		AUTODETECT_SEQ_RTT);
	if (adn < 0) return 0;
	(void)clock_gettime(CLOCK_MONOTONIC, &t0);
	if (autodetect_send(t, user_id, chan, ad, (size_t)adn) != 0)
		return -1;
	rc = autodetect_recv(t, chan, &rsp);
	if (rc != 0) return rc > 0 ? 0 : -1;
	(void)clock_gettime(CLOCK_MONOTONIC, &t1);
	if (rsp.response_type != RDP_AUTODETECT_RTT_RSP) return 0;
	rtt_ms = (uint32_t)((t1.tv_sec - t0.tv_sec) * 1000
		+ (t1.tv_nsec - t0.tv_nsec) / 1000000);

	/* Bandwidth: bracket a fixed payload burst with Start/Stop and read
	 * the client's timing back. */
	adn = rdp_autodetect_build_bw_start(ad, sizeof ad, AUTODETECT_SEQ_BW);
	if (adn < 0 || autodetect_send(t, user_id, chan, ad,
		(size_t)adn) != 0)
		return -1;
	for (i = 0; i < AUTODETECT_PROBE_COUNT; i++) {
		adn = rdp_autodetect_build_bw_payload(ad, sizeof ad,
			AUTODETECT_SEQ_BW, AUTODETECT_PROBE_CHUNK);
		if (adn < 0 || autodetect_send(t, user_id, chan, ad,
			(size_t)adn) != 0)
			return -1;
	}
	adn = rdp_autodetect_build_bw_stop(ad, sizeof ad, AUTODETECT_SEQ_BW);
	if (adn < 0 || autodetect_send(t, user_id, chan, ad,
		(size_t)adn) != 0)
		return -1;
	rc = autodetect_recv(t, chan, &rsp);
	if (rc != 0) return rc > 0 ? 0 : -1;
	if (rsp.response_type != RDP_AUTODETECT_BW_RESULTS) return 0;
	/* A client cannot have received more than we sent; cap byte_count to
	 * the probe size so a lying result cannot inflate the measurement. */
	if (rsp.byte_count > AUTODETECT_PROBE_BYTES)
		rsp.byte_count = AUTODETECT_PROBE_BYTES;
	kbps = rdp_autodetect_bandwidth_kbps(rsp.byte_count, rsp.time_delta);
	/* Bound the result so the (int) return stays small and non-negative
	 * (it must never be mistaken for a transport error). */
	if (kbps > AUTODETECT_KBPS_MAX)
		kbps = AUTODETECT_KBPS_MAX;

	/* Inform the client of the result (best effort). */
	adn = rdp_autodetect_build_netchar_result(ad, sizeof ad,
		AUTODETECT_SEQ_RESULT, rtt_ms, kbps, rtt_ms);
	if (adn > 0)
		(void)autodetect_send(t, user_id, chan, ad, (size_t)adn);

	rdp_info("conn[%s]: autodetect rtt=%ums bandwidth=%ukbps",
		peer, rtt_ms, kbps);
	return (int)kbps;
}

/* FNV-1a 64-bit hash; fold n bytes at p into the running state h. */
static uint64_t
fnv1a64(uint64_t h, const void *p, size_t n)
{
	const uint8_t *b = p;
	size_t i;
	for (i = 0; i < n; i++) {
		h ^= b[i];
		h *= 0x100000001b3ull;
	}
	return h;
}

#define PROXY_PTR_CACHE_MAX 32

struct proxy_input_ctx {
	int be_fd;
	int last_mouse_x, last_mouse_y;
	uint16_t pending_high;   /* stashed UTF-16 high surrogate */
	uint16_t ptr_cache_n;    /* active slots, 0 = caching off */
	uint16_t ptr_cache_next; /* round-robin victim */
	struct { uint64_t hash; int valid; } ptr_cache[PROXY_PTR_CACHE_MAX];
};

struct clip_state {
	int      enabled;
	uint16_t channel_id;
	uint16_t user_id;
	int      use_long_names;
	int      caps_sent;

	/* The client's dynamic ids for named/standard formats, learned from
	 * its CB_FORMAT_LIST, so we can request them on the X side's behalf. */
	uint32_t client_html_id;
	uint32_t client_dib_id;
	uint32_t client_files_id;   /* "FileGroupDescriptorW" */

	/* Semantic format of the CB_FORMAT_DATA_REQUEST we last sent to the
	 * client, so its response (which carries no format id) is decoded
	 * correctly.  CLIPRDR is request/response serialised in practice. */
	uint32_t pending_req_fmt;

	/* Inbound CLIPRDR channel fragment reassembly (CHANNEL_PDU_HEADER
	 * FIRST..LAST), bounded by CLIP_MAX_PDU. */
	struct rdp_cliprdr_reasm reasm;
};

/* Map a CLIPRDR format id the client advertised or requested to one of our
 * semantic backend formats, or 0 if we do not handle it.  HTML uses the id
 * we advertised (CB_FMT_HTML_ID); the client echoes the advertiser's id. */
static uint32_t
clip_sem_from_id(uint32_t id)
{
	if (id == CF_UNICODETEXT || id == CF_TEXT)
		return RDP_BE_CLIP_FMT_TEXT;
	if (id == CF_DIB || id == CF_DIBV5)
		return RDP_BE_CLIP_FMT_IMAGE;
	if (id == CB_FMT_HTML_ID)
		return RDP_BE_CLIP_FMT_HTML;
	if (id == CB_FMT_FILEGROUP_ID)
		return RDP_BE_CLIP_FMT_FILES;
	return 0;
}

/* Map a semantic format to the id to request from the client. */
static uint32_t
clip_id_for_client(const struct clip_state *cs, uint32_t sem)
{
	switch (sem) {
	case RDP_BE_CLIP_FMT_TEXT:
		return CF_UNICODETEXT;
	case RDP_BE_CLIP_FMT_IMAGE:
		return cs->client_dib_id;
	case RDP_BE_CLIP_FMT_HTML:
		return cs->client_html_id;
	case RDP_BE_CLIP_FMT_FILES:
		return cs->client_files_id;
	}
	return 0;
}

/* Largest reassembled inbound CLIPRDR PDU we accept.  A format-data
 * response can carry up to BE_MAX_PAYLOAD of UTF-8 text, which the client
 * sends as UTF-16 (twice the size) plus headers; 8 MiB covers it and
 * bounds memory against a hostile client. */
#define CLIP_MAX_PDU (8u * 1024u * 1024u)

/* Largest data we may put in a CLIP_DATA / CLIP_FILE_DATA frame to the
 * session.  The 8-byte message header plus the data must stay under the
 * backend's 4 MiB payload cap or rdp_be_recv rejects it and the session
 * tears down, so a hostile client cannot weaponise an oversized blob. */
#define CLIP_BE_DATA_MAX (4u * 1024u * 1024u - 8u)

/* Send a CLIPRDR PDU: wrap `payload[0..len)` in a CHANNEL_PDU_HEADER
 * (FIRST | LAST) and ship via MCS Send Data Indication on the
 * CLIPRDR channel. */
#define VC_CHUNK_SIZE 16000

static int
send_clip_pdu(struct rdp_tls *t,
		uint16_t user_id, uint16_t channel_id,
		const uint8_t *payload, size_t len)
{
	uint8_t buf[VC_CHUNK_SIZE + 128];
	uint8_t inner[VC_CHUNK_SIZE + 8];
	size_t off = 0;

	while (off < len) {
		uint8_t chan_hdr[8];
		uint32_t flags = 0;
		size_t chunk = len - off;
		ssize_t dt_n, mcs_n;

		if (chunk > VC_CHUNK_SIZE)
			chunk = VC_CHUNK_SIZE;
		if (off == 0) flags |= CHANNEL_FLAG_FIRST;
		if (off + chunk >= len) flags |= CHANNEL_FLAG_LAST;

		chan_hdr[0] = (uint8_t)(len & 0xff);
		chan_hdr[1] = (uint8_t)((len >> 8) & 0xff);
		chan_hdr[2] = (uint8_t)((len >> 16) & 0xff);
		chan_hdr[3] = (uint8_t)((len >> 24) & 0xff);
		chan_hdr[4] = (uint8_t)(flags & 0xff);
		chan_hdr[5] = (uint8_t)((flags >> 8) & 0xff);
		chan_hdr[6] = (uint8_t)((flags >> 16) & 0xff);
		chan_hdr[7] = (uint8_t)((flags >> 24) & 0xff);
		memcpy(inner, chan_hdr, 8);
		memcpy(inner + 8, payload + off, chunk);

		dt_n = rdp_x224_build_dt(buf + 4, sizeof buf - 4);
		if (dt_n < 0) return -1;
		mcs_n = rdp_mcs_build_send_data_indication(buf + 4 + dt_n,
			sizeof buf - 4 - dt_n, user_id, channel_id,
			inner, 8 + chunk);
		if (mcs_n < 0) return -1;
		{
			size_t total = 4 + (size_t)dt_n + (size_t)mcs_n;
			if (rdp_tpkt_encode_hdr(buf, (uint16_t)total) < 0)
				return -1;
			if (rdp_tls_write_full(t, buf, total)
			    != (ssize_t)total)
				return -1;
		}
		off += chunk;
	}
	return 0;
}

static int
clip_send_monitor_ready_and_caps(struct rdp_tls *t, struct clip_state *cs)
{
	uint8_t pdu[64];
	ssize_t n;
	n = rdp_cliprdr_build_clip_caps(pdu, sizeof pdu);
	if (n < 0) return -1;
	if (send_clip_pdu(t, cs->user_id, cs->channel_id, pdu, (size_t)n) != 0)
		return -1;
	n = rdp_cliprdr_build_monitor_ready(pdu, sizeof pdu);
	if (n < 0) return -1;
	if (send_clip_pdu(t, cs->user_id, cs->channel_id, pdu, (size_t)n) != 0)
		return -1;
	cs->caps_sent = 1;
	return 0;
}

static int
clip_handle_pdu(struct rdp_tls *t, int be_fd,
		struct clip_state *cs,
		const uint8_t *pdu, size_t len)
{
	struct rdp_cliprdr_hdr h;
	if (rdp_cliprdr_parse_hdr(pdu, len, &h) != 0) return -1;
	switch (h.msg_type) {
	case CB_CLIP_CAPS:
		if (h.data_len >= 4 && len >= 8 + 4) {
			size_t off = 8 + 4;
			while (off + 4 <= len) {
				uint16_t ctype = (uint16_t)pdu[off]
					| ((uint16_t)pdu[off + 1] << 8);
				uint16_t clen  = (uint16_t)pdu[off + 2]
					| ((uint16_t)pdu[off + 3] << 8);
				if (clen < 4 || off + clen > len) break;
				if (ctype == CB_CAPSTYPE_GENERAL && clen >= 12) {
					uint32_t fl = (uint32_t)pdu[off + 8]
						| ((uint32_t)pdu[off + 9] << 8)
						| ((uint32_t)pdu[off + 10] << 16)
						| ((uint32_t)pdu[off + 11] << 24);
					if (fl & CB_USE_LONG_FORMAT_NAMES)
						cs->use_long_names = 1;
				}
				off += clen;
			}
		}
		rdp_debug("cliprdr: client caps (long_names=%d)",
			cs->use_long_names);
		break;
	case CB_FORMAT_LIST: {
		struct rdp_cliprdr_formats f;
		uint32_t bitmap = 0;
		(void)rdp_cliprdr_parse_format_list(pdu + 8,
			len > 8 ? len - 8 : 0, cs->use_long_names, &f);
		cs->client_html_id  = f.has_html ? f.html_id : 0;
		cs->client_dib_id   = f.has_dib ? f.dib_id : 0;
		cs->client_files_id = f.has_files ? f.files_id : 0;
		rdp_debug("cliprdr: client formats text=%d/%d html=%d dib=%d files=%d",
			f.has_unicode_text, f.has_text, f.has_html, f.has_dib,
			f.has_files);
		{
			uint8_t r[16];
			ssize_t rn = rdp_cliprdr_build_format_list_response(
				r, sizeof r, 1);
			if (rn > 0)
				(void)send_clip_pdu(t, cs->user_id,
					cs->channel_id, r, (size_t)rn);
		}
		if (f.has_unicode_text || f.has_text)
			bitmap |= RDP_BE_CLIP_FMT_TEXT;
		if (f.has_dib)
			bitmap |= RDP_BE_CLIP_FMT_IMAGE;
		if (f.has_html)
			bitmap |= RDP_BE_CLIP_FMT_HTML;
		if (f.has_files)
			bitmap |= RDP_BE_CLIP_FMT_FILES;
		if (bitmap != 0) {
			struct rdp_be_clip_offer offer = { bitmap };
			(void)rdp_be_send(be_fd, RDP_BE_CLIP_OFFER,
				&offer, sizeof offer);
		}
		break;
	}
	case CB_FORMAT_LIST_RESPONSE:
		break;
	case CB_FORMAT_DATA_REQUEST: {
		uint32_t format = 0;
		if (rdp_cliprdr_parse_format_data_request(pdu + 8,
			len > 8 ? len - 8 : 0, &format) == 0) {
			uint32_t sem = clip_sem_from_id(format);
			if (sem != 0) {
				struct rdp_be_clip_request req = { sem };
				(void)rdp_be_send(be_fd, RDP_BE_CLIP_REQUEST,
					&req, sizeof req);
			} else {
				uint8_t r[16];
				ssize_t rn =
				    rdp_cliprdr_build_format_data_response(
					r, sizeof r, NULL, 0, 0);
				if (rn > 0)
					(void)send_clip_pdu(t, cs->user_id,
						cs->channel_id, r, (size_t)rn);
			}
		}
		break;
	}
	case CB_FORMAT_DATA_RESPONSE: {
		/* The client answered the request we sent on the X side's
		 * behalf; pending_req_fmt tells us how to decode it. */
		size_t data_off = 8;
		size_t data_len = h.data_len;
		uint32_t sem = cs->pending_req_fmt;
		struct rdp_be_clip_data_hdr h2;
		uint8_t *out;
		int fail = (h.msg_flags & CB_RESPONSE_FAIL) ? 1 : 0;

		cs->pending_req_fmt = 0;
		if (data_off + data_len > len) data_len = len - data_off;
		h2.format = sem;
		h2.status = fail;
		if (fail) {
			(void)rdp_be_send(be_fd, RDP_BE_CLIP_DATA,
				&h2, sizeof h2);
			break;
		}
		if (sem == RDP_BE_CLIP_FMT_FILES) {
			/* The client returned the FileGroupDescriptorW blob; relay
			 * it verbatim to the session as CLIP_DATA(FILES).  The
			 * session parses it and downloads each file's bytes over the
			 * FILE_REQUEST/FILE_DATA pair.  Truncate an oversized blob to
			 * a whole number of descriptors the frame can hold; the
			 * session clamps the file count anyway. */
			if (data_len > CLIP_BE_DATA_MAX)
				data_len = CLIP_BE_DATA_MAX;
			out = malloc(sizeof h2 + data_len);
			if (out == NULL) break;
			memcpy(out, &h2, sizeof h2);
			if (data_len > 0)
				memcpy(out + sizeof h2, pdu + data_off, data_len);
			(void)rdp_be_send(be_fd, RDP_BE_CLIP_DATA,
				out, sizeof h2 + data_len);
			free(out);
		} else if (sem == RDP_BE_CLIP_FMT_IMAGE) {
			/* CF_DIB/CF_DIBV5 -> BMP byte stream for the X side. */
			uint8_t *bmp;
			ssize_t bl;
			size_t bcap = data_len + 14;   /* + BITMAPFILEHEADER */

			bmp = malloc(bcap);
			if (bmp == NULL) break;
			bl = rdp_cliprdr_dib_to_bmp(pdu + data_off, data_len,
				bmp, bcap);
			if (bl < 0) {
				/* Malformed DIB: report failure to the session. */
				free(bmp);
				h2.status = 1;
				(void)rdp_be_send(be_fd, RDP_BE_CLIP_DATA,
					&h2, sizeof h2);
				break;
			}
			out = malloc(sizeof h2 + (size_t)bl);
			if (out == NULL) {
				free(bmp);
				break;
			}
			memcpy(out, &h2, sizeof h2);
			memcpy(out + sizeof h2, bmp, (size_t)bl);
			free(bmp);
			(void)rdp_be_send(be_fd, RDP_BE_CLIP_DATA,
				out, sizeof h2 + (size_t)bl);
			free(out);
		} else if (sem == RDP_BE_CLIP_FMT_HTML) {
			/* CF_HTML envelope -> raw fragment bytes. */
			size_t fo = 0, fl = 0;
			(void)rdp_cliprdr_html_unwrap(pdu + data_off, data_len,
				&fo, &fl);
			out = malloc(sizeof h2 + fl);
			if (out == NULL) break;
			memcpy(out, &h2, sizeof h2);
			if (fl > 0)
				memcpy(out + sizeof h2, pdu + data_off + fo, fl);
			(void)rdp_be_send(be_fd, RDP_BE_CLIP_DATA,
				out, sizeof h2 + fl);
			free(out);
		} else {
			/* Default: UTF-16LE text -> UTF-8. */
			size_t out_size = sizeof h2 + data_len * 2 + 1;
			size_t got;
			out = malloc(out_size);
			if (out == NULL) break;
			h2.format = RDP_BE_CLIP_FMT_TEXT;
			memcpy(out, &h2, sizeof h2);
			got = rdp_utf16le_to_utf8((char *)out + sizeof h2,
				out_size - sizeof h2, pdu + data_off, data_len);
			if (got == (size_t)-1) got = 0;
			while (got > 0
			    && ((char *)out + sizeof h2)[got - 1] == '\0')
				got--;
			(void)rdp_be_send(be_fd, RDP_BE_CLIP_DATA,
				out, sizeof h2 + got);
			free(out);
		}
		break;
	}
	case CB_FILECONTENTS_REQUEST: {
		/* The client wants a file's size or a byte range from the
		 * FileGroupDescriptorW the session offered.  Forward it to the
		 * session as a FILE_REQUEST; the session reads the local file and
		 * answers with FILE_DATA, which we relay as CB_FILECONTENTS_RESPONSE. */
		struct rdp_cliprdr_filereq fr;
		struct rdp_be_clip_file_req be;

		if (rdp_cliprdr_parse_filecontents_request(pdu + 8,
			len > 8 ? len - 8 : 0, &fr) != 0)
			break;
		be.stream_id = fr.stream_id;
		be.lindex = fr.lindex;
		be.flags = fr.flags;
		be.pos_low = (uint32_t)(fr.position & 0xffffffffu);
		be.pos_high = (uint32_t)(fr.position >> 32);
		be.cb_requested = fr.cb_requested;
		(void)rdp_be_send(be_fd, RDP_BE_CLIP_FILE_REQUEST,
			&be, sizeof be);
		break;
	}
	case CB_FILECONTENTS_RESPONSE: {
		/* The client answered a session-originated CB_FILECONTENTS_REQUEST
		 * (file paste from the client into the session): forward the bytes
		 * (or the failure status) to the session as FILE_DATA.  The file
		 * data can be several MiB, so size the frame to it. */
		uint32_t stream_id = 0;
		const uint8_t *data = NULL;
		size_t dlen = 0;
		int fail = (h.msg_flags & CB_RESPONSE_FAIL) ? 1 : 0;
		struct rdp_be_clip_file_data_hdr fh;
		uint8_t *out;

		if (rdp_cliprdr_parse_filecontents_response(pdu + 8,
			len > 8 ? len - 8 : 0, &stream_id, &data, &dlen) != 0)
			break;
		if (fail) {
			data = NULL;
			dlen = 0;
		}
		/* A hostile client may over-deliver beyond the requested range;
		 * keep the relayed frame under the backend payload cap. */
		if (dlen > CLIP_BE_DATA_MAX)
			dlen = CLIP_BE_DATA_MAX;
		fh.stream_id = stream_id;
		fh.status = fail;
		out = malloc(sizeof fh + dlen);
		if (out == NULL) break;
		memcpy(out, &fh, sizeof fh);
		if (dlen > 0)
			memcpy(out + sizeof fh, data, dlen);
		(void)rdp_be_send(be_fd, RDP_BE_CLIP_FILE_DATA,
			out, sizeof fh + dlen);
		free(out);
		break;
	}
	default:
		rdp_debug("cliprdr: ignoring msg_type %u",
			(unsigned)h.msg_type);
		break;
	}
	return 0;
}

static int
clip_handle_be(struct rdp_tls *t, struct clip_state *cs,
		uint32_t type, const uint8_t *payload, size_t len)
{
	uint8_t pdu[0x2000];
	ssize_t n;

	switch (type) {
	case RDP_BE_CLIP_OFFER: {
		/* The X side announced clipboard content; advertise the
		 * matching formats to the client.  HTML and the file group
		 * carry a registered name so the client can map them. */
		struct rdp_clip_fmt fmts[4];
		size_t nf = 0;
		uint32_t bitmap = RDP_BE_CLIP_FMT_TEXT;

		if (!cs->enabled) return 0;
		if (len >= sizeof(struct rdp_be_clip_offer)) {
			struct rdp_be_clip_offer o;
			memcpy(&o, payload, sizeof o);
			bitmap = o.formats;
		}
		if (bitmap & RDP_BE_CLIP_FMT_TEXT) {
			fmts[nf].id = CF_UNICODETEXT;
			fmts[nf].name = NULL;
			nf++;
		}
		if (bitmap & RDP_BE_CLIP_FMT_IMAGE) {
			fmts[nf].id = CF_DIB;
			fmts[nf].name = NULL;
			nf++;
		}
		if (bitmap & RDP_BE_CLIP_FMT_HTML) {
			fmts[nf].id = CB_FMT_HTML_ID;
			fmts[nf].name = CB_FMT_NAME_HTML;
			nf++;
		}
		if (bitmap & RDP_BE_CLIP_FMT_FILES) {
			fmts[nf].id = CB_FMT_FILEGROUP_ID;
			fmts[nf].name = CB_FMT_NAME_FILEGROUP;
			nf++;
		}
		if (nf == 0) return 0;
		n = rdp_cliprdr_build_format_list(pdu, sizeof pdu,
			cs->use_long_names, fmts, nf);
		if (n < 0) return -1;
		return send_clip_pdu(t, cs->user_id, cs->channel_id,
			pdu, (size_t)n);
	}
	case RDP_BE_CLIP_REQUEST: {
		/* The X side asked for one format from the client. */
		uint32_t sem = RDP_BE_CLIP_FMT_TEXT;
		uint32_t cid;

		if (len >= sizeof(struct rdp_be_clip_request)) {
			struct rdp_be_clip_request rq;
			memcpy(&rq, payload, sizeof rq);
			sem = rq.format;
		}
		cid = clip_id_for_client(cs, sem);
		if (cid == 0) return 0;   /* client did not advertise it */
		cs->pending_req_fmt = sem;
		n = rdp_cliprdr_build_format_data_request(pdu, sizeof pdu, cid);
		if (n < 0) return -1;
		return send_clip_pdu(t, cs->user_id, cs->channel_id,
			pdu, (size_t)n);
	}
	case RDP_BE_CLIP_DATA: {
		struct rdp_be_clip_data_hdr h;
		const uint8_t *data;
		size_t dlen, resp_cap;
		uint8_t *resp;
		int rc;

		if (len < sizeof h) return -1;
		memcpy(&h, payload, sizeof h);
		if (h.status != 0) {
			n = rdp_cliprdr_build_format_data_response(
				pdu, sizeof pdu, NULL, 0, 0);
			if (n < 0) return -1;
			return send_clip_pdu(t, cs->user_id, cs->channel_id,
				pdu, (size_t)n);
		}
		data = payload + sizeof h;
		dlen = len - sizeof h;
		if (h.format == RDP_BE_CLIP_FMT_FILES) {
			/* The session already built the FileGroupDescriptorW blob;
			 * relay it as the CB_FORMAT_DATA_RESPONSE unchanged. */
			resp_cap = RDP_CLIPRDR_HDR_LEN + dlen;
			resp = malloc(resp_cap);
			if (resp == NULL) return -1;
			n = rdp_cliprdr_build_format_data_response(
				resp, resp_cap, data, dlen, 1);
		} else if (h.format == RDP_BE_CLIP_FMT_IMAGE) {
			/* BMP byte stream -> CF_DIB (strip the file header). */
			size_t doff = 0, dl = 0;

			if (rdp_cliprdr_bmp_to_dib(data, dlen, &doff, &dl) != 0) {
				n = rdp_cliprdr_build_format_data_response(
					pdu, sizeof pdu, NULL, 0, 0);
				if (n < 0) return -1;
				return send_clip_pdu(t, cs->user_id,
					cs->channel_id, pdu, (size_t)n);
			}
			resp_cap = RDP_CLIPRDR_HDR_LEN + dl;
			resp = malloc(resp_cap);
			if (resp == NULL) return -1;
			n = rdp_cliprdr_build_format_data_response(
				resp, resp_cap, data + doff, dl, 1);
		} else if (h.format == RDP_BE_CLIP_FMT_HTML) {
			/* Raw HTML fragment -> CF_HTML envelope. */
			uint8_t *cfh;
			ssize_t cl;
			size_t cfh_cap = dlen + 256;   /* envelope overhead */

			cfh = malloc(cfh_cap);
			if (cfh == NULL) return -1;
			cl = rdp_cliprdr_html_wrap(cfh, cfh_cap, data, dlen);
			if (cl < 0) {
				free(cfh);
				return -1;
			}
			resp_cap = RDP_CLIPRDR_HDR_LEN + (size_t)cl;
			resp = malloc(resp_cap);
			if (resp == NULL) {
				free(cfh);
				return -1;
			}
			n = rdp_cliprdr_build_format_data_response(
				resp, resp_cap, cfh, (size_t)cl, 1);
			free(cfh);
		} else {
			/* Default: UTF-8 -> UTF-16LE text.  The response can
			 * far exceed the fixed pdu buffer for a large paste, so
			 * size it to the data; send_clip_pdu fragments it. */
			size_t need = dlen * 2 + 2;
			size_t got;
			uint8_t *utf16 = malloc(need);

			if (utf16 == NULL) return -1;
			got = rdp_utf8_to_utf16le(utf16, need - 2,
				(const char *)data, dlen);
			if (got == (size_t)-1) got = 0;
			utf16[got]     = 0;
			utf16[got + 1] = 0;
			resp_cap = RDP_CLIPRDR_HDR_LEN + got + 2;
			resp = malloc(resp_cap);
			if (resp == NULL) {
				free(utf16);
				return -1;
			}
			n = rdp_cliprdr_build_format_data_response(
				resp, resp_cap, utf16, got + 2, 1);
			free(utf16);
		}
		if (n < 0) {
			free(resp);
			return -1;
		}
		rc = send_clip_pdu(t, cs->user_id, cs->channel_id,
			resp, (size_t)n);
		free(resp);
		return rc;
	}
	case RDP_BE_CLIP_FILE_DATA: {
		/* The session answered a CB_FILECONTENTS_REQUEST: wrap the bytes
		 * (or the failure status) in a CB_FILECONTENTS_RESPONSE for the
		 * client.  File data can be several MiB, so size the buffer to it;
		 * send_clip_pdu fragments. */
		struct rdp_be_clip_file_data_hdr h;
		const uint8_t *data;
		size_t dlen, resp_cap;
		uint8_t *resp;
		int rc;

		if (len < sizeof h) return -1;
		memcpy(&h, payload, sizeof h);
		data = payload + sizeof h;
		dlen = len - sizeof h;
		if (h.status != 0) {
			data = NULL;
			dlen = 0;
		}
		resp_cap = RDP_CLIPRDR_HDR_LEN + 4 + dlen;
		resp = malloc(resp_cap);
		if (resp == NULL) return -1;
		n = rdp_cliprdr_build_filecontents_response(resp, resp_cap,
			h.stream_id, data, dlen, h.status == 0);
		if (n < 0) {
			free(resp);
			return -1;
		}
		rc = send_clip_pdu(t, cs->user_id, cs->channel_id,
			resp, (size_t)n);
		free(resp);
		return rc;
	}
	case RDP_BE_CLIP_FILE_REQUEST: {
		/* File paste from the client into the session: the session wants
		 * one file's size or a byte range from the FileGroupDescriptorW
		 * the client offered.  Build a CB_FILECONTENTS_REQUEST and send it
		 * to the client; its CB_FILECONTENTS_RESPONSE comes back as the
		 * RDP_BE_CLIP_FILE_DATA relay in clip_handle_pdu. */
		struct rdp_be_clip_file_req be;
		struct rdp_cliprdr_filereq fr;
		uint8_t req[40];

		if (len < sizeof be) return -1;
		memcpy(&be, payload, sizeof be);
		memset(&fr, 0, sizeof fr);
		/* The session picks the stream_id and uses it to match the file
		 * chunk in flight; the client echoes it in CB_FILECONTENTS_RESPONSE
		 * and the response relay hands it straight back, so pass it through
		 * unchanged. */
		fr.stream_id = be.stream_id;
		fr.lindex = be.lindex;
		fr.flags = be.flags;
		fr.position = (uint64_t)be.pos_low
			| ((uint64_t)be.pos_high << 32);
		fr.cb_requested = be.cb_requested;
		n = rdp_cliprdr_build_filecontents_request(req, sizeof req, &fr);
		if (n < 0) return -1;
		return send_clip_pdu(t, cs->user_id, cs->channel_id,
			req, (size_t)n);
	}
	}
	return 0;
}

/* Translate a fast-path event and forward to the backend. */
static void
on_input_event(void *vctx, const struct rdp_fp_input_event *ev)
{
	struct proxy_input_ctx *ctx = vctx;
	switch (ev->type) {
	case RDP_FP_INPUT_SCANCODE: {
		struct rdp_be_input_key k = {0};
		k.scancode = ev->keycode;
		k.down = (ev->flags & 0x01) ? 0 : 1;   /* bit 0 = release */
		k.extended = (ev->flags & 0x02) ? 1 : 0;
		(void)rdp_be_send(ctx->be_fd, RDP_BE_INPUT_KEY, &k, sizeof k);
		break;
	}
	case RDP_FP_INPUT_MOUSE:
	case RDP_FP_INPUT_MOUSEX: {
		struct rdp_be_input_mouse m = {0};
		uint16_t f = ev->flags;
		m.x = ev->x; m.y = ev->y;
		if (f & 0x0800) m.flags |= 0x01;       /* PTRFLAGS_MOVE */
		if (f & 0x1000) m.buttons |= 0x01;     /* button1 */
		if (f & 0x2000) m.buttons |= 0x02;     /* button2 */
		if (f & 0x4000) m.buttons |= 0x04;     /* button3 */
		if (f & 0x8000) m.buttons |= 0x08;     /* down vs up */
		if (m.buttons) m.flags |= 0x02;
		(void)rdp_be_send(ctx->be_fd, RDP_BE_INPUT_MOUSE, &m, sizeof m);
		ctx->last_mouse_x = m.x;
		ctx->last_mouse_y = m.y;
		break;
	}
	case RDP_FP_INPUT_UNICODE: {
		struct rdp_be_input_unicode u = {0};
		uint16_t cu = ev->keycode;   /* UTF-16 code unit */
		uint32_t cp;
		if (ev->flags & 0x01)        /* release: inject on press only */
			break;
		if (cu >= 0xd800 && cu <= 0xdbff) {
			ctx->pending_high = cu;  /* high surrogate: await low */
			break;
		}
		if (cu >= 0xdc00 && cu <= 0xdfff) {
			if (ctx->pending_high == 0)
				break;           /* unpaired low surrogate */
			cp = 0x10000u
			    + (((uint32_t)(ctx->pending_high - 0xd800)) << 10)
			    + (uint32_t)(cu - 0xdc00);
			ctx->pending_high = 0;
		} else {
			ctx->pending_high = 0;   /* drop any stale high */
			cp = cu;
		}
		u.codepoint = cp;
		u.down = 1;
		(void)rdp_be_send(ctx->be_fd, RDP_BE_INPUT_UNICODE,
			&u, sizeof u);
		break;
	}
	case RDP_FP_INPUT_SYNC: {
		struct rdp_be_input_sync s = {0};
		/* Low nibble = SCROLL|NUM|CAPS|KANA; mask off reserved bits. */
		s.flags = (uint32_t)(ev->flags & 0x0f);
		(void)rdp_be_send(ctx->be_fd, RDP_BE_INPUT_SYNC, &s, sizeof s);
		break;
	}
	default:
		break;
	}
}

/* Emit a single TS_UPDATE_BITMAP body as one or more fast-path PDUs.
 * When the body fits a single PDU it is sent unfragmented; otherwise it
 * is sliced into FIRST/NEXT/LAST fragments of at most (chunk_target - 6)
 * body bytes each (6 = 1 action + 2 length + 3 inner header headroom).
 * Returns 0 on success, -1 on failure. */
static int
send_bitmap_fragments(struct rdp_tls *t, const uint8_t *body,
		size_t body_size, size_t chunk_target)
{
	uint8_t pkt[0x4000];
	size_t frag = chunk_target - 6;
	size_t off = 0;
	int first = 1;

	/* Slice size must keep the whole PDU under the wire ceiling and
	 * within the 16-bit update length. */
	if (frag > 0xffff) frag = 0xffff;
	while (off < body_size) {
		size_t slice = body_size - off;
		uint8_t flag;
		ssize_t n;
		if (slice > frag) slice = frag;
		if (off + slice >= body_size)
			flag = first ? RDP_FP_FRAGMENT_SINGLE
				: RDP_FP_FRAGMENT_LAST;
		else
			flag = first ? RDP_FP_FRAGMENT_FIRST
				: RDP_FP_FRAGMENT_NEXT;
		n = rdp_fp_build_update_frag(pkt, sizeof pkt,
			RDP_FP_UPDATE_BITMAP, flag, body + off, slice);
		if (n < 0) return -1;
		if (rdp_tls_write_full(t, pkt, (size_t)n) != (ssize_t)n)
			return -1;
		off += slice;
		first = 0;
	}
	return 0;
}

/* Send one 64x64-or-smaller tile through the persistent bitmap cache as
 * drawing orders.  A MemBlt recalls the cached slot for the tile; on a cache
 * miss it is preceded by a Cache Bitmap Rev2 secondary order carrying the
 * RLE-compressed pixels, so the client stores the tile before the MemBlt
 * blits it.  Both orders travel in one fast-path Orders update.  tile_pix is
 * tw*th packed 24bpp pixels (top-down).  Returns 0 on success, -1 on failure.
 *
 * A cache miss reserves a slot, so any failure after the lookup tears the
 * connection down (the caller breaks on -1); the slot is never left naming a
 * bitmap the client did not receive. */
static int
send_tile_orders(struct rdp_tls *t, struct rdp_bmpcache *cache,
		uint32_t dx, uint32_t dy, uint16_t tw, uint16_t th,
		const uint8_t *tile_pix)
{
	/* One Cache Bitmap order plus a MemBlt for a 64x64 24bpp tile: the RLE
	 * stream never expands the raw pixels by more than a few bytes, so this
	 * is a generous single-PDU bound. */
	uint8_t body[2 + 64 * 64 * 3 + 512];
	uint8_t pkt[0x4000];
	uint64_t key;
	uint8_t cache_id = 0;
	uint16_t cache_index = 0;
	uint16_t norders = 0;
	size_t blen = 2;            /* leave room for the numberOrders field */
	struct rdp_memblt m;
	ssize_t n;

	key = rdp_bmpcache_key(tile_pix, (size_t)tw * th * 3);
	if (rdp_bmpcache_lookup(cache, key, &cache_id, &cache_index) == 0) {
		/* Miss: the client does not hold this tile.  Compress it and
		 * emit a Cache Bitmap order to store it in the reserved slot. */
		uint8_t rle[64 * 64 * 3 + 512];
		size_t rlen = 0;
		struct rdp_cache_bitmap cb;
		if (rdp_bitmap_rle_compress_24(rle, sizeof rle, &rlen,
		    tile_pix, tw, th) != 0)
			return -1;
		memset(&cb, 0, sizeof cb);
		cb.cache_id = cache_id;
		cb.cache_index = cache_index;
		cb.bpp = 24;
		cb.width = tw;
		cb.height = th;
		cb.key = key;
		cb.compressed = 1;
		cb.data = rle;
		cb.len = rlen;
		n = rdp_order_build_cache_bitmap_v2(body + blen,
		    sizeof body - blen, &cb);
		if (n < 0)
			return -1;
		blen += (size_t)n;
		norders++;
	}

	memset(&m, 0, sizeof m);
	m.cache_id = cache_id;
	m.cache_index = cache_index;
	/* Absolute screen coordinates; an out-of-range value (a frame whose edge
	 * exceeds 65535) is rejected by rdp_order_build_memblt rather than
	 * silently truncated, so a bad coordinate fails loud instead of blitting
	 * to the wrong place. */
	m.x = (int32_t)dx;
	m.y = (int32_t)dy;
	m.w = tw;
	m.h = th;
	m.rop = RDP_ROP_SRCCOPY;
	n = rdp_order_build_memblt(body + blen, sizeof body - blen, &m);
	if (n < 0)
		return -1;
	blen += (size_t)n;
	norders++;

	body[0] = (uint8_t)(norders & 0xFF);
	body[1] = (uint8_t)((norders >> 8) & 0xFF);

	n = rdp_fp_build_update(pkt, sizeof pkt, RDP_FP_UPDATE_ORDERS,
	    body, blen);
	if (n < 0)
		return -1;
	if (rdp_tls_write_full(t, pkt, (size_t)n) != (ssize_t)n)
		return -1;
	return 0;
}

/* Tile a frame and push it to the client.  When cache is non-NULL the tiles
 * go out as cached drawing orders (MemBlt, with a Cache Bitmap on a miss);
 * otherwise as fast-path bitmap updates.  chunk_target is the largest
 * fast-path PDU we may emit; a bitmap tile that does not fit one PDU is sliced
 * across fragments. */
static int
push_frame_tiled(struct rdp_tls *t,
		uint16_t fx, uint16_t fy, uint16_t fw, uint16_t fh,
		const uint8_t *pixels, size_t chunk_target,
		struct rdp_bmpcache *cache)
{
	const uint16_t TILE = 64;
	uint8_t tile_pix[64 * 64 * 3];
	uint8_t pkt[0x4000];
	uint16_t y;

	for (y = 0; y < fh; y += TILE) {
		uint16_t th = (uint16_t)(y + TILE > fh ? fh - y : TILE);
		uint16_t x;
		for (x = 0; x < fw; x += TILE) {
			uint16_t tw = (uint16_t)(x + TILE > fw ? fw - x : TILE);
			uint16_t wpad = (uint16_t)((tw + 3) & ~3u);
			size_t body_size = 4 + 18 + (size_t)wpad * 3 * th;
			ssize_t n;
			size_t row;
			for (row = 0; row < th; row++) {
				memcpy(tile_pix + row * tw * 3,
					pixels + ((size_t)(y + row) * fw
						+ x) * 3,
					(size_t)tw * 3);
			}
			/* Cached path: recall or store the tile as orders.  Pass
			 * the absolute coordinate untruncated so an edge past
			 * 65535 is rejected, not wrapped. */
			if (cache != NULL) {
				if (send_tile_orders(t, cache,
					(uint32_t)fx + x, (uint32_t)fy + y,
					tw, th, tile_pix) != 0)
					return -1;
				continue;
			}
			/* Common path: the whole tile fits one PDU. */
			if (body_size + 6 <= chunk_target) {
				n = rdp_fp_build_bitmap_update(pkt, sizeof pkt,
					(uint16_t)(fx + x), (uint16_t)(fy + y),
					tw, th, tile_pix, (size_t)tw * 3);
				if (n < 0) return -1;
				if (rdp_tls_write_full(t, pkt, (size_t)n)
				    != (ssize_t)n)
					return -1;
				continue;
			}
			/* Oversized tile: build the body once and fragment. */
			{
				uint8_t *scratch = malloc(body_size);
				ssize_t bn;
				int rc;
				if (scratch == NULL) return -1;
				bn = rdp_fp_build_bitmap_body(scratch, body_size,
					(uint16_t)(fx + x), (uint16_t)(fy + y),
					tw, th, tile_pix, (size_t)tw * 3);
				if (bn < 0) {
					free(scratch);
					return -1;
				}
				rc = send_bitmap_fragments(t, scratch,
					(size_t)bn, chunk_target);
				free(scratch);
				if (rc != 0) return -1;
			}
		}
	}
	return 0;
}

/* Read one TPKT or fast-path PDU into buf.  Returns total length
 * read on success, 0 on clean EOF, -1 on error.  `kind` is set to
 * 1 for TPKT, 0 for fast-path. */
static ssize_t
read_one_rdp_pdu(struct rdp_tls *t, uint8_t *buf, size_t cap, int *kind)
{
	uint8_t lead;
	ssize_t r;
	struct rdp_tpkt h;
	size_t total;

	r = rdp_tls_read(t, &lead, 1);
	if (r <= 0) return r;
	buf[0] = lead;
	if (lead == 0x03) {
		r = rdp_tls_read_full(t, buf + 1, 3);
		if (r != 3) return -1;
		if (rdp_tpkt_parse_hdr(&h, buf) < 0) return -1;
		if (h.length > cap) return -1;
		r = rdp_tls_read_full(t, buf + 4, (size_t)h.length - 4);
		if (r < 0) return -1;
		*kind = 1;
		return (ssize_t)h.length;
	}
	r = rdp_tls_read_full(t, buf + 1, 1);
	if (r != 1) return -1;
	if ((buf[1] & 0x80) == 0) {
		total = buf[1];
		if (total < 2) total = 2;
		if (total > cap) return -1;
		if (total > 2) {
			r = rdp_tls_read_full(t, buf + 2, total - 2);
			if (r < 0) return -1;
		}
	} else {
		r = rdp_tls_read_full(t, buf + 2, 1);
		if (r < 0) return -1;
		total = ((size_t)(buf[1] & 0x7f) << 8) | buf[2];
		if (total < 3) total = 3;
		if (total > cap) return -1;
		if (total > 3) {
			r = rdp_tls_read_full(t, buf + 3, total - 3);
			if (r < 0) return -1;
		}
	}
	*kind = 0;
	return (ssize_t)total;
}

struct dynvc_state {
	int      enabled;
	uint16_t channel_id;
	struct drdynvc_state dv;
	struct sndin_state   sndin;  /* AUDIO_INPUT (microphone) negotiation */
	struct rdp_cam_state cam;    /* MS-RDPECAM camera negotiation */
	uint8_t *cam_frame;          /* reusable header+frame forward buffer */
	size_t   cam_frame_cap;
};

struct snd_state {
	int      enabled;
	uint16_t channel_id;
	struct rdpsnd_state snd;
};

struct rail_state {
	int      enabled;
	uint16_t channel_id;
	int      handshake_sent;
};

/* Per-job print state machine.  A PRINT_JOB from the session opens the
 * printer (CREATE), writes the spool in chunks (WRITE) at advancing
 * offsets, then closes it (CLOSE).  Each step is async: its completion
 * advances the state and emits the next IRP.  cid is the completion id of
 * the IRP currently in flight so a completion can be matched back. */
#define RDPDR_MAX_PRINT_JOBS 8
#define RDPDR_PRINT_CHUNK    8000u   /* per WRITE spool slice, safe size */

enum print_job_state {
	PJ_FREE = 0,
	PJ_CREATE,   /* CREATE in flight; completion yields the file_id */
	PJ_WRITE,    /* WRITE in flight; on completion advance offset */
	PJ_CLOSE     /* CLOSE in flight; on completion free the job */
};

struct print_job {
	enum print_job_state state;
	uint32_t device_id;
	uint32_t file_id;     /* from CREATE completion */
	uint32_t cid;         /* completion id of the in-flight IRP */
	uint8_t *spool;       /* owned copy of the job's spool bytes */
	size_t   spool_len;
	size_t   off;         /* bytes already written */
};

struct dr_state {
	int      enabled;
	uint16_t channel_id;
	struct rdpdr_state dr;
	struct print_job jobs[RDPDR_MAX_PRINT_JOBS];
};

/* Free a print job's spool copy and return the slot to the pool.  Safe to
 * call on an already free job. */
static void
print_job_free(struct print_job *j)
{
	free(j->spool);
	j->spool = NULL;
	j->spool_len = 0;
	j->off = 0;
	j->state = PJ_FREE;
	j->device_id = 0;
	j->file_id = 0;
	j->cid = 0;
}

/* True if device_id names a printer device in the parsed device list. */
static int
dr_is_printer_device(const struct dr_state *dr, uint32_t device_id)
{
	uint32_t i;

	for (i = 0; i < dr->dr.device_count && i < RDPDR_MAX_DEVICES; i++) {
		const struct rdpdr_device *d = &dr->dr.devices[i];
		if (d->in_use && d->device_id == device_id)
			return d->device_type == RDPDR_DTYP_PRINT;
	}
	return 0;
}

/* Find the in-flight print job whose current IRP has completion id cid. */
static struct print_job *
print_job_by_cid(struct dr_state *dr, uint32_t cid)
{
	int i;

	for (i = 0; i < RDPDR_MAX_PRINT_JOBS; i++)
		if (dr->jobs[i].state != PJ_FREE && dr->jobs[i].cid == cid)
			return &dr->jobs[i];
	return NULL;
}

/* Emit the next WRITE IRP for job j (one RDPDR_PRINT_CHUNK slice at j->off)
 * and record its completion id.  Returns 0 on success, -1 on failure (the
 * caller frees the job). */
static int
print_job_send_write(struct rdp_tls *t, uint16_t user_id,
		struct dr_state *dr, struct print_job *j)
{
	uint8_t irp[IRP_HDR_SIZE + 32 + RDPDR_PRINT_CHUNK];
	size_t chunk = j->spool_len - j->off;
	uint32_t cid = 0;
	ssize_t in;

	if (chunk > RDPDR_PRINT_CHUNK)
		chunk = RDPDR_PRINT_CHUNK;
	in = rdp_rdpdr_build_irp_write(&dr->dr, irp, sizeof irp,
		j->device_id, j->file_id, (uint64_t)j->off,
		j->spool + j->off, chunk, &cid);
	if (in <= 0)
		return -1;
	j->cid = cid;
	j->state = PJ_WRITE;
	(void)send_clip_pdu(t, user_id, dr->channel_id, irp, (size_t)in);
	return 0;
}

/* Emit the CLOSE IRP for job j and record its completion id.  Returns 0 on
 * success, -1 on failure (the caller frees the job). */
static int
print_job_send_close(struct rdp_tls *t, uint16_t user_id,
		struct dr_state *dr, struct print_job *j)
{
	uint8_t irp[IRP_HDR_SIZE + 32];
	uint32_t cid = 0;
	ssize_t in;

	in = rdp_rdpdr_build_irp_close(&dr->dr, irp, sizeof irp,
		j->device_id, j->file_id, &cid);
	if (in <= 0)
		return -1;
	j->cid = cid;
	j->state = PJ_CLOSE;
	(void)send_clip_pdu(t, user_id, dr->channel_id, irp, (size_t)in);
	return 0;
}

/* Start a print job: take ownership of a spool copy and emit the CREATE IRP
 * to open the printer (DesiredAccess = GENERIC_WRITE).  spool is consumed
 * (freed) on every path so the caller never frees it.  Returns 0 if the job
 * is in flight, -1 if it could not be started. */
static int
print_job_start(struct rdp_tls *t, uint16_t user_id, struct dr_state *dr,
		uint32_t device_id, uint8_t *spool, size_t spool_len)
{
	uint8_t irp[IRP_HDR_SIZE + 64 + 2];
	struct print_job *j = NULL;
	uint32_t cid = 0;
	ssize_t in;
	int i;

	for (i = 0; i < RDPDR_MAX_PRINT_JOBS; i++)
		if (dr->jobs[i].state == PJ_FREE) {
			j = &dr->jobs[i];
			break;
		}
	if (j == NULL) {
		rdp_warn("rdpdr: no free print job slot, dropping job");
		free(spool);
		return -1;
	}

	/* Open the printer.  Empty path, GENERIC_WRITE access, disposition
	 * and options 0 per MS-RDPEPC printing. */
	in = rdp_rdpdr_build_irp_create(&dr->dr, irp, sizeof irp,
		device_id, "", 0x40000000u /* GENERIC_WRITE */, 0, 0, &cid);
	if (in <= 0) {
		free(spool);
		return -1;
	}
	j->state = PJ_CREATE;
	j->device_id = device_id;
	j->file_id = 0;
	j->cid = cid;
	j->spool = spool;
	j->spool_len = spool_len;
	j->off = 0;
	(void)send_clip_pdu(t, user_id, dr->channel_id, irp, (size_t)in);
	return 0;
}

/* Advance the print job that the completion comp belongs to.  Called only
 * for completions on printer devices.  Frees the job on CLOSE completion or
 * on any error. */
static void
print_job_on_completion(struct rdp_tls *t, uint16_t user_id,
		struct dr_state *dr, const struct rdpdr_completion *comp)
{
	struct print_job *j = print_job_by_cid(dr, comp->completion_id);

	if (j == NULL) {
		rdp_warn("rdpdr: print completion cid=%u has no job",
			(unsigned)comp->completion_id);
		return;
	}
	if (comp->io_status != STATUS_SUCCESS) {
		rdp_warn("rdpdr: print job dev=%u failed status=0x%08x "
			"state=%d", (unsigned)j->device_id,
			(unsigned)comp->io_status, (int)j->state);
		print_job_free(j);
		return;
	}

	switch (j->state) {
	case PJ_CREATE:
		/* CREATE completion body starts with the FileId (u32). */
		if (comp->data_len >= 4)
			j->file_id = ld32_safe(comp->data);
		if (j->spool_len == 0) {
			/* Nothing to write; close straight away. */
			if (print_job_send_close(t, user_id, dr, j) != 0)
				print_job_free(j);
			break;
		}
		if (print_job_send_write(t, user_id, dr, j) != 0)
			print_job_free(j);
		break;
	case PJ_WRITE:
		/* The completion reports how many bytes were written; trust
		 * the chunk size we sent and advance by it. */
		j->off += (j->spool_len - j->off) > RDPDR_PRINT_CHUNK
			? RDPDR_PRINT_CHUNK : (j->spool_len - j->off);
		if (j->off < j->spool_len) {
			if (print_job_send_write(t, user_id, dr, j) != 0)
				print_job_free(j);
		} else {
			if (print_job_send_close(t, user_id, dr, j) != 0)
				print_job_free(j);
		}
		break;
	case PJ_CLOSE:
		rdp_debug("rdpdr: print job dev=%u done (%zu bytes)",
			(unsigned)j->device_id, j->spool_len);
		print_job_free(j);
		break;
	default:
		print_job_free(j);
		break;
	}
}

/* Set from cfg in rdp_conn_run; used during channel dispatch, which
 * runs before the per-connection setup, so declared at file scope. */
static int g_prefer_wan_audio;
static int g_remoteapp;   /* client requested RemoteApp (RAIL) via INFO_RAIL */
static struct rail_state g_rail;   /* RAIL channel, set during channel join */
/* Offer the AUDIO_INPUT (microphone) dynamic channel; default on, cleared
 * by rdpd -m.  When off the channel is simply never created. */
static int g_allow_microphone = 1;
/* Offer MS-RDPECAM client camera redirection; default off (camera is
 * privacy-sensitive), set by rdpd -C.  When off the channel is never
 * created. */
static int g_allow_camera;
/* Offer the persistent bitmap cache (drawing orders) on the fast-path bitmap
 * path; default off, set by rdpd -B.  When off the demand-active is unchanged
 * and no orders are sent. */
static int g_allow_bitmap_cache;
/* Per-connection bitmap cache slot manager (one worker == one connection),
 * created when g_allow_bitmap_cache is set. */
static struct rdp_bmpcache *g_bmpcache;
/* Set from the client's Confirm Active: 1 only when the client announced both
 * MemBlt order support and a Bitmap Cache Rev2 cap.  The cached-tile drawing
 * orders are sent only when this is set, so a client that did not enable its
 * bitmap cache is never sent orders it would reject. */
static int g_client_bitmap_cache_ok;
/* The client's preferred colour depth from its Bitmap cap.  The interleaved-RLE
 * codec (used by both the cache orders and the fast-path bitmaps) emits a 24bpp
 * stream that mstsc only decodes in a 24bpp session, so RLE output is sent only
 * to 24bpp clients; others get raw bitmaps, which every client accepts. */
static uint16_t g_client_bpp = 24;
/* Set when the client advertised RNS_UD_CS_SUPPORT_HEARTBEAT_PDU; g_heartbeat_chan
 * is the MCS message channel to send Heartbeat PDUs on (0 if none). */
static int g_client_heartbeat;
static uint16_t g_heartbeat_chan;

/* Try to recognise a channel-bearing TPKT/MCS SDR and dispatch.
 * Returns 1 if handled, 0 if not, -1 on disconnect, 2 if a resize
 * is requested (new_w/new_h set). */
static int
maybe_dispatch_clip(struct rdp_tls *t, int be_fd,
		struct clip_state *cs, struct dynvc_state *dv,
		struct snd_state *ss, struct dr_state *dr,
		const uint8_t *frame, size_t frame_len, const char *peer,
		uint16_t *new_w, uint16_t *new_h,
		const uint8_t **out_gfx, size_t *out_gfx_len)
{
	const uint8_t *mcs_p;
	size_t mcs_len;
	ssize_t dt;
	uint16_t uid, cid;
	const uint8_t *payload;
	size_t payload_len;

	if (frame_len < 4 + 3) return 0;
	dt = rdp_x224_parse_dt(frame + 4, frame_len - 4);
	if (dt < 0) return 0;
	mcs_p = frame + 4 + (size_t)dt;
	mcs_len = frame_len - 4 - (size_t)dt;
	if (mcs_len < 1) return 0;

	if (mcs_p[0] == RDP_MCS_TYPE_DISCONNECT) {
		rdp_debug("conn[%s]: MCS disconnect", peer);
		return -1;
	}
	if (mcs_p[0] != RDP_MCS_TYPE_SEND_DATA_REQ) return 0;
	if (rdp_mcs_parse_send_data_request(mcs_p, mcs_len, &uid, &cid,
		&payload, &payload_len) < 0)
		return 0;

	/* If this is on the CLIPRDR channel, reassemble fragments then hand
	 * off the complete PDU.  The 8-byte CHANNEL_PDU_HEADER carries the
	 * full PDU length and FIRST/LAST flags; a single-fragment PDU (the
	 * common case) is dispatched in place without a copy. */
	if (cs->enabled && cid == cs->channel_id) {
		uint32_t total, cflags;
		const uint8_t *pdu;
		size_t pdu_len;

		if (payload_len < 8) return 1;
		total = (uint32_t)payload[0] | ((uint32_t)payload[1] << 8)
			| ((uint32_t)payload[2] << 16)
			| ((uint32_t)payload[3] << 24);
		cflags = (uint32_t)payload[4] | ((uint32_t)payload[5] << 8)
			| ((uint32_t)payload[6] << 16)
			| ((uint32_t)payload[7] << 24);

		if (rdp_cliprdr_reasm_feed(&cs->reasm, payload + 8,
			payload_len - 8, total, cflags, &pdu, &pdu_len) == 1) {
			(void)clip_handle_pdu(t, be_fd, cs, pdu, pdu_len);
			rdp_cliprdr_reasm_reset(&cs->reasm);
		}
		return 1;
	}

	/* DRDYNVC channel: dynamic virtual channels (resize, GFX). */
	if (dv->enabled && cid == dv->channel_id) {
		if (payload_len < 8) return 1;
		{
			uint8_t resp[64];
			size_t resp_len = 0;
			const uint8_t *gfx_data = NULL;
			size_t gfx_len = 0;
			int rc = rdp_drdynvc_handle(&dv->dv,
				payload + 8, payload_len - 8,
				resp, sizeof resp, &resp_len,
				new_w, new_h,
				&gfx_data, &gfx_len);
			if (resp_len > 0) {
				(void)send_clip_pdu(t, cs->user_id,
					dv->channel_id, resp, resp_len);
			}
			if (rc == 5 && !dv->dv.gfx_create_pending
			    && dv->dv.gfx_channel_id < 0) {
				uint8_t gc[64];
				ssize_t gn = rdp_drdynvc_build_create_gfx(
					&dv->dv, gc, sizeof gc);
				if (gn > 0)
					(void)send_clip_pdu(t, cs->user_id,
						dv->channel_id, gc, (size_t)gn);
			}
			if (rc == 5 && !dv->dv.disp_create_pending
			    && dv->dv.disp_channel_id < 0) {
				uint8_t dcc[64];
				ssize_t dn = rdp_drdynvc_build_create_disp(
					&dv->dv, dcc, sizeof dcc);
				if (dn > 0)
					(void)send_clip_pdu(t, cs->user_id,
						dv->channel_id, dcc,
						(size_t)dn);
			}
			if (rc == 5 && g_allow_microphone
			    && !dv->dv.audioin_create_pending
			    && dv->dv.audioin_channel_id < 0) {
				uint8_t ac[64];
				ssize_t an =
				    rdp_drdynvc_build_create_audio_input(
					&dv->dv, ac, sizeof ac);
				if (an > 0)
					(void)send_clip_pdu(t, cs->user_id,
						dv->channel_id, ac,
						(size_t)an);
			}
			/* RDPEI is harmless to offer (a client without touch
			 * just declines the Create), so open it unconditionally
			 * like gfx and DisplayControl, not behind a config flag. */
			if (rc == 5 && !dv->dv.rdpei_create_pending
			    && dv->dv.rdpei_channel_id < 0) {
				uint8_t rc_buf[64];
				ssize_t rn =
				    rdp_drdynvc_build_create_rdpei(
					&dv->dv, rc_buf, sizeof rc_buf);
				if (rn > 0)
					(void)send_clip_pdu(t, cs->user_id,
						dv->channel_id, rc_buf,
						(size_t)rn);
			}
			/* Camera redirection (MS-RDPECAM) is opt-in via -C: offer
			 * only the enumerator channel here; the per-device channel
			 * is opened later, when the client announces a camera. */
			if (rc == 5 && g_allow_camera
			    && !dv->dv.camenum_create_pending
			    && dv->dv.camenum_channel_id < 0) {
				uint8_t cc[64];
				ssize_t cn = rdp_drdynvc_build_create_cam_enum(
					&dv->dv, cc, sizeof cc);
				if (cn > 0)
					(void)send_clip_pdu(t, cs->user_id,
						dv->channel_id, cc, (size_t)cn);
			}
			if (rc == 7) return 7;
			if (rc == 8) return 11;   /* DisplayControl up */
			if (rc == 10) return 14;  /* AUDIO_INPUT up: send Version */
			if (rc == 1) return 2;
			if (rc == 3 && gfx_data != NULL && gfx_len > 0) {
				const uint8_t *gp = gfx_data;
				size_t gl = gfx_len;
				uint16_t cmdId;
				if (gl < 2) return 1;
				cmdId = (uint16_t)gp[0]
					| ((uint16_t)gp[1] << 8);
				if (cmdId == RDPGFX_CMDID_CAPSADVERTISE) {
					if (out_gfx) *out_gfx = gp;
					if (out_gfx_len) *out_gfx_len = gl;
					return 4;
				}
				if (cmdId == RDPGFX_CMDID_FRAMEACKNOWLEDGE) {
					if (out_gfx) *out_gfx = gp;
					if (out_gfx_len) *out_gfx_len = gl;
					return 6;
				}
			}
			/* AUDIO_INPUT (MS-RDPEAI) SNDIN PDU: surface it for the
			 * proxy loop, which drives the negotiation and forwards
			 * captured audio to the session. */
			if (rc == 9 && gfx_data != NULL && gfx_len > 0) {
				if (out_gfx) *out_gfx = gfx_data;
				if (out_gfx_len) *out_gfx_len = gfx_len;
				return 13;
			}
			if (rc == 11) return 15;  /* RDPEI up: send SC_READY */
			/* RDPEI (MS-RDPEI) PDU: surface it for the proxy loop,
			 * which parses the contacts and forwards them to the
			 * session. */
			if (rc == 12 && gfx_data != NULL && gfx_len > 0) {
				if (out_gfx) *out_gfx = gfx_data;
				if (out_gfx_len) *out_gfx_len = gfx_len;
				return 16;
			}
			if (rc == 13) return 17;  /* camera enumerator up */
			if (rc == 14) return 18;  /* camera device up: Activate */
			/* Camera enumerator/device PDU: surface it for the proxy
			 * loop, which drives the negotiation and forwards frames. */
			if (rc == 15 && gfx_data != NULL && gfx_len > 0) {
				if (out_gfx) *out_gfx = gfx_data;
				if (out_gfx_len) *out_gfx_len = gfx_len;
				return 19;
			}
			if (rc == 16 && gfx_data != NULL && gfx_len > 0) {
				if (out_gfx) *out_gfx = gfx_data;
				if (out_gfx_len) *out_gfx_len = gfx_len;
				return 20;
			}
		}
		return 1;
	}

	/* RDPSND channel: audio format negotiation + wave confirm. */
	if (ss->enabled && cid == ss->channel_id) {
		if (payload_len < 8) return 1;
		(void)rdp_rdpsnd_handle(&ss->snd, payload + 8,
			payload_len - 8, g_prefer_wan_audio);
		return 1;
	}

	/* RAIL channel (MS-RDPERP): consume the client's HANDSHAKE,
	 * CLIENTSTATUS and SYSPARAM orders, and acknowledge an EXEC launch
	 * request with EXEC_RESULT.  The order follows the 8-byte virtual
	 * channel header. */
	if (g_remoteapp && g_rail.enabled && cid == g_rail.channel_id) {
		struct rdp_rail_order o;
		if (payload_len < 8) return 1;
		if (rdp_rail_parse_order(payload + 8, payload_len - 8, &o) == 0
		    && o.order_type == RAIL_ORDER_EXEC) {
			uint8_t er[560];
			uint16_t el = o.exe_len > 520 ? 520 : o.exe_len;
			ssize_t en = rdp_rail_build_exec_result(er, sizeof er,
				o.exec_flags, RAIL_EXEC_S_OK, 0, o.exe, el);
			if (en > 0)
				(void)send_clip_pdu(t, uid, g_rail.channel_id,
					er, (size_t)en);
		}
		return 1;
	}

	/* RDPDR channel: device redirection. */
	if (dr->enabled && cid == dr->channel_id) {
		if (payload_len < 8) return 1;
		{
			uint8_t resp[4096];
			size_t resp_len = 0;
			struct rdpdr_completion compl_info;
			int rc;
			memset(&compl_info, 0, sizeof compl_info);
			rc = rdp_rdpdr_handle(&dr->dr,
				payload + 8, payload_len - 8,
				resp, sizeof resp, &resp_len,
				&compl_info);
			{
				size_t roff = 0;
				while (roff + 4 <= resp_len) {
					uint16_t rcomp = (uint16_t)resp[roff]
					    | ((uint16_t)resp[roff+1] << 8);
					uint16_t rpid = (uint16_t)resp[roff+2]
					    | ((uint16_t)resp[roff+3] << 8);
					size_t plen = rdp_rdpdr_pdu_len(
					    rcomp, rpid,
					    resp + roff, resp_len - roff);
					if (plen == 0 || roff + plen > resp_len)
						break;
					(void)send_clip_pdu(t, uid,
					    dr->channel_id,
					    resp + roff, plen);
					roff += plen;
				}
			}
			/* Route the completion.  A completion for a printer
			 * device drives the per-job print state machine; a
			 * completion for any other device becomes an FS_RSP to
			 * the session.  The two never share a completion id, so
			 * the device type of the completing device decides. */
			if (rc == 1 && dr_is_printer_device(dr,
			    compl_info.device_id)) {
				print_job_on_completion(t, uid, dr,
				    &compl_info);
			} else if (rc == 1 && be_fd >= 0) {
				struct rdp_be_fs_rsp rsp;
				rsp.req_id = compl_info.be_req_id;
				rsp.status = compl_info.io_status;
				rsp.file_id = 0;
				rsp.length = (uint32_t)compl_info.data_len;
				if (compl_info.major_function == IRP_MJ_CREATE
				    && compl_info.data_len >= 4)
					rsp.file_id = ld32_safe(
					    compl_info.data);
				if (rdp_be_send(be_fd, RDP_BE_FS_RSP,
				    &rsp, sizeof rsp) == 0
				    && compl_info.data_len > 0
				    && compl_info.major_function
				    != IRP_MJ_CREATE)
					(void)rdp_write_full(be_fd,
					    compl_info.data,
					    compl_info.data_len);
			}
			/* Announce any newly enumerated drives and printers to
			 * the session.  The device list is parsed inside
			 * rdp_rdpdr_handle, so we scan for unannounced devices
			 * here.  Drives become an FS_DEVICE (the FUSE mount
			 * presents them); printers become a PRINTER_DEVICE. */
			if (be_fd >= 0) {
				uint32_t di;
				for (di = 0; di < dr->dr.device_count
				    && di < RDPDR_MAX_DEVICES; di++) {
					struct rdpdr_device *d =
					    &dr->dr.devices[di];
					if (!d->in_use || d->announced)
						continue;
					if (d->device_type
					    == RDPDR_DTYP_FILESYSTEM) {
						struct rdp_be_fs_device fsd;
						memset(&fsd, 0, sizeof fsd);
						fsd.device_id = d->device_id;
						fsd.device_type = d->device_type;
						fsd.added = 1;
						memcpy(fsd.name, d->name,
						    sizeof d->name);
						if (rdp_be_send(be_fd,
						    RDP_BE_FS_DEVICE,
						    &fsd, sizeof fsd) == 0)
							d->announced = 1;
					} else if (d->device_type
					    == RDPDR_DTYP_PRINT) {
						struct rdp_be_printer_device pd;
						memset(&pd, 0, sizeof pd);
						pd.device_id = d->device_id;
						pd.flags = d->is_default
						    ? RDP_BE_PRINTER_FLAG_DEFAULT
						    : 0u;
						memcpy(pd.name, d->printer_name,
						    sizeof pd.name);
						pd.name[sizeof pd.name - 1] =
						    '\0';
						memcpy(pd.driver,
						    d->driver_name,
						    sizeof pd.driver);
						pd.driver[sizeof pd.driver - 1] =
						    '\0';
						if (rdp_be_send(be_fd,
						    RDP_BE_PRINTER_DEVICE,
						    &pd, sizeof pd) == 0)
							d->announced = 1;
					}
				}
			}
		}
		return 1;
	}

	/* On the I/O channel, look for share-data PDUs we care about:
	 * Shutdown Request -> answer with Shutdown Request Denied so
	 * the client sends a graceful MCS Disconnect. */
	if (cid == RDP_MCS_IO_CHANNEL_ID && payload_len >= 6) {
		uint16_t ptype = (uint16_t)(payload[2] | (payload[3] << 8));
		if ((ptype & 0x0f) == RDP_PDU_TYPE_DATA && payload_len >= 18) {
			uint8_t pdu_type2 = payload[14];
			if (pdu_type2 == RDP_PDU2_FONTLIST) {
				uint8_t fm[64];
				ssize_t fn = rdp_pdu_build_font_map(
					fm, sizeof fm, uid,
					RDP_CONN_SHARE_ID);
				if (fn > 0)
					(void)send_send_data(t, uid,
						RDP_MCS_IO_CHANNEL_ID,
						fm, (size_t)fn);
				return 1;
			}
			/* The Persistent Key List PDU is part of the connection
			 * finalization sequence (MS-RDPBCGR 2.2.1.17) and so is
			 * read and ingested by the finalization reader in
			 * run_proxy, not here in the steady-state dispatcher. */
			if (pdu_type2 == RDP_PDU2_SUPPRESS_OUTPUT) {
				/* allowDisplayUpdates is the first body
				 * byte (payload[18]): 0 = suppress output,
				 * else allow.  Pause or resume the stream. */
				if (payload_len >= 19 && payload[18] == 0)
					return 8;
				return 9;
			}
			if (pdu_type2 == RDP_PDU2_REFRESH_RECT) {
				/* Client wants a region redrawn; make sure
				 * output is flowing again. */
				return 9;
			}
			if (pdu_type2 == RDP_PDU2_SHUTDOWN_REQUEST) {
				/* Build a Shutdown Denied PDU and send back.
				 * The client should follow up with MCS
				 * Disconnect Provider Ultimatum. */
				uint8_t out[64];
				uint16_t total = 18;
				ssize_t r;
				rdp_debug("conn[%s]: shutdown request",
					peer);
				r = rdp_pdu_build_share_data(out, sizeof out,
					1007 /* worker user id */,
					0x000103EAu,
					RDP_PDU2_SHUTDOWN_DENIED, total);
				if (r == 18) {
					(void)send_send_data(t, 1007,
						RDP_MCS_IO_CHANNEL_ID,
						out, (size_t)total);
				}
				return 1;
			}
		}
	}
	return 0;
}

/* Run Deactivate-All + re-Demand-Active + finalization at a new
 * desktop size.  Returns 0 on success. */
static int
do_reactivate(struct rdp_tls *t, int be_fd, uint16_t user_id,
		uint16_t io_channel, uint16_t new_w, uint16_t new_h,
		const char *peer)
{
	uint8_t pdu[2200];
	ssize_t n;

	rdp_info("conn[%s]: reactivate %ux%u", peer, new_w, new_h);

	/* 1. Deactivate-All */
	n = rdp_pdu_build_deactivate_all(pdu, sizeof pdu, user_id,
		RDP_CONN_SHARE_ID);
	if (n < 0) return -1;
	if (send_send_data(t, user_id, io_channel, pdu, (size_t)n) != 0)
		return -1;

	/* 2. New Demand Active */
	{
		uint8_t caps[2048];
		ssize_t cn = rdp_capset_build_demand_active(caps, sizeof caps,
			RDP_CONN_SHARE_ID, new_w, new_h, g_remoteapp, g_allow_bitmap_cache);
		if (cn < 0) return -1;
		{
			ssize_t hdr_n = rdp_pdu_build_share_control(pdu,
				sizeof pdu, RDP_PDU_TYPE_DEMAND_ACTIVE,
				user_id, (uint16_t)(cn + 6));
			if (hdr_n < 0) return -1;
			memcpy(pdu + hdr_n, caps, (size_t)cn);
			if (send_send_data(t, user_id, io_channel,
				pdu, (size_t)hdr_n + (size_t)cn) != 0)
				return -1;
		}
	}

	/* 3. Read Confirm Active (skip other PDUs the client may send) */
	{
		uint8_t buf[0x4000];
		int got_confirm = 0;
		int tries;
		for (tries = 0; tries < 20 && !got_confirm; tries++) {
			int kind = 0;
			ssize_t r = read_one_rdp_pdu(t, buf, sizeof buf, &kind);
			if (r <= 0) return -1;
			if (kind == 1) {
				const uint8_t *mcs_p;
				size_t mcs_len;
				uint16_t uid, cid;
				const uint8_t *payload;
				size_t payload_len;
				if (strip_tpkt_x224(buf, (size_t)r,
				    &mcs_p, &mcs_len) == 0) {
					if (mcs_p[0] == RDP_MCS_TYPE_SEND_DATA_REQ) {
						if (rdp_mcs_parse_send_data_request(
						    mcs_p, mcs_len, &uid, &cid,
						    &payload, &payload_len) >= 0
						    && payload_len >= 8) {
							uint16_t ptype =
							    (uint16_t)(payload[2]
							    | (payload[3] << 8));
							if ((ptype & 0x0f) ==
							    RDP_PDU_TYPE_CONFIRM_ACTIVE)
								got_confirm = 1;
						}
					}
				}
			}
		}
		if (!got_confirm) return -1;
	}

	/* 4. Server finalization first, then client responds in parallel. */
	n = rdp_pdu_build_synchronize(pdu, sizeof pdu, user_id,
		RDP_CONN_SHARE_ID, 1002);
	if (n < 0 ||
		send_send_data(t, user_id, io_channel, pdu, (size_t)n) != 0)
		return -1;
	n = rdp_pdu_build_control(pdu, sizeof pdu, user_id,
		RDP_CONN_SHARE_ID, RDP_CTRL_COOPERATE, 0, 0);
	if (n < 0 ||
		send_send_data(t, user_id, io_channel, pdu, (size_t)n) != 0)
		return -1;
	n = rdp_pdu_build_control(pdu, sizeof pdu, user_id,
		RDP_CONN_SHARE_ID, RDP_CTRL_GRANTED_CONTROL, 1002, 1002);
	if (n < 0 ||
		send_send_data(t, user_id, io_channel, pdu, (size_t)n) != 0)
		return -1;
	n = rdp_pdu_build_font_map(pdu, sizeof pdu, user_id,
		RDP_CONN_SHARE_ID);
	if (n < 0 ||
		send_send_data(t, user_id, io_channel, pdu, (size_t)n) != 0)
		return -1;

	/* 5. Tell the backend to resize. */
	{
		struct rdp_be_resize rs = { new_w, new_h, {0, 0} };
		(void)rdp_be_send(be_fd, RDP_BE_RESIZE, &rs, sizeof rs);
	}

	/* 7. Send Synchronize + Pointer Default. */
	{
		uint8_t fp[64];
		ssize_t fn;
		fn = rdp_fp_build_synchronize(fp, sizeof fp);
		if (fn > 0) (void)rdp_tls_write_full(t, fp, (size_t)fn);
		fn = rdp_fp_build_pointer_default(fp, sizeof fp);
		if (fn > 0) (void)rdp_tls_write_full(t, fp, (size_t)fn);
	}
	return 0;
}

/* Post-login proxy loop: shovel fast-path input from TLS to backend,
 * shovel FRAME messages from backend to fast-path bitmap updates,
 * and dispatch CLIPRDR + DRDYNVC PDUs in both directions. */
/* Helper: send a DRDYNVC Data PDU containing `data[0..len)` on the
 * given DRDYNVC sub-channel `dv_chan`.  Wraps in DRDYNVC framing +
 * CHANNEL_PDU_HEADER + MCS SDI. */
static int
send_drdynvc_data(struct rdp_tls *t, uint16_t user_id,
		uint16_t drdynvc_mcs_chan, int dv_chan,
		const uint8_t *data, size_t len)
{
	uint8_t *buf;
	size_t hdr_off;
	uint8_t cb;

	/* DRDYNVC Data header: cmd=3 in high nibble + cbId in low 2 bits. */
	if (dv_chan <= 0xff) cb = 0;
	else if (dv_chan <= 0xffff) cb = 1;
	else cb = 2;

	hdr_off = 1 + (cb == 0 ? 1 : (cb == 1 ? 2 : 4));
	buf = malloc(hdr_off + len);
	if (buf == NULL) return -1;
	buf[0] = (uint8_t)((DRDYNVC_CMD_DATA << 4) | cb);
	if (cb == 0) buf[1] = (uint8_t)dv_chan;
	else if (cb == 1) {
		buf[1] = (uint8_t)(dv_chan & 0xff);
		buf[2] = (uint8_t)((dv_chan >> 8) & 0xff);
	} else {
		buf[1] = (uint8_t)(dv_chan & 0xff);
		buf[2] = (uint8_t)((dv_chan >> 8) & 0xff);
		buf[3] = (uint8_t)((dv_chan >> 16) & 0xff);
		buf[4] = (uint8_t)((dv_chan >> 24) & 0xff);
	}
	memcpy(buf + hdr_off, data, len);
	{
		int rc = send_clip_pdu(t, user_id, drdynvc_mcs_chan,
			buf, hdr_off + len);
		free(buf);
		return rc;
	}
}

/* RDP8 bulk segment descriptors (MS-RDPEGFX 2.2.5.1 / FreeRDP zgfx.h). */
#define ZGFX_SEGMENTED_SINGLE       0xE0
#define ZGFX_SEGMENTED_MULTIPART    0xE1
#define ZGFX_PACKET_COMPR_TYPE_RDP8 0x04
/* Max payload per segment: stay at/under the client's 64 KiB buffer. */
#define ZGFX_SEG_MAX                65535

/* Wrap a GFX PDU in the RDP8 bulk-encoded (uncompressed) framing and
 * send it on the DRDYNVC sub-channel.  PDUs up to ZGFX_SEG_MAX go in a
 * single segment; larger ones are split into a multipart series so the
 * client's 64 KiB per-segment decode buffer is never overrun. */
static int
send_gfx_pdu(struct rdp_tls *t, uint16_t user_id,
		uint16_t drdynvc_mcs_chan, int dv_chan,
		const uint8_t *data, size_t len)
{
	uint8_t *zbuf;
	size_t zlen;
	int rc;

	if (len <= ZGFX_SEG_MAX) {
		/* Single uncompressed RDP8 segment. */
		zlen = 2 + len;
		zbuf = malloc(zlen);
		if (zbuf == NULL)
			return -1;
		zbuf[0] = ZGFX_SEGMENTED_SINGLE;
		zbuf[1] = ZGFX_PACKET_COMPR_TYPE_RDP8;
		memcpy(zbuf + 2, data, len);
	} else {
		/* Multipart: descriptor + segmentCount + uncompressedSize,
		 * then per chunk a segmentSize + flags byte + data.  Each
		 * chunk payload is capped at ZGFX_SEG_MAX so the client's
		 * 64 KiB segment buffer is never overrun. */
		size_t nseg = (len + ZGFX_SEG_MAX - 1) / ZGFX_SEG_MAX;
		size_t i, off = 0;
		uint8_t *p;

		zlen = 7 + nseg * 5 + len;
		zbuf = malloc(zlen);
		if (zbuf == NULL)
			return -1;
		p = zbuf;
		*p++ = ZGFX_SEGMENTED_MULTIPART;
		*p++ = (uint8_t)(nseg & 0xff);
		*p++ = (uint8_t)((nseg >> 8) & 0xff);
		*p++ = (uint8_t)(len & 0xff);
		*p++ = (uint8_t)((len >> 8) & 0xff);
		*p++ = (uint8_t)((len >> 16) & 0xff);
		*p++ = (uint8_t)((len >> 24) & 0xff);
		for (i = 0; i < nseg; i++) {
			size_t chunk = len - off;
			uint32_t segsz;

			if (chunk > ZGFX_SEG_MAX)
				chunk = ZGFX_SEG_MAX;
			segsz = (uint32_t)(chunk + 1);  /* incl. flags byte */
			*p++ = (uint8_t)(segsz & 0xff);
			*p++ = (uint8_t)((segsz >> 8) & 0xff);
			*p++ = (uint8_t)((segsz >> 16) & 0xff);
			*p++ = (uint8_t)((segsz >> 24) & 0xff);
			*p++ = ZGFX_PACKET_COMPR_TYPE_RDP8;
			memcpy(p, data + off, chunk);
			p += chunk;
			off += chunk;
		}
	}

	rc = send_drdynvc_data(t, user_id, drdynvc_mcs_chan, dv_chan,
		zbuf, zlen);
	free(zbuf);
	return rc;
}

static void
ensure_gfx_surface(struct rdp_tls *t, uint16_t user_id,
		struct dynvc_state *dv, struct rdpgfx_state *gfx,
		uint16_t desktop_w, uint16_t desktop_h)
{
	uint8_t gbuf[512];
	ssize_t gn;

	if (gfx->surface_created || dv->dv.gfx_channel_id < 0)
		return;
	gn = rdp_rdpgfx_build_reset(gbuf, sizeof gbuf, desktop_w, desktop_h);
	if (gn > 0)
		(void)send_gfx_pdu(t, user_id, dv->channel_id,
			dv->dv.gfx_channel_id, gbuf, (size_t)gn);
	gn = rdp_rdpgfx_build_create_surface(gbuf, sizeof gbuf,
		gfx->surface_id, desktop_w, desktop_h);
	if (gn > 0)
		(void)send_gfx_pdu(t, user_id, dv->channel_id,
			dv->dv.gfx_channel_id, gbuf, (size_t)gn);
	gn = rdp_rdpgfx_build_map_surface(gbuf, sizeof gbuf,
		gfx->surface_id, desktop_w, desktop_h);
	if (gn > 0)
		(void)send_gfx_pdu(t, user_id, dv->channel_id,
			dv->dv.gfx_channel_id, gbuf, (size_t)gn);
	gfx->surface_created = 1;
}

/* Set per worker from rdp_conn_cfg; gates whether GFX AVC is offered to
 * clients that advertise v10.x without AVC_DISABLED (mstsc, macOS). */
static int g_allow_v10_avc;
static int g_allow_progressive;
static int g_allow_avc444;
static int g_allow_autodetect;

/* Apply one camera negotiation action: send the request/response on the right
 * camera channel, open the per-device channel when a camera is announced, and
 * forward one raw frame to the session as an RDP_BE_CAMERA message. */
static void
cam_forward_action(struct rdp_tls *t, uint32_t user_id, int be_fd,
		struct dynvc_state *dv, const struct rdp_cam_action *act)
{
	if (act->send_chan == 0 && act->send_len > 0
	    && dv->dv.camenum_channel_id >= 0)
		(void)send_drdynvc_data(t, user_id, dv->channel_id,
			dv->dv.camenum_channel_id, act->send, act->send_len);
	else if (act->send_chan == 1 && act->send_len > 0
	    && dv->dv.camdev_channel_id >= 0)
		(void)send_drdynvc_data(t, user_id, dv->channel_id,
			dv->dv.camdev_channel_id, act->send, act->send_len);

	if (act->open_device && !dv->dv.camdev_create_pending
	    && dv->dv.camdev_channel_id < 0) {
		uint8_t cc[300];
		ssize_t cn = rdp_drdynvc_build_create_cam_device(&dv->dv,
			act->dev_name, act->dev_name_len, cc, sizeof cc);
		if (cn > 0)
			(void)send_clip_pdu(t, user_id, dv->channel_id,
				cc, (size_t)cn);
	}

	/* Camera unplugged: close the device channel and reset its id so a
	 * later DeviceAdded re-opens it. */
	if (act->close_device && dv->dv.camdev_channel_id > 0) {
		uint8_t cl[8];
		ssize_t cn = rdp_drdynvc_build_close_cam_device(&dv->dv,
			cl, sizeof cl);
		if (cn > 0)
			(void)send_clip_pdu(t, user_id, dv->channel_id,
				cl, (size_t)cn);
	}

	if (act->have_frame && act->frame != NULL && act->frame_len > 0
	    && act->frame_len <= RDP_BE_CAMERA_MAX) {
		size_t need = sizeof(struct rdp_be_camera) + act->frame_len;
		struct rdp_be_camera ch;
		if (need > dv->cam_frame_cap) {
			uint8_t *nb = realloc(dv->cam_frame, need);
			if (nb == NULL) return;        /* drop this frame */
			dv->cam_frame = nb;
			dv->cam_frame_cap = need;
		}
		memset(&ch, 0, sizeof ch);
		ch.format = act->frame_fmt.format;
		ch.width = act->frame_fmt.width;
		ch.height = act->frame_fmt.height;
		ch.size = (uint32_t)act->frame_len;
		memcpy(dv->cam_frame, &ch, sizeof ch);
		memcpy(dv->cam_frame + sizeof ch, act->frame, act->frame_len);
		(void)rdp_be_send(be_fd, RDP_BE_CAMERA, dv->cam_frame, need);
	}
}

/* Send a Set Error Info PDU so the client shows a disconnect reason instead of
 * a bare drop.  Only valid on an activated connection. */
static void
send_error_info(struct rdp_tls *t, uint16_t user_id, uint16_t io_channel,
		uint32_t code)
{
	uint8_t ei[128];
	ssize_t en = rdp_pdu_build_set_error_info(ei, sizeof ei, user_id,
		RDP_CONN_SHARE_ID, code);
	if (en > 0)
		(void)send_send_data(t, user_id, io_channel, ei, (size_t)en);
}

static void
run_proxy(struct rdp_tls *t, int be_fd,
		struct clip_state *cs, struct dynvc_state *dv,
		struct snd_state *ss, struct dr_state *dr,
		uint16_t user_id, uint16_t io_channel,
		uint16_t desktop_w, uint16_t desktop_h,
		uint32_t client_max_request,
		uint16_t client_color_ptr, uint16_t client_large_ptr,
		uint16_t client_pointer_cache_size,
		const char *peer)
{
	struct proxy_input_ctx ictx;
	memset(&ictx, 0, sizeof ictx);
	ictx.be_fd = be_fd;
	/* Largest cursor edge we may send: 96x96 only when the client
	 * advertises the large-pointer flag, else the legacy 32x32.  A New
	 * Pointer update must fit one fast-path PDU, which caps a 32bpp
	 * cursor body near 60x60, so clamp there and scale larger cursors
	 * down to fit. */
	uint16_t ptr_maxdim = (client_large_ptr & 0x0001) ? 96 : 32;
	int can_color_ptr = (client_color_ptr != 0);
	if (ptr_maxdim > 60) ptr_maxdim = 60;
	/* Pointer cache: bound the client's advertised slot count to our
	 * table, and disable caching when color pointers are unsupported. */
	ictx.ptr_cache_n = client_pointer_cache_size;
	if (ictx.ptr_cache_n > PROXY_PTR_CACHE_MAX)
		ictx.ptr_cache_n = PROXY_PTR_CACHE_MAX;
	if (!can_color_ptr)
		ictx.ptr_cache_n = 0;
	uint8_t *frame_buf = NULL;
	size_t   frame_cap = 0;
	struct rdpgfx_state gfx = {0};
	struct rdp_h264 *h264 = NULL;
	struct rdp_avc444 *avc444 = NULL;
	struct rdp_progressive *prog = NULL;
	int output_suppressed = 0;
	int backend_lost = 0;
	/* Largest fast-path PDU we will emit per bitmap fragment.  Honour
	 * the client's MultifragmentUpdate MaxRequestSize when present,
	 * never exceeding our own safe ceiling.  Floor it so the per-slice
	 * header (6 bytes) never underflows and fragments stay sensible. */
	size_t chunk_target = RDP_FP_FRAGMENT_SAFE_SIZE;
	if (client_max_request != 0
	    && client_max_request < (uint32_t)chunk_target)
		chunk_target = (size_t)client_max_request;
	if (chunk_target < 512)
		chunk_target = 512;
	gfx.surface_id = 0;
	gfx.frame_id = 0;
	gfx.desktop_w = desktop_w;
	gfx.desktop_h = desktop_h;

	/* Read client finalization (Sync, Control, Control, FontList)
	 * before initializing channels. */
	{
		uint8_t fbuf[0x4000];
		int _fi;
		for (_fi = 0; _fi < 10; _fi++) {
			int fk = 0;
			ssize_t fr = read_one_rdp_pdu(t, fbuf, sizeof fbuf, &fk);
			if (fr <= 0) break;
			if (fk == 1) {
				const uint8_t *mp;
				size_t ml;
				uint16_t fuid, fcid;
				const uint8_t *fp;
				size_t fl;
				if (strip_tpkt_x224(fbuf, (size_t)fr,
				    &mp, &ml) == 0
				    && mp[0] == RDP_MCS_TYPE_SEND_DATA_REQ
				    && rdp_mcs_parse_send_data_request(
					mp, ml, &fuid, &fcid, &fp, &fl) >= 0
				    && fl >= 18) {
					uint16_t pt = (uint16_t)(fp[2]
						| (fp[3] << 8));
					if ((pt & 0x0f) == RDP_PDU_TYPE_DATA
					    && fp[14] ==
					    RDP_PDU2_BITMAPCACHE_PERSISTENT_LIST
					    && fl > 18) {
						/* The client lists the cached tiles it
						 * already holds on disk from a prior
						 * session; load them so they are recalled
						 * with MemBlt instead of re-sent.  This PDU
						 * arrives in the finalization stream, before
						 * the Font List, so it is ingested here. */
						size_t nk = 0; int pf = 0, pl = 0;
						(void)rdp_bmpcache_parse_persistent_list(
							fp + 18, fl - 18, NULL, 0,
							&nk, &pf, &pl);
						if (g_bmpcache != NULL)
							(void)rdp_bmpcache_ingest_persistent(
								g_bmpcache, fp + 18, fl - 18);
						rdp_debug("conn[%s]: persistent key list: "
							"%zu keys (first=%d last=%d)",
							peer, nk, pf, pl);
					}
					if ((pt & 0x0f) == RDP_PDU_TYPE_DATA
					    && fp[14] == RDP_PDU2_FONTLIST) {
						ssize_t fn =
							rdp_pdu_build_font_map(
							fbuf, sizeof fbuf,
							user_id,
							RDP_CONN_SHARE_ID);
						if (fn > 0)
							(void)send_send_data(t,
								user_id,
								io_channel,
								fbuf,
								(size_t)fn);
						break;
					}
				}
			}
		}
	}

	if (cs->enabled) {
		if (clip_send_monitor_ready_and_caps(t, cs) != 0)
			rdp_warn("conn[%s]: cliprdr init failed", peer);
		else
			rdp_debug("conn[%s]: cliprdr ready (chan=%u)",
				peer, cs->channel_id);
	}
	if (dv->enabled) {
		uint8_t dvcaps[64];
		ssize_t cn = rdp_drdynvc_build_caps(dvcaps, sizeof dvcaps);
		if (cn > 0) {
			rdp_debug("conn[%s]: drdynvc CAPS tx %zd: %02x %02x %02x %02x",
				peer, cn, dvcaps[0], cn>1?dvcaps[1]:0,
				cn>2?dvcaps[2]:0, cn>3?dvcaps[3]:0);
			(void)send_clip_pdu(t, user_id, dv->channel_id,
				dvcaps, (size_t)cn);
		}
	}
	if (ss->enabled) {
		uint8_t fmts[128];
		ssize_t fn = rdp_rdpsnd_build_formats(fmts, sizeof fmts);
		if (fn > 0)
			(void)send_clip_pdu(t, user_id, ss->channel_id,
				fmts, (size_t)fn);
		rdp_debug("conn[%s]: rdpsnd formats sent (chan=%u)",
			peer, ss->channel_id);
	}
	if (dr->enabled) {
		uint8_t ann[16];
		ssize_t an = rdp_rdpdr_build_announce(ann, sizeof ann);
		if (an > 0)
			(void)send_clip_pdu(t, user_id, dr->channel_id,
				ann, (size_t)an);
		rdp_debug("conn[%s]: rdpdr announce sent (chan=%u)",
			peer, dr->channel_id);
	}

	/* Send a fast-path Synchronize + pointer to keep the client
	 * alive while the backend starts. */
	{
		uint8_t fp[64];
		ssize_t fn;
		fn = rdp_fp_build_synchronize(fp, sizeof fp);
		if (fn > 0) (void)rdp_tls_write_full(t, fp, (size_t)fn);
		fn = rdp_fp_build_pointer_default(fp, sizeof fp);
		if (fn > 0) (void)rdp_tls_write_full(t, fp, (size_t)fn);
	}

	/* RemoteApp: the server drives the RAIL handshake once the session is
	 * active; the client then streams its own handshake and orders. */
	if (g_remoteapp && g_rail.enabled && !g_rail.handshake_sent) {
		uint8_t hs[16];
		ssize_t hn = rdp_rail_build_handshake(hs, sizeof hs, 0x00001db0);
		if (hn > 0 && send_clip_pdu(t, user_id, g_rail.channel_id,
			hs, (size_t)hn) == 0) {
			struct rdp_be_rail rl;
			g_rail.handshake_sent = 1;
			rdp_info("conn[%s]: RAIL handshake sent", peer);
			/* Tell the session it is a RemoteApp session so it
			 * switches to per-window RAIL mode and emits WINDOW
			 * geometry events.  Carry the desktop size for the
			 * X11/Xvfb single-window fallback. */
			rl.width = desktop_w;
			rl.height = desktop_h;
			(void)rdp_be_send(be_fd, RDP_BE_RAIL, &rl, sizeof rl);
		}
	}

	/* Heartbeat timer: when the client supports the Heartbeat PDU, poll with
	 * a finite timeout and emit a heartbeat every period so an idle session
	 * is not dropped by the client's connection-health check. */
	struct timespec hb_next = {0, 0};
	int hb_on = g_client_heartbeat && g_heartbeat_chan != 0;
	if (hb_on) {
		clock_gettime(CLOCK_MONOTONIC, &hb_next);
		hb_next.tv_sec += HEARTBEAT_PERIOD_S;
	}

	for (;;) {
		struct pollfd pfd[2];
		int tls_fd = rdp_tls_fd(t);
		int timeout = -1;

		pfd[0].fd = tls_fd;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		pfd[1].fd = be_fd;
		pfd[1].events = POLLIN;
		pfd[1].revents = 0;
		if (hb_on) {
			struct timespec now = {0, 0};
			long ms;
			clock_gettime(CLOCK_MONOTONIC, &now);
			ms = (hb_next.tv_sec - now.tv_sec) * 1000
			    + (hb_next.tv_nsec - now.tv_nsec) / 1000000;
			timeout = ms > 0 ? (int)ms : 0;
		}
		if (poll(pfd, 2, timeout) < 0) {
			if (errno == EINTR) continue;
			break;
		}
		if (hb_on) {
			struct timespec now = {0, 0};
			clock_gettime(CLOCK_MONOTONIC, &now);
			if (now.tv_sec > hb_next.tv_sec
			    || (now.tv_sec == hb_next.tv_sec
				&& now.tv_nsec >= hb_next.tv_nsec)) {
				(void)send_heartbeat(t, user_id,
					g_heartbeat_chan);
				hb_next = now;
				hb_next.tv_sec += HEARTBEAT_PERIOD_S;
			}
		}
		if (pfd[1].revents & (POLLHUP | POLLERR)) {
			rdp_debug("conn[%s]: backend gone (rev=0x%x)",
				peer, pfd[1].revents);
			backend_lost = 1;
			break;
		}

		if (pfd[0].revents & POLLIN) {
			uint8_t pdu[0x4000];
			int kind = 0;
			ssize_t n = read_one_rdp_pdu(t, pdu, sizeof pdu, &kind);
			if (n <= 0) break;
			if (kind == 1) {
				uint16_t rw = 0, rh = 0;
				const uint8_t *gfx_pdu = NULL;
				size_t gfx_pdu_len = 0;
				int r = maybe_dispatch_clip(t, be_fd,
					cs, dv, ss, dr,
					pdu, (size_t)n, peer,
					&rw, &rh,
					&gfx_pdu, &gfx_pdu_len);
				if (r < 0) break;
				if (r == 8) output_suppressed = 1;
				if (r == 9) output_suppressed = 0;
				if (r == 11) {
					/* DisplayControl is up: advertise our
					 * monitor limits so the client may
					 * request a dynamic resize. */
					uint8_t dc[20];
					ssize_t dn =
						rdp_drdynvc_build_disp_caps(
							dc, sizeof dc);
					if (dn > 0) {
						(void)send_drdynvc_data(t,
							user_id,
							dv->channel_id,
							dv->dv.disp_channel_id,
							dc, (size_t)dn);
						rdp_info("conn[%s]: "
							"DisplayControl caps "
							"sent", peer);
					}
				}
				if (r == 7 && gfx.active) {
					rdp_info("conn[%s]: GFX closed, "
						"reverting to bitmap", peer);
					gfx.active = 0;
					if (h264) {
						rdp_h264_close(h264);
						h264 = NULL;
					}
					if (avc444) {
						rdp_avc444_close(avc444);
						avc444 = NULL;
					}
					if (prog) {
						rdp_progressive_close(prog);
						prog = NULL;
					}
				}
				if (r == 2 && rw > 0 && rh > 0) {
					if (do_reactivate(t, be_fd, user_id,
						io_channel, rw, rh, peer) != 0)
						break;
					desktop_w = rw;
					desktop_h = rh;
					gfx.desktop_w = rw;
					gfx.desktop_h = rh;
					if (h264)
						(void)rdp_h264_resize(h264,
							rw, rh);
					if (avc444
					    && rdp_avc444_resize(avc444,
						rw, rh) != 0) {
						/* Resize tore the encoder
						 * down; drop to bitmap
						 * rather than keep a dead
						 * handle. */
						rdp_avc444_close(avc444);
						avc444 = NULL;
					}
					if (prog)
						(void)rdp_progressive_resize(prog,
							rw, rh);
					/* Recreate the GFX surface at the new
					 * size: ensure_gfx_surface re-sends
					 * RESET_GRAPHICS + CreateSurface +
					 * MapSurface on the next frame (which
					 * also forces an IDR for it). */
					gfx.surface_created = 0;
				}
				if (r == 4 && !gfx.active
				    && dv->dv.gfx_channel_id >= 0
				    && gfx_pdu != NULL) {
					struct rdpgfx_caps_advertise adv;
					uint32_t sel_ver, sel_flags;
					enum rdpgfx_codec sel_codec;
					memset(&adv, 0, sizeof adv);
					if (rdp_rdpgfx_parse_caps_advertise(
						gfx_pdu, gfx_pdu_len,
						&adv) == 0
					    && rdp_rdpgfx_select_caps(
						&adv, &sel_ver,
						&sel_flags,
						&sel_codec,
						g_allow_v10_avc,
						g_allow_progressive,
						g_allow_avc444) == 0) {
						/*
						 * Probe the encoder before confirming
						 * the codec. If it will not open, send
						 * no CapsConfirm so the client falls
						 * back to bitmap instead of waiting for
						 * frames that never arrive.
						 */
						if (sel_codec == RDPGFX_CODEC_AVC420)
							h264 = rdp_h264_open(
								desktop_w,
								desktop_h);
						else if (sel_codec
						    == RDPGFX_CODEC_AVC444) {
							avc444 = rdp_avc444_open(
								desktop_w,
								desktop_h);
							/*
							 * AVC444 opens two encoders
							 * and is more failure-prone
							 * than AVC420; the same client
							 * decodes AVC420, so fall back
							 * to it rather than to bitmap.
							 */
							if (avc444 == NULL
							    && (h264 = rdp_h264_open(
								desktop_w,
								desktop_h)) != NULL)
								sel_codec =
									RDPGFX_CODEC_AVC420;
						} else if (sel_codec
						    == RDPGFX_CODEC_CAPROGRESSIVE)
							prog = rdp_progressive_open(
								desktop_w,
								desktop_h);
						if (h264 != NULL || avc444 != NULL
						    || prog != NULL) {
							uint8_t gbuf[512];
							ssize_t gn;
							rdp_info("conn[%s]: GFX caps "
								"ver=0x%08x flags=0x%08x "
								"codec=%d",
								peer, sel_ver,
								sel_flags,
								(int)sel_codec);
							gn = rdp_rdpgfx_build_caps_confirm(
								gbuf, sizeof gbuf,
								sel_ver, sel_flags);
							if (gn > 0)
								(void)send_gfx_pdu(t,
									user_id,
									dv->channel_id,
									dv->dv.gfx_channel_id,
									gbuf, (size_t)gn);
							gfx.active = 1;
							gfx.codec = sel_codec;
							rdp_info("conn[%s]: GFX caps "
								"confirmed", peer);
						} else {
							rdp_warn("conn[%s]: GFX codec "
								"unavailable, bitmap mode",
								peer);
						}
					} else {
						rdp_info("conn[%s]: no GFX caps, "
							"bitmap mode", peer);
					}
				}
				if (r == 6 && gfx_pdu != NULL) {
					uint32_t aq, af, at;
					if (rdp_rdpgfx_parse_frame_ack(
						gfx_pdu, gfx_pdu_len,
						&aq, &af, &at) == 0) {
						gfx.last_ack_frame = af;
						gfx.queue_depth = aq;
					}
				}
				if (r == 14 && dv->dv.audioin_channel_id >= 0) {
					/* AUDIO_INPUT channel is open: kick off
					 * the MS-RDPEAI negotiation by sending the
					 * server Version PDU; the client's reply
					 * drives rdp_sndin_handle from there. */
					uint8_t vpdu[16];
					ssize_t vn = rdp_sndin_build_version(
						vpdu, sizeof vpdu);
					if (vn > 0) {
						(void)send_drdynvc_data(t,
							user_id,
							dv->channel_id,
							dv->dv.audioin_channel_id,
							vpdu, (size_t)vn);
						dv->sndin.phase =
						    SNDIN_VERSION_SENT;
					}
				}
				if (r == 13 && gfx_pdu != NULL
				    && dv->dv.audioin_channel_id >= 0) {
					/* MS-RDPEAI SNDIN PDU: advance the
					 * negotiation, send any reply over the
					 * AUDIO_INPUT subchannel, and forward
					 * captured PCM to the session in chunks
					 * bounded at RDP_BE_AUDIO_INPUT_MAX. */
					uint8_t sout[64];
					size_t sout_len = 0;
					const uint8_t *aud = NULL;
					size_t aud_len = 0;
					(void)rdp_sndin_handle(&dv->sndin,
						gfx_pdu, gfx_pdu_len,
						sout, sizeof sout, &sout_len,
						&aud, &aud_len);
					if (sout_len > 0)
						(void)send_drdynvc_data(t,
							user_id,
							dv->channel_id,
							dv->dv.audioin_channel_id,
							sout, sout_len);
					while (aud != NULL && aud_len > 0) {
						size_t chunk = aud_len;
						if (chunk > RDP_BE_AUDIO_INPUT_MAX)
							chunk =
							    RDP_BE_AUDIO_INPUT_MAX;
						(void)rdp_be_send(be_fd,
							RDP_BE_AUDIO_INPUT,
							aud, chunk);
						aud += chunk;
						aud_len -= chunk;
					}
				}
				if (r == 15 && dv->dv.rdpei_channel_id >= 0) {
					/* RDPEI channel is open: send the
					 * SC_READY PDU advertising our protocol
					 * version; the client's CS_READY reply
					 * starts the touch frame stream. */
					uint8_t scr[32];
					ssize_t scn = rdp_rdpei_build_sc_ready(
						scr, sizeof scr,
						RDPEI_PROTOCOL_V1);
					if (scn > 0)
						(void)send_drdynvc_data(t,
							user_id,
							dv->channel_id,
							dv->dv.rdpei_channel_id,
							scr, (size_t)scn);
				}
				if (r == 16 && gfx_pdu != NULL
				    && dv->dv.rdpei_channel_id >= 0) {
					/* MS-RDPEI PDU: parse the contacts and,
					 * for a TOUCH or PEN frame, forward them
					 * to the session as an INPUT_TOUCH
					 * backend message.  CS_READY just gets a
					 * debug log; the stream flows from there. */
					struct rdp_rdpei_event ev;
					memset(&ev, 0, sizeof ev);
					if (rdp_rdpei_parse_event(gfx_pdu,
						gfx_pdu_len, &ev) == 0) {
						if (ev.event_id
						    == RDPEI_EVENTID_CS_READY) {
							rdp_debug("conn[%s]: RDPEI "
								"CS_READY ver=0x%08x "
								"maxContacts=%u",
								peer,
								ev.cs_version,
								ev.cs_max_contacts);
						} else if ((ev.event_id
						    == RDPEI_EVENTID_TOUCH
						    || ev.event_id
						    == RDPEI_EVENTID_PEN)
						    && ev.contact_count > 0) {
							uint8_t tbuf[sizeof(
							    struct rdp_be_input_touch)
							    + RDPEI_MAX_CONTACTS
							    * sizeof(struct
							    rdp_be_touch_contact)];
							struct rdp_be_input_touch th;
							size_t off = 0, ci;
							uint32_t n_ct =
								ev.contact_count;
							if (n_ct > RDPEI_MAX_CONTACTS)
								n_ct =
								    RDPEI_MAX_CONTACTS;
							th.count = n_ct;
							memcpy(tbuf, &th,
								sizeof th);
							off = sizeof th;
							for (ci = 0; ci < n_ct;
							    ci++) {
								struct
								rdp_be_touch_contact tc;
								tc.id = ev.contacts[ci].id;
								tc.is_pen = (uint8_t)
								    (ev.contacts[ci].is_pen
								    ? 1 : 0);
								tc.flags = (uint16_t)
								    ev.contacts[ci].flags;
								tc.x = ev.contacts[ci].x;
								tc.y = ev.contacts[ci].y;
								tc.pressure =
								    ev.contacts[ci].pressure;
								memcpy(tbuf + off,
									&tc,
									sizeof tc);
								off += sizeof tc;
							}
							(void)rdp_be_send(be_fd,
								RDP_BE_INPUT_TOUCH,
								tbuf, off);
						}
					}
				}
				if (r == 18) {
					/* Camera device channel open: send the
					 * Activate to start the device negotiation. */
					struct rdp_cam_action act;
					if (rdp_cam_device_opened(&dv->cam,
						&act) == 0)
						cam_forward_action(t, user_id,
							be_fd, dv, &act);
				}
				if ((r == 19 || r == 20) && gfx_pdu != NULL) {
					/* Camera PDU on the enumerator (19) or
					 * device (20) channel: drive the
					 * negotiation and forward frames. */
					struct rdp_cam_action act;
					int ch = (r == 19) ? 0 : 1;
					if (rdp_cam_negotiate(&dv->cam, ch,
						gfx_pdu, gfx_pdu_len, &act) == 0)
						cam_forward_action(t, user_id,
							be_fd, dv, &act);
				}
				/* r == 17 (camera enumerator up): nothing to
				 * send; the client now sends SelectVersionRequest. */
				/* Untouched TPKTs (Shutdown, etc.) silently
				 * ignored.  MCS Disconnect already handled. */
			} else {
				(void)rdp_fp_parse_input(pdu, (size_t)n,
					on_input_event, &ictx, NULL);
			}
		}
		if (pfd[1].revents & POLLIN) {
			uint32_t type;
			uint8_t hdr[RDP_BE_HEADER];
			ssize_t hr;
			uint32_t len;

			hr = rdp_read_full(be_fd, hdr, RDP_BE_HEADER);
			if (hr <= 0) { backend_lost = 1; break; }
			type = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8)
				| ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
			len = (uint32_t)hdr[4] | ((uint32_t)hdr[5] << 8)
				| ((uint32_t)hdr[6] << 16) | ((uint32_t)hdr[7] << 24);
			if (type == RDP_BE_FRAME) {
				struct rdp_be_frame_hdr fhdr;
				size_t pix_bytes;
				if (rdp_read_full(be_fd, &fhdr,
					sizeof fhdr) != sizeof fhdr)
					break;
				pix_bytes = (size_t)fhdr.w * fhdr.h * 3;
				if (pix_bytes > frame_cap) {
					free(frame_buf);
					frame_buf = malloc(pix_bytes);
					frame_cap = pix_bytes;
					if (frame_buf == NULL) break;
				}
				if (rdp_read_full(be_fd, frame_buf, pix_bytes)
				    != (ssize_t)pix_bytes)
					break;
				/* Client suppressed output (minimized): drain
				 * the frame but neither encode nor send it. */
				if (output_suppressed)
					continue;
				if (gfx.active && h264 != NULL
				    && dv->dv.gfx_channel_id >= 0) {
					int fresh = !gfx.surface_created;
					ensure_gfx_surface(t, user_id, dv,
						&gfx, desktop_w, desktop_h);
					if (fresh && gfx.surface_created)
						rdp_h264_force_idr(h264);
					if (rdp_rdpgfx_may_send_frame(&gfx)) {
						const uint8_t *h264_out;
						size_t h264_len;
						int keyframe;
						if (rdp_h264_encode(h264,
							frame_buf, fhdr.w,
							fhdr.h,
							&h264_out, &h264_len,
							&keyframe) == 0
						    && h264_out != NULL
						    && h264_len > 0) {
							uint8_t *gpdu;
							size_t gpdu_cap =
								h264_len + 256;
							gpdu = malloc(gpdu_cap);
							if (gpdu != NULL) {
								ssize_t gn;
								int gw, gh;
								rdp_h264_dims(h264,
									&gw, &gh);
								gfx.frame_id++;
								gn = rdp_rdpgfx_build_avc420_frame(
									gpdu,
									gpdu_cap,
									gfx.surface_id,
									gfx.frame_id,
									gw,
									gh,
									h264_out,
									h264_len);
								if (gn > 0) {
									(void)send_gfx_pdu(
										t,
										user_id,
										dv->channel_id,
										dv->dv.gfx_channel_id,
										gpdu,
										(size_t)gn);
									rdp_rdpgfx_frame_sent(
										&gfx,
										(size_t)gn);
								}
								free(gpdu);
							}
						}
					}
				} else if (gfx.active && avc444 != NULL
				    && dv->dv.gfx_channel_id >= 0) {
					int fresh = !gfx.surface_created;
					ensure_gfx_surface(t, user_id, dv,
						&gfx, desktop_w, desktop_h);
					if (fresh && gfx.surface_created)
						rdp_avc444_force_idr(avc444);
					if (rdp_rdpgfx_may_send_frame(&gfx)) {
						const uint8_t *m_out;
						const uint8_t *a_out;
						size_t m_len, a_len;
						int keyframe;
						if (rdp_avc444_encode(avc444,
							frame_buf, fhdr.w,
							fhdr.h,
							&m_out, &m_len,
							&a_out, &a_len,
							&keyframe) == 0
						    && m_out != NULL
						    && m_len > 0
						    && a_out != NULL
						    && a_len > 0) {
							uint8_t *gpdu;
							size_t gpdu_cap =
								m_len + a_len
								+ 256;
							gpdu = malloc(gpdu_cap);
							if (gpdu != NULL) {
								ssize_t gn;
								int gw, gh;
								rdp_avc444_dims(avc444,
									&gw, &gh);
								gfx.frame_id++;
								gn = rdp_rdpgfx_build_avc444_frame(
									gpdu,
									gpdu_cap,
									gfx.surface_id,
									gfx.frame_id,
									(uint16_t)gw,
									(uint16_t)gh,
									m_out,
									m_len,
									a_out,
									a_len);
								if (gn > 0) {
									(void)send_gfx_pdu(
										t,
										user_id,
										dv->channel_id,
										dv->dv.gfx_channel_id,
										gpdu,
										(size_t)gn);
									rdp_rdpgfx_frame_sent(
										&gfx,
										(size_t)gn);
								}
								free(gpdu);
							}
						}
					}
				} else if (gfx.active && prog != NULL
				    && dv->dv.gfx_channel_id >= 0) {
					ensure_gfx_surface(t, user_id, dv,
						&gfx, desktop_w, desktop_h);
					if (rdp_rdpgfx_may_send_frame(&gfx)) {
						const uint8_t *prog_out;
						size_t prog_len;
						if (rdp_progressive_encode(prog,
							frame_buf, fhdr.w,
							fhdr.h,
							&prog_out, &prog_len)
							== 0) {
							uint8_t *gpdu;
							size_t gpdu_cap =
								prog_len + 256;
							gpdu = malloc(gpdu_cap);
							if (gpdu != NULL) {
								ssize_t gn;
								gfx.frame_id++;
								gn = rdp_rdpgfx_build_progressive_frame(
									gpdu,
									gpdu_cap,
									gfx.surface_id,
									gfx.frame_id,
									prog_out,
									prog_len);
								if (gn > 0) {
									(void)send_gfx_pdu(
										t,
										user_id,
										dv->channel_id,
										dv->dv.gfx_channel_id,
										gpdu,
										(size_t)gn);
									rdp_rdpgfx_frame_sent(
										&gfx,
										(size_t)gn);
								}
								free(gpdu);
							}
						}
					}
				} else {
					if (push_frame_tiled(t, fhdr.x,
						fhdr.y, fhdr.w, fhdr.h,
						frame_buf, chunk_target,
						(g_allow_bitmap_cache
						 && g_client_bitmap_cache_ok
						 && g_client_bpp == 24)
						? g_bmpcache : NULL) != 0)
						break;
				}
			} else if (type == RDP_BE_H264_FRAME) {
				struct rdp_be_h264_frame_hdr fhdr;
				uint8_t *h264_data;
				if (rdp_read_full(be_fd, &fhdr,
					sizeof fhdr) != sizeof fhdr)
					break;
				if (fhdr.h264_len == 0
				    || fhdr.h264_len > 0x1000000)
					break;
				h264_data = malloc(fhdr.h264_len);
				if (h264_data == NULL) break;
				if (rdp_read_full(be_fd, h264_data,
				    fhdr.h264_len)
				    != (ssize_t)fhdr.h264_len) {
					free(h264_data);
					break;
				}
				if (output_suppressed) {
					free(h264_data);
					continue;
				}
				if (gfx.active
				    && gfx.codec == RDPGFX_CODEC_AVC420
				    && dv->dv.gfx_channel_id >= 0) {
					ensure_gfx_surface(t, user_id, dv,
						&gfx, desktop_w, desktop_h);
					if (rdp_rdpgfx_may_send_frame(&gfx)) {
						uint8_t *gpdu;
						size_t gpdu_cap =
							fhdr.h264_len + 256;
						gpdu = malloc(gpdu_cap);
						if (gpdu != NULL) {
							ssize_t gn;
							gfx.frame_id++;
							gn = rdp_rdpgfx_build_avc420_frame(
								gpdu,
								gpdu_cap,
								gfx.surface_id,
								gfx.frame_id,
								fhdr.w,
								fhdr.h,
								h264_data,
								fhdr.h264_len);
							if (gn > 0) {
								(void)send_gfx_pdu(
									t,
									user_id,
									dv->channel_id,
									dv->dv.gfx_channel_id,
									gpdu,
									(size_t)gn);
								rdp_rdpgfx_frame_sent(
									&gfx,
									(size_t)gn);
							}
							free(gpdu);
						}
					}
				} else {
					/* GFX is not active, or its
					 * codec is not AVC420 (e.g.
					 * AVC444 or Progressive, which
					 * the worker encodes from raw
					 * frames).  A pre-encoded AVC420
					 * 4:2:0 bitstream cannot be
					 * repackaged for those, so drop
					 * it. */
				}
				free(h264_data);
			} else if (type == RDP_BE_HELLO_S2W) {
				uint8_t junk[64];
				size_t left = len;
				while (left > 0) {
					size_t c = left > sizeof junk
					    ? sizeof junk : left;
					if (rdp_read_full(be_fd, junk, c) <= 0)
						break;
					left -= c;
				}
			} else if (type == RDP_BE_CLIP_OFFER
			    || type == RDP_BE_CLIP_REQUEST
			    || type == RDP_BE_CLIP_DATA
			    || type == RDP_BE_CLIP_FILE_REQUEST
			    || type == RDP_BE_CLIP_FILE_DATA) {
				uint8_t *pl = NULL;
				/* The session is the user's own helper, but bound
				 * the allocation anyway: every clip payload it
				 * sends fits well under 8 MiB (data is capped at
				 * 4 MiB on its side). */
				if (len > 8u * 1024u * 1024u) goto out;
				if (len > 0) {
					pl = malloc(len);
					if (pl == NULL) goto out;
					if (rdp_read_full(be_fd, pl, len)
					    != (ssize_t)len) {
						free(pl);
						goto out;
					}
				}
				(void)clip_handle_be(t, cs, type, pl, len);
				free(pl);
			} else if (type == RDP_BE_AUDIO) {
				if (ss->enabled && ss->snd.negotiated
				    && len > 0 && len <= 65536) {
					uint8_t *pcm = malloc(len);
					if (pcm != NULL
					    && rdp_read_full(be_fd, pcm, len)
					    == (ssize_t)len) {
						const uint8_t *audio = pcm;
						size_t audio_len = len;
						uint8_t *enc = NULL;
						int ok = 1;
						if (ss->snd.chosen_tag
						    == WAVE_FORMAT_ALAW) {
							enc = malloc(len / 2 + 1);
							if (enc == NULL)
								ok = 0;
							else {
								audio_len =
								  rdp_rdpsnd_alaw_encode(
								    pcm, len, enc);
								audio = enc;
							}
						}
						if (ok) {
							uint8_t *wpdu =
							    malloc(audio_len + 20);
							if (wpdu != NULL) {
								ssize_t wn;
								wn = rdp_rdpsnd_build_wave2(
								    &ss->snd, wpdu,
								    audio_len + 20,
								    audio, audio_len);
								if (wn > 0)
									(void)send_clip_pdu(
									    t, user_id,
									    ss->channel_id,
									    wpdu,
									    (size_t)wn);
								free(wpdu);
							}
						}
						free(enc);
					}
					free(pcm);
				} else if (len > 0) {
					uint8_t junk[1024];
					size_t left = len;
					while (left > 0) {
						size_t c = left > sizeof junk
						    ? sizeof junk : left;
						if (rdp_read_full(be_fd,
						    junk, c) <= 0) break;
						left -= c;
					}
				}
			} else if (type == RDP_BE_CURSOR) {
				struct rdp_be_cursor_hdr ch;
				size_t want = (len >= sizeof ch)
					? len - sizeof ch : 0;
				size_t npx = 0;
				uint8_t *argb = NULL;
				int valid = 0;

				/* A header too short to hold the fixed struct
				 * is malformed: drain the whole payload and
				 * move on without touching it. */
				if (len < sizeof ch) {
					size_t left = len;
					uint8_t junk[1024];
					while (left > 0) {
						size_t c = left > sizeof junk
							? sizeof junk : left;
						if (rdp_read_full(be_fd, junk,
						    c) <= 0) goto out;
						left -= c;
					}
					continue;
				}
				/* A failed header read means the stream is
				 * desynced; bail like the other branches. */
				if (rdp_read_full(be_fd, &ch, sizeof ch)
				    != (ssize_t)sizeof ch)
					goto out;
				npx = (size_t)ch.width * ch.height;
				if (ch.width > 0 && ch.height > 0
				    && npx <= (1u << 20)
				    && npx * 4 == want) {
					argb = malloc(want);
					if (argb != NULL) {
						/* A partial pixel read also
						 * desyncs the stream. */
						if (rdp_read_full(be_fd, argb,
						    want) != (ssize_t)want) {
							free(argb);
							goto out;
						}
						valid = 1;
					}
				}
				/* Geometry rejected or malloc failed: the
				 * pixels are still on the wire, so drain them
				 * to keep the stream framed. */
				if (!valid && argb == NULL) {
					size_t left = want;
					uint8_t junk[1024];
					while (left > 0) {
						size_t c = left > sizeof junk
							? sizeof junk : left;
						if (rdp_read_full(be_fd, junk,
						    c) <= 0) goto out;
						left -= c;
					}
				}
				/* Without colour pointer support, the default
				 * system pointer is left in place. */
				if (valid && can_color_ptr) {
					uint16_t sw = ch.width;
					uint16_t sh = ch.height;
					uint16_t hx = ch.hotspot_x;
					uint16_t hy = ch.hotspot_y;
					uint8_t *scaled = NULL;
					const uint8_t *src = argb;
					size_t src_stride = (size_t)sw * 4;
					if (sw > ptr_maxdim
					    || sh > ptr_maxdim) {
						/* Nearest-neighbour shrink to
						 * fit ptr_maxdim, preserving
						 * aspect. */
						uint32_t dw = sw, dh = sh;
						if (dw > ptr_maxdim) {
							dh = (uint32_t)dh
							    * ptr_maxdim / dw;
							dw = ptr_maxdim;
						}
						if (dh > ptr_maxdim) {
							dw = (uint32_t)dw
							    * ptr_maxdim / dh;
							dh = ptr_maxdim;
						}
						if (dw == 0) dw = 1;
						if (dh == 0) dh = 1;
						scaled = malloc((size_t)dw
						    * dh * 4);
						if (scaled != NULL) {
							uint32_t yy;
							for (yy = 0; yy < dh; yy++) {
								uint32_t sy = yy
								  * sh / dh;
								uint32_t xx;
								for (xx = 0; xx < dw; xx++) {
									uint32_t sx = xx
									  * sw / dw;
									const uint8_t *sp =
									  argb + ((size_t)sy
									  * sw + sx) * 4;
									uint8_t *dp =
									  scaled + ((size_t)yy
									  * dw + xx) * 4;
									dp[0] = sp[0];
									dp[1] = sp[1];
									dp[2] = sp[2];
									dp[3] = sp[3];
								}
							}
							/* Scale the hotspot by the
							 * same factor, clamp into
							 * the new bounds. */
							hx = (uint16_t)((uint32_t)hx
							    * dw / sw);
							hy = (uint16_t)((uint32_t)hy
							    * dh / sh);
							if (hx >= dw)
								hx = (uint16_t)(dw - 1);
							if (hy >= dh)
								hy = (uint16_t)(dh - 1);
							src = scaled;
							src_stride = (size_t)dw * 4;
							sw = (uint16_t)dw;
							sh = (uint16_t)dh;
						}
					}
					if (src != NULL
					    && (scaled != NULL
						|| !(ch.width > ptr_maxdim
						    || ch.height > ptr_maxdim))) {
						uint8_t pkt[0x4000];
						/* Hash the final post-scale cursor:
						 * hotspot, geometry and each row's
						 * sw*4 payload bytes (skipping any
						 * stride padding). */
						uint64_t hsh =
						    0xcbf29ce484222325ull;
						uint16_t dims[4];
						uint16_t r;
						dims[0] = hx; dims[1] = hy;
						dims[2] = sw; dims[3] = sh;
						hsh = fnv1a64(hsh, dims,
						    sizeof dims);
						for (r = 0; r < sh; r++)
							hsh = fnv1a64(hsh,
							    src + (size_t)r
							    * src_stride,
							    (size_t)sw * 4);
						if (ictx.ptr_cache_n > 0) {
							int hit = -1, i;
							for (i = 0; i < (int)ictx.ptr_cache_n; i++)
								if (ictx.ptr_cache[i].valid && ictx.ptr_cache[i].hash == hsh) { hit = i; break; }
							if (hit >= 0) {
								ssize_t pn = rdp_fp_build_pointer_cached(pkt, sizeof pkt, (uint16_t)hit);
								if (pn > 0) (void)rdp_tls_write_full(t, pkt, (size_t)pn);
							} else {
								uint16_t slot = ictx.ptr_cache_next;
								ssize_t pn = rdp_fp_build_pointer_new(pkt, sizeof pkt, slot, hx, hy, sw, sh, src, src_stride);
								if (pn > 0) {
									(void)rdp_tls_write_full(t, pkt, (size_t)pn);
									ictx.ptr_cache[slot].hash = hsh;
									ictx.ptr_cache[slot].valid = 1;
									ictx.ptr_cache_next = (uint16_t)((slot + 1) % ictx.ptr_cache_n);
								}
							}
						} else {
							ssize_t pn = rdp_fp_build_pointer_new(pkt, sizeof pkt, 0, hx, hy, sw, sh, src, src_stride);
							if (pn > 0) (void)rdp_tls_write_full(t, pkt, (size_t)pn);
						}
					}
					free(scaled);
				}
				free(argb);
			} else if (type == RDP_BE_WINDOW) {
				/* RemoteApp window order: turn the geometry into a
				 * Window Information drawing order and send it as a
				 * fast-path ORDERS update. */
				uint8_t wbuf[1024];
				if (len > 0 && len <= sizeof wbuf
				    && rdp_read_full(be_fd, wbuf, len)
					== (ssize_t)len) {
					if (g_remoteapp && len
					    >= sizeof(struct rdp_be_window)) {
						struct rdp_be_window wmsg;
						uint8_t order[600];
						ssize_t on;
						memcpy(&wmsg, wbuf, sizeof wmsg);
						if (wmsg.op == RDP_BE_WINDOW_OP_DELETE) {
							on = rdp_rail_build_window_delete(
								order, sizeof order,
								wmsg.window_id);
						} else {
							struct rdp_rail_window rw;
							size_t avail = len - sizeof wmsg;
							uint16_t tl = wmsg.title_len;
							if (tl > avail) tl = (uint16_t)avail;
							if (tl > 256) tl = 256;
							memset(&rw, 0, sizeof rw);
							rw.window_id = wmsg.window_id;
							rw.x = wmsg.x; rw.y = wmsg.y;
							rw.w = wmsg.w; rw.h = wmsg.h;
							rw.style = RAIL_WS_POPUP
							    | RAIL_WS_VISIBLE;
							rw.show_state = RAIL_WINDOW_SHOW;
							rw.title = wbuf + sizeof wmsg;
							rw.title_len = tl;
							on = rdp_rail_build_window_new(
								order, sizeof order, &rw);
						}
						if (on > 0) {
							uint8_t body[602];
							uint8_t upd[700];
							ssize_t un;
							body[0] = 1; body[1] = 0;
							memcpy(body + 2, order,
								(size_t)on);
							un = rdp_fp_build_update(upd,
								sizeof upd,
								RDP_FP_UPDATE_ORDERS,
								body, 2 + (size_t)on);
							if (un > 0)
								(void)rdp_tls_write_full(
									t, upd, (size_t)un);
						}
					}
				} else if (len > 0) {
					uint8_t junk[256];
					size_t left = len;
					while (left > 0) {
						size_t c = left > sizeof junk
						    ? sizeof junk : left;
						if (rdp_read_full(be_fd, junk, c)
						    <= 0) break;
						left -= c;
					}
				}
			} else if (type == RDP_BE_FS_REQ
			    && dr->enabled
			    && len >= sizeof(struct rdp_be_fs_req)) {
				struct rdp_be_fs_req freq;
				/* Trailing payload is path/data/SetBuffer per
				 * op.  The frame length is authoritative; the
				 * client is untrusted so bound it before any
				 * allocation. */
				uint32_t payload_len = len
				    - (uint32_t)sizeof freq;
				uint8_t *payload = NULL;
				uint8_t *irp = NULL;
				size_t irp_cap;
				ssize_t in = -1;
				uint32_t cid = 0;
				if (rdp_read_full(be_fd, &freq,
				    sizeof freq) != sizeof freq) goto out;
				if (payload_len > RDP_BE_FS_MAX_PAYLOAD) {
					/* Drain the oversize payload and reject
					 * so the stream stays framed. */
					uint8_t junk[1024];
					uint32_t skip = payload_len;
					while (skip > 0) {
						uint32_t c = skip > sizeof junk
						    ? (uint32_t)sizeof junk
						    : skip;
						if (rdp_read_full(be_fd, junk, c)
						    <= 0) goto out;
						skip -= c;
					}
					{
						struct rdp_be_fs_rsp rsp;
						rsp.req_id = freq.req_id;
						rsp.status = STATUS_UNSUCCESSFUL;
						rsp.file_id = 0;
						rsp.length = 0;
						(void)rdp_be_send(be_fd,
						    RDP_BE_FS_RSP,
						    &rsp, sizeof rsp);
					}
					continue;
				}
				if (payload_len > 0) {
					/* +1 so OPEN/LIST can NUL terminate the
					 * UTF-8 path in place. */
					payload = malloc(payload_len + 1);
					if (payload == NULL) goto out;
					if (rdp_read_full(be_fd, payload,
					    payload_len) != (ssize_t)payload_len) {
						free(payload);
						goto out;
					}
					payload[payload_len] = '\0';
				}
				/* OPEN and LIST expand the UTF-8 path/pattern
				 * to UTF-16LE plus a NUL, so reserve room for
				 * the doubled size; this also covers the
				 * verbatim WRITE/SET_INFO payloads since
				 * (payload_len+1)*2 >= payload_len. */
				irp_cap = (size_t)IRP_HDR_SIZE + 32
				    + ((size_t)payload_len + 1) * 2;
				irp = malloc(irp_cap);
				if (irp == NULL) {
					free(payload);
					goto out;
				}
				switch (freq.op) {
				case RDP_FS_OPEN: {
					uint32_t da = freq.desired_access
					    ? freq.desired_access
					    : (FILE_READ_DATA
					    | FILE_LIST_DIRECTORY);
					uint32_t disp = freq.disposition
					    ? freq.disposition : FILE_OPEN;
					in = rdp_rdpdr_build_irp_create(
					    &dr->dr, irp, irp_cap,
					    freq.device_id,
					    payload ? (const char *)payload : "",
					    da, disp, freq.options, &cid);
					break;
				}
				case RDP_FS_READ:
					in = rdp_rdpdr_build_irp_read(
					    &dr->dr, irp, irp_cap,
					    freq.device_id, freq.file_id,
					    freq.length, freq.offset, &cid);
					break;
				case RDP_FS_WRITE:
					in = rdp_rdpdr_build_irp_write(
					    &dr->dr, irp, irp_cap,
					    freq.device_id, freq.file_id,
					    freq.offset, payload, payload_len,
					    &cid);
					break;
				case RDP_FS_CLOSE:
					in = rdp_rdpdr_build_irp_close(
					    &dr->dr, irp, irp_cap,
					    freq.device_id, freq.file_id,
					    &cid);
					break;
				case RDP_FS_LIST:
					in = rdp_rdpdr_build_irp_query_dir(
					    &dr->dr, irp, irp_cap,
					    freq.device_id, freq.file_id,
					    payload_len > 0
					    ? (const char *)payload : "*",
					    1, &cid);
					break;
				case RDP_FS_QUERY_INFO:
					in = rdp_rdpdr_build_irp_query_info(
					    &dr->dr, irp, irp_cap,
					    freq.device_id, freq.file_id,
					    freq.info_class, &cid);
					break;
				case RDP_FS_SET_INFO:
					in = rdp_rdpdr_build_irp_set_info(
					    &dr->dr, irp, irp_cap,
					    freq.device_id, freq.file_id,
					    freq.info_class, payload,
					    payload_len, &cid);
					break;
				default:
					in = -1;
					break;
				}
				if (in > 0) {
					int pi;
					for (pi = 0; pi < RDPDR_MAX_PENDING; pi++)
						if (dr->dr.pending[pi].in_use
						    && dr->dr.pending[pi].completion_id == cid) {
							dr->dr.pending[pi].be_req_id = freq.req_id;
							break;
						}
					(void)send_clip_pdu(t, user_id,
					    dr->channel_id,
					    irp, (size_t)in);
				} else {
					struct rdp_be_fs_rsp rsp;
					rsp.req_id = freq.req_id;
					rsp.status = STATUS_NOT_IMPLEMENTED;
					rsp.file_id = 0;
					rsp.length = 0;
					(void)rdp_be_send(be_fd,
					    RDP_BE_FS_RSP,
					    &rsp, sizeof rsp);
				}
				free(irp);
				free(payload);
			} else if (type == RDP_BE_PRINT_JOB
			    && dr->enabled
			    && len >= sizeof(struct rdp_be_print_job_hdr)) {
				struct rdp_be_print_job_hdr pjh;
				uint32_t spool_len = len
				    - (uint32_t)sizeof pjh;
				uint8_t *spool = NULL;
				if (rdp_read_full(be_fd, &pjh, sizeof pjh)
				    != sizeof pjh) goto out;
				if (spool_len > RDP_BE_PRINT_JOB_MAX_SPOOL) {
					/* Drain the oversize spool so the stream
					 * stays framed, then drop the job. */
					uint8_t junk[1024];
					uint32_t skip = spool_len;
					while (skip > 0) {
						uint32_t c = skip > sizeof junk
						    ? (uint32_t)sizeof junk
						    : skip;
						if (rdp_read_full(be_fd, junk,
						    c) <= 0) goto out;
						skip -= c;
					}
					rdp_warn("rdpdr: print job too large "
					    "(%u bytes), dropped",
					    (unsigned)spool_len);
					continue;
				}
				if (spool_len > 0) {
					spool = malloc(spool_len);
					if (spool == NULL) goto out;
					if (rdp_read_full(be_fd, spool,
					    spool_len)
					    != (ssize_t)spool_len) {
						free(spool);
						goto out;
					}
				}
				/* print_job_start takes ownership of spool and
				 * frees it on every path. */
				(void)print_job_start(t, user_id, dr,
				    pjh.device_id, spool, spool_len);
			} else if (type == RDP_BE_BYE) {
				break;
			} else {
				uint8_t junk[1024];
				size_t left = len;
				while (left > 0) {
					size_t n2 = left > sizeof junk
						? sizeof junk : left;
					if (rdp_read_full(be_fd, junk, n2)
					    != (ssize_t)n2) goto out;
					left -= n2;
				}
			}
		}
	}
out:
	/* If the session backend died (process exit or crash), tell the
	 * client why so it shows a reason instead of a silent drop. */
	if (backend_lost)
		send_error_info(t, user_id, io_channel, ERRINFO_LOGOFF_BY_USER);
	if (h264 != NULL) rdp_h264_close(h264);
	if (avc444 != NULL) rdp_avc444_close(avc444);
	if (prog != NULL) rdp_progressive_close(prog);
	free(frame_buf);
	rdp_drdynvc_cleanup(&dv->dv);
	free(dv->cam_frame);
	dv->cam_frame = NULL;
	dv->cam_frame_cap = 0;
	/* Free any in-flight print job spool copies. */
	{
		int pj;
		for (pj = 0; pj < RDPDR_MAX_PRINT_JOBS; pj++)
			print_job_free(&dr->jobs[pj]);
	}
}

/* Extract the bare IP (no port) from a peer string formatted as
 * "host:port" or "[host]:port", for per-source-IP auth rate-limiting. */
static void
peer_to_ip(const char *peer, char *ip, size_t cap)
{
	const char *start, *end;
	size_t n;
	if (cap == 0) return;
	if (peer == NULL) { ip[0] = '\0'; return; }
	if (peer[0] == '[') {
		start = peer + 1;
		end = strchr(start, ']');
	} else {
		start = peer;
		end = strrchr(peer, ':');
	}
	n = end != NULL ? (size_t)(end - start) : strlen(start);
	if (n >= cap) n = cap - 1;
	memcpy(ip, start, n);
	ip[n] = '\0';
}

struct sessmgr_auth_ctx {
	const char         *sock;
	struct rdp_sessmgr *sm;       /* opened on success */
	const char         *ip;       /* client source IP for rate-limiting */
};

static int
sessmgr_auth_thunk(const char *user, const char *pass, void *ctx)
{
	struct sessmgr_auth_ctx *c = ctx;
	if (c->sm->fd >= 0)
		rdp_sessmgr_close(c->sm);
	return rdp_sessmgr_open_auth(c->sm, c->sock, user, pass, c->ip);
}

void
rdp_conn_run(int fd, const struct rdp_conn_cfg *cfg, const char *peer)
{
	uint8_t  buf[RDP_CONN_BUF];
	uint8_t  scratch[RDP_CONN_BUF];
	ssize_t  n;
	struct rdp_x224_cr cr;
	struct rdp_tls *t = NULL;
	uint16_t user_id = 1002;
	uint16_t io_channel = RDP_MCS_IO_CHANNEL_ID;
	uint16_t desktop_w = 0, desktop_h = 0;
	uint32_t client_lcid = 0;
	uint16_t client_early_caps = 0;
	uint16_t msgchannel_id = 0;
	uint32_t client_max_request = 0;
	uint16_t client_color_ptr = 0, client_large_ptr = 0;
	uint16_t client_pointer_cache_size = 0;
	int use_nla = 0;
	char nla_user[256] = {0}, nla_pass[256] = {0};
	char client_ip[RDP_SESSMGR_IP_MAX];
	const uint8_t *ci_pw = NULL;
	size_t ci_pw_len = 0;
	struct rdp_tls_ctx *tls = cfg->tls;
	struct clip_state clip = {0};

	g_allow_v10_avc = cfg->allow_v10_avc;
	g_allow_progressive = cfg->allow_progressive;
	g_allow_avc444 = cfg->allow_avc444;
	g_allow_autodetect = cfg->allow_autodetect;
	g_prefer_wan_audio = cfg->prefer_wan_audio;
	g_allow_microphone = cfg->allow_microphone;
	g_allow_camera = cfg->allow_camera;
	g_allow_bitmap_cache = cfg->allow_bitmap_cache;
	if (g_allow_bitmap_cache && g_bmpcache == NULL)
		g_bmpcache = rdp_bmpcache_create();
	struct dynvc_state dynvc = {0};
	struct snd_state snd = {0};
	struct dr_state devr = {0};
	struct rdp_client_info client_info;
	uint32_t logon_id = 0;
	uint8_t  arc_random[16] = {0};
	clip.user_id = user_id;
	rdp_cliprdr_reasm_init(&clip.reasm, CLIP_MAX_PDU);
	dynvc.dv.disp_channel_id = -1;
	dynvc.dv.gfx_channel_id = -1;
	dynvc.dv.audioin_channel_id = -1;
	dynvc.dv.rdpei_channel_id = -1;
	dynvc.dv.camenum_channel_id = -1;
	dynvc.dv.camdev_channel_id = -1;
	rdp_sndin_init(&dynvc.sndin);
	rdp_cam_state_init(&dynvc.cam);
	memset(&client_info, 0, sizeof client_info);
	peer_to_ip(peer, client_ip, sizeof client_ip);

	rdp_debug("conn[%s]: starting", peer);

	/* 1. CR/CC. */
	n = read_tpkt_raw(fd, buf, sizeof buf);
	if (n <= 0) { rdp_err("conn[%s]: short CR", peer); goto done; }
	if (rdp_x224_parse_cr(&cr, buf + 4, (size_t)n - 4) < 0) {
		rdp_err("conn[%s]: bad CR", peer);
		goto done;
	}
	if (cr.have_neg_req
	    && (cr.requested_protocols & RDP_PROTO_SSL) == 0
	    && (cr.requested_protocols & RDP_PROTO_HYBRID) == 0) {
		ssize_t cc;
		cc = rdp_x224_build_cc(scratch + 4, sizeof scratch - 4, 1, 0,
			RDP_NEG_FAIL_SSL_REQUIRED_BY_SERVER);
		if (cc < 0) goto done;
		(void)rdp_tpkt_encode_hdr(scratch, (uint16_t)(4 + cc));
		(void)rdp_write_full(fd, scratch, 4 + (size_t)cc);
		goto done;
	}
	{
		uint32_t selected = RDP_PROTO_SSL;
		if (cr.have_neg_req
		    && (cr.requested_protocols & RDP_PROTO_HYBRID)
		    && cfg->sessmgr_sock != NULL
		    && cfg->sessmgr_sock[0] != '\0') {
			FILE *_hf = fopen(NTHASH_PATH, "r");
			if (_hf != NULL) {
				fclose(_hf);
				selected = RDP_PROTO_HYBRID;
			}
		}
		ssize_t cc = rdp_x224_build_cc(scratch + 4, sizeof scratch - 4,
			0, selected, 0);
		if (cc < 0) goto done;
		(void)rdp_tpkt_encode_hdr(scratch, (uint16_t)(4 + cc));
		if (rdp_write_full(fd, scratch, 4 + (size_t)cc)
		    != (ssize_t)(4 + cc)) {
			rdp_err("conn[%s]: write CC", peer);
			goto done;
		}
		use_nla = (selected == RDP_PROTO_HYBRID);
	}

	/* 2. TLS. */
	t = rdp_tls_accept(tls, fd);
	if (t == NULL) {
		rdp_err("conn[%s]: TLS handshake failed", peer);
		goto done;
	}
	rdp_debug("conn[%s]: TLS established (%s)", peer,
		rdp_tls_version(t));

	if (use_nla) {
		if (rdp_nla_server(t, nla_user, sizeof nla_user,
		    nla_pass, sizeof nla_pass) != 0) {
			rdp_warn("conn[%s]: NLA failed", peer);
			goto done;
		}
		rdp_info("conn[%s]: NLA authenticated '%s'",
			peer, nla_user);
	}

	/* 3. MCS Connect Initial. */
	{
		struct rdp_mcs_connect_initial ci;
		const uint8_t *mcs_p;
		size_t mcs_len;

		n = read_tpkt_tls(t, buf, sizeof buf);
		if (n <= 0) goto done;
		if (strip_tpkt_x224(buf, (size_t)n, &mcs_p, &mcs_len) != 0)
			goto done;
		if (rdp_mcs_parse_connect_initial(mcs_p, mcs_len, &ci) < 0) {
			rdp_err("conn[%s]: bad MCS Connect Initial", peer);
			goto done;
		}
		desktop_w = ci.desktop_width ? ci.desktop_width : 1024;
		desktop_h = ci.desktop_height ? ci.desktop_height : 768;
		client_lcid = ci.keyboard_layout;
		client_early_caps = ci.early_capability_flags;

		if (ci.monitor_count > 1) {
			int32_t min_x = 0, min_y = 0;
			int32_t max_x = 0, max_y = 0;
			uint32_t mi;
			for (mi = 0; mi < ci.monitor_count; mi++) {
				if (mi == 0 || ci.monitors[mi].left < min_x)
					min_x = ci.monitors[mi].left;
				if (mi == 0 || ci.monitors[mi].top < min_y)
					min_y = ci.monitors[mi].top;
				if (mi == 0 || ci.monitors[mi].right > max_x)
					max_x = ci.monitors[mi].right;
				if (mi == 0 || ci.monitors[mi].bottom > max_y)
					max_y = ci.monitors[mi].bottom;
			}
			desktop_w = (uint16_t)(max_x - min_x + 1);
			desktop_h = (uint16_t)(max_y - min_y + 1);
			rdp_info("conn[%s]: %u monitors, bounding box %ux%u",
				peer, ci.monitor_count,
				(unsigned)desktop_w, (unsigned)desktop_h);
		}

		rdp_info("conn[%s]: connect from %s, %ux%u, %u channels",
			peer, ci.client_hostname[0] ? ci.client_hostname : "?",
			desktop_w, desktop_h, ci.channel_count);

		/* Identify the CLIPRDR channel, if the client asked for it. */
		for (uint32_t i = 0; i < ci.channel_count; i++) {
			char name[9];
			memcpy(name, ci.channels[i].name, 8);
			name[8] = '\0';
			rdp_debug("conn[%s]: channel %u = '%s'",
				peer, (unsigned)(1004 + i), name);
			if (strncasecmp(name, "CLIPRDR", 7) == 0) {
				clip.enabled    = 1;
				clip.channel_id = (uint16_t)(1004 + i);
			}
			if (strncasecmp(name, "DRDYNVC", 7) == 0) {
				dynvc.enabled    = 1;
				dynvc.channel_id = (uint16_t)(1004 + i);
			}
			if (strncasecmp(name, "RDPSND", 6) == 0) {
				snd.enabled    = 1;
				snd.channel_id = (uint16_t)(1004 + i);
			}
			if (strncasecmp(name, "RDPDR", 5) == 0) {
				devr.enabled    = 1;
				devr.channel_id = (uint16_t)(1004 + i);
			}
			if (strncasecmp(name, "rail", 4) == 0) {
				g_rail.enabled    = 1;
				g_rail.channel_id = (uint16_t)(1004 + i);
			}
		}

		{
			struct rdp_mcs_connect_response cr2;
			ssize_t cr_n, dt_n;

			memset(&cr2, 0, sizeof cr2);
			cr2.io_channel_id = io_channel;
			cr2.user_channel_base = 1004;
			cr2.channel_count = (uint16_t)ci.channel_count;
			for (uint16_t i = 0; i < cr2.channel_count; i++)
				cr2.channel_ids[i] = (uint16_t)(1004 + i);
			cr2.requested_protocols = cr.have_neg_req
			? cr.requested_protocols : 0;
			cr2.early_capability_flags = 0x0e;
			if (ci.has_msgchannel)
				cr2.msgchannel_id =
					(uint16_t)(1004 + ci.channel_count);
			msgchannel_id = cr2.msgchannel_id;
			g_client_heartbeat = (ci.early_capability_flags
			    & RDP_CS_EARLYCAP_HEARTBEAT) != 0;
			g_heartbeat_chan = msgchannel_id;

			dt_n = rdp_x224_build_dt(scratch + 4, sizeof scratch - 4);
			cr_n = rdp_mcs_build_connect_response(
				scratch + 4 + dt_n, sizeof scratch - 4 - dt_n,
				&cr2);
			if (cr_n < 0) goto done;
			if (write_tpkt_tls(t, scratch,
				4 + (size_t)dt_n + (size_t)cr_n) != 0) goto done;
		}
	}

	/* 4. Erect Domain + Attach User. */
	{
		const uint8_t *mcs_p;
		size_t mcs_len;

		n = read_tpkt_tls(t, buf, sizeof buf);
		if (n <= 0) goto done;
		if (strip_tpkt_x224(buf, (size_t)n, &mcs_p, &mcs_len) != 0
		    || rdp_mcs_parse_erect_domain(mcs_p, mcs_len) < 0) {
			rdp_err("conn[%s]: expected Erect Domain", peer);
			goto done;
		}
		n = read_tpkt_tls(t, buf, sizeof buf);
		if (n <= 0) goto done;
		if (strip_tpkt_x224(buf, (size_t)n, &mcs_p, &mcs_len) != 0
		    || rdp_mcs_parse_attach_user_request(mcs_p, mcs_len) < 0) {
			rdp_err("conn[%s]: expected Attach User", peer);
			goto done;
		}
		{
			uint8_t body[8];
			ssize_t bn = rdp_mcs_build_attach_user_confirm(body,
				sizeof body, user_id);
			ssize_t dt_n;
			if (bn < 0) goto done;
			dt_n = rdp_x224_build_dt(scratch + 4,
				sizeof scratch - 4);
			memcpy(scratch + 4 + dt_n, body, bn);
			if (write_tpkt_tls(t, scratch,
				4 + (size_t)dt_n + (size_t)bn) != 0) goto done;
		}
	}

	/* 5. Channel Join loop -- mstsc joins user channel, I/O channel,
	 *    then each virtual channel.  We confirm each. */
	{int _jc = 0;
	for (;;) {
		const uint8_t *mcs_p;
		size_t mcs_len;
		uint16_t uid, cid;
		uint8_t body[8];
		ssize_t bn, dt_n;

		n = read_tpkt_tls(t, buf, sizeof buf);
		if (n <= 0) goto done;
		if (strip_tpkt_x224(buf, (size_t)n, &mcs_p, &mcs_len) != 0)
			goto done;

		/* Either Channel Join Request or the first Send Data Request
		 * carrying the Client Info PDU.  Distinguish by type byte. */
		if (mcs_len < 1) goto done;
		if (mcs_p[0] == RDP_MCS_TYPE_CHANNEL_JOIN_REQ) {
			if (rdp_mcs_parse_channel_join_request(mcs_p, mcs_len,
				&uid, &cid) < 0) goto done;
			bn = rdp_mcs_build_channel_join_confirm(body,
				sizeof body, uid, cid);
			if (bn < 0) goto done;
			dt_n = rdp_x224_build_dt(scratch + 4,
				sizeof scratch - 4);
			memcpy(scratch + 4 + dt_n, body, bn);
			if (_jc < 12) {
				rdp_debug("conn[%s]: join req uid=%u cid=%u -> confirm %02x %02x %02x %02x %02x %02x %02x %02x",
					peer, uid, cid,
					body[0], body[1], body[2], body[3],
					bn>4?body[4]:0, bn>5?body[5]:0, bn>6?body[6]:0, bn>7?body[7]:0);
			}
			if (++_jc > 50) { rdp_err("conn[%s]: join loop overflow", peer); goto done; }
			if (write_tpkt_tls(t, scratch,
				4 + (size_t)dt_n + (size_t)bn) != 0) goto done;
			continue;
		}
		if (mcs_p[0] == RDP_MCS_TYPE_SEND_DATA_REQ) {
			const uint8_t *payload;
			size_t payload_len;
			uint32_t sec_flags;
			ssize_t sh;
			if (rdp_mcs_parse_send_data_request(mcs_p, mcs_len,
				&uid, &cid, &payload, &payload_len) < 0)
				goto done;
			sh = rdp_sec_parse_header(payload, payload_len,
				&sec_flags);
			if (sh < 0) goto done;
			if ((sec_flags & RDP_SEC_INFO_PKT) == 0) {
				rdp_err("conn[%s]: expected Client Info", peer);
				goto done;
			}
			if (rdp_client_info_parse(payload + sh,
				payload_len - (size_t)sh, &client_info,
				&ci_pw, &ci_pw_len) < 0) {
				rdp_err("conn[%s]: bad Client Info", peer);
				goto done;
			}
			g_remoteapp = (client_info.flags
				& RDP_INFO_RAIL) != 0;
			rdp_info("conn[%s]: user=%s domain=%s arc=%s",
				peer,
				client_info.username[0] ? client_info.username : "?",
				client_info.domain,
				client_info.have_arc ? "yes" : "no");
			break;
		}
		rdp_err("conn[%s]: unexpected MCS type 0x%02x",
			peer, mcs_p[0]);
		goto done;
	}}

	/* 6b. Connect-time network auto-detection (opt-in via rdpd -N): the
	 * sequence allows it after the Client Info PDU and before licensing.
	 * Only when the client advertised support and a message channel was
	 * negotiated; the measured bandwidth caps the encoder bitrate. */
	if (g_allow_autodetect && msgchannel_id != 0
	    && (client_early_caps & RDP_CS_EARLYCAP_NETCHAR_AUTODETECT) != 0) {
		int kbps = do_autodetect(t, user_id, msgchannel_id, peer);
		if (kbps < 0) goto done;   /* transport error mid-stream */
		if (kbps > 0) {
			/* Use 85% of the measured link as the peak cap, with a
			 * floor and ceiling so a bad measurement cannot starve
			 * or runaway the encoder. */
			int cap = (int)(((uint32_t)kbps * 85) / 100);
			if (cap < 1000) cap = 1000;
			if (cap > 30000) cap = 30000;
			rdp_h264_set_target_kbps(cap);
		}
	}

	/* 7. Send License Valid Client. */
	{
		uint8_t lic[64];
		ssize_t ln;
		uint8_t body[64];

		ln = rdp_license_build_valid_client(lic, sizeof lic);
		if (ln < 0) goto done;
		(void)rdp_sec_build_header(body, sizeof body,
			RDP_SEC_LICENSE_PKT);
		memcpy(body + 4, lic, (size_t)ln);
		if (send_send_data(t, user_id, io_channel, body, 4 + ln) != 0)
			goto done;
	}

	/* 8. Demand Active. */
	{
		uint8_t caps[2048];
		ssize_t cn;
		uint8_t pdu[2200];
		ssize_t hdr_n;

		cn = rdp_capset_build_demand_active(caps, sizeof caps,
			RDP_CONN_SHARE_ID, desktop_w, desktop_h, g_remoteapp, g_allow_bitmap_cache);
		if (cn < 0) goto done;
		if ((size_t)cn + 6 > sizeof pdu) goto done;
		hdr_n = rdp_pdu_build_share_control(pdu, sizeof pdu,
			RDP_PDU_TYPE_DEMAND_ACTIVE, user_id,
			(uint16_t)(cn + 6));
		if (hdr_n < 0) goto done;
		memcpy(pdu + hdr_n, caps, (size_t)cn);
		if (send_send_data(t, user_id, io_channel, pdu,
			(size_t)hdr_n + (size_t)cn) != 0) goto done;
	}

	/* 8b. Read Confirm Active.  Under Enhanced RDP Security (TLS or
	 * CredSSP) the per-PDU Security Header is only carried for the
	 * Client Info and License PDUs; Confirm Active and all later
	 * PDUs go straight to the share-control header. */
	{
		const uint8_t *mcs_p;
		size_t mcs_len;
		const uint8_t *payload;
		size_t payload_len;
		uint16_t uid, cid;
		uint16_t ptype, psrc, plen;

		n = read_tpkt_tls(t, buf, sizeof buf);
		if (n <= 0) goto done;
		if (strip_tpkt_x224(buf, (size_t)n, &mcs_p, &mcs_len) != 0
		    || rdp_mcs_parse_send_data_request(mcs_p, mcs_len, &uid,
			&cid, &payload, &payload_len) < 0)
			goto done;
		if (rdp_pdu_parse_share_control(payload,
			payload_len, &ptype, &psrc, &plen) < 0)
			goto done;
		if (ptype != RDP_PDU_TYPE_CONFIRM_ACTIVE) {
			rdp_err("conn[%s]: expected Confirm Active, got %u",
				peer, ptype);
			goto done;
		}
		rdp_debug("conn[%s]: confirm active from src=%u len=%u",
			peer, psrc, plen);
		/* Pull the client's MultifragmentUpdate MaxRequestSize so we
		 * can size fast-path bitmap fragments to what it accepts.  The
		 * confirm-active body follows the 6-byte share-control header. */
		if (payload_len > 6) {
			uint32_t mrq = 0;
			uint16_t cptr = 0, lptr = 0, pcache = 0, cbpp = 24;
			int cache_ok = 0;
			if (rdp_capset_parse_confirm_active(payload + 6,
				payload_len - 6, &cbpp, &mrq, &cptr, &lptr,
				&pcache, &cache_ok) == 0) {
				client_max_request = mrq;
				client_color_ptr = cptr;
				client_large_ptr = lptr;
				client_pointer_cache_size = pcache;
				g_client_bitmap_cache_ok = cache_ok;
				g_client_bpp = cbpp;
				/* The interleaved-RLE codec emits a 24bpp stream;
				 * clients that negotiated another depth (mstsc uses
				 * 32bpp) reject it but accept raw 24bpp, so only
				 * compress fast-path bitmaps for 24bpp clients (the
				 * cache orders are gated the same way below). */
				rdp_fp_allow_rle_compress(cbpp == 24);
			}
		}
		rdp_debug("conn[%s]: client MaxRequestSize=%u colorPtr=%u largePtr=0x%04x ptrCache=%u",
			peer, (unsigned)client_max_request,
			(unsigned)client_color_ptr, (unsigned)client_large_ptr,
			(unsigned)client_pointer_cache_size);
	}

	/* 9. Finalization handshake. */
	{
		uint8_t pdu[64];
		ssize_t pn;

		pn = rdp_pdu_build_synchronize(pdu, sizeof pdu, user_id,
			RDP_CONN_SHARE_ID, 1002);
		if (pn < 0 ||
			send_send_data(t, user_id, io_channel, pdu, (size_t)pn) != 0)
			goto done;
		pn = rdp_pdu_build_control(pdu, sizeof pdu, user_id,
			RDP_CONN_SHARE_ID, RDP_CTRL_COOPERATE, 0, 0);
		if (pn < 0 ||
			send_send_data(t, user_id, io_channel, pdu, (size_t)pn) != 0)
			goto done;
		pn = rdp_pdu_build_control(pdu, sizeof pdu, user_id,
			RDP_CONN_SHARE_ID, RDP_CTRL_GRANTED_CONTROL,
			1002, 1002);
		if (pn < 0 ||
			send_send_data(t, user_id, io_channel, pdu, (size_t)pn) != 0)
			goto done;
		pn = rdp_pdu_build_font_map(pdu, sizeof pdu, user_id,
			RDP_CONN_SHARE_ID);
		if (pn < 0 ||
			send_send_data(t, user_id, io_channel, pdu, (size_t)pn) != 0)
			goto done;
	}

	rdp_info("conn[%s]: activated %ux%u", peer, desktop_w, desktop_h);

	/* 10. Phase B/D: send a Synchronize + System Pointer, then hand
	 * the connection to the greeter for the login dialog.  If the
	 * greeter returns OK we fall through to the post-login frame;
	 * if it returns -1 (cancelled or failed) we close the session. */
	{
		uint8_t pkt[64];
		ssize_t pn;

		pn = rdp_fp_build_synchronize(pkt, sizeof pkt);
		if (pn > 0) (void)rdp_tls_write_full(t, pkt, (size_t)pn);
		pn = rdp_fp_build_pointer_default(pkt, sizeof pkt);
		if (pn > 0) (void)rdp_tls_write_full(t, pkt, (size_t)pn);
	}

	/* Check for auto-reconnect cookie.  If the client presented one
	 * and the sessmgr still holds the suspended backend, skip the
	 * greeter entirely and resume the existing session. */
	if (client_info.have_arc
	    && cfg->sessmgr_sock != NULL && cfg->sessmgr_sock[0] != '\0') {
		int be_fd = -1;
		uint8_t stored_arc[16];
		rdp_info("conn[%s]: reconnect attempt logonId=%u",
			peer, (unsigned)client_info.arc_logon_id);
		if (rdp_sessmgr_resume(cfg->sessmgr_sock,
			client_info.arc_logon_id, &be_fd, stored_arc) == 0) {
			uint8_t expected_verifier[16];
			rdp_hmac_md5(stored_arc, 16,
				client_info.arc_security_verifier, 16,
				expected_verifier);
			if (rdp_consttime_eq(expected_verifier,
			    client_info.arc_security_verifier, 16) != 0) {
				rdp_warn("conn[%s]: ARC verifier mismatch",
					peer);
				(void)close(be_fd);
				goto done;
			}
			rdp_info("conn[%s]: resumed backend fd %d",
				peer, be_fd);
			/* Generate a fresh ARC cookie for the next
			 * potential reconnect. */
			logon_id = rdp_rand_u32();
			rdp_rand_bytes(arc_random, sizeof arc_random);
			{
				uint8_t ssi[128];
				ssize_t sn = rdp_pdu_build_save_session_info_arc(
					ssi, sizeof ssi, user_id,
					RDP_CONN_SHARE_ID,
					logon_id, arc_random);
				if (sn > 0)
					(void)send_send_data(t, user_id,
						io_channel, ssi, (size_t)sn);
			}
			run_proxy(t, be_fd, &clip, &dynvc, &snd, &devr,
				user_id, io_channel,
				desktop_w, desktop_h, client_max_request,
				client_color_ptr, client_large_ptr,
				client_pointer_cache_size, peer);
			/* On disconnect: try to SUSPEND the session so it
			 * survives for the next reconnect. */
			if (rdp_sessmgr_suspend(cfg->sessmgr_sock,
				logon_id, arc_random, be_fd) == 0)
				rdp_info("conn[%s]: session suspended", peer);
			(void)close(be_fd);
			goto send_disconnect;
		}
		rdp_debug("conn[%s]: reconnect failed; falling through "
			"to greeter", peer);
	}

	/* NLA-authenticated: use the credentials extracted from CredSSP. */
	if (use_nla && nla_user[0] != '\0'
	    && cfg->sessmgr_sock != NULL && cfg->sessmgr_sock[0] != '\0') {
		struct rdp_sessmgr sm = { -1, {0} };
		rdp_info("conn[%s]: NLA login as %s", peer, nla_user);
		if (rdp_sessmgr_open_auth(&sm, cfg->sessmgr_sock,
			nla_user, nla_pass, client_ip) == 0) {
			int be_fd = -1;
			if (rdp_sessmgr_spawn(&sm, desktop_w, desktop_h,
			    client_lcid, client_info.timezone,
			    &be_fd) == 0 && be_fd >= 0) {
				/* Write a .tok file with a nonce so the next
				 * SSL connection can auto-login via NLA_AUTH. */
				{
					uint8_t nonce[16];
					int tokfd;
					rdp_rand_bytes(nonce, sizeof nonce);
					tokfd = open(NTHASH_PATH ".tok",
						O_WRONLY | O_CREAT | O_EXCL, 0600);
					if (tokfd >= 0) {
						char tokbuf[512];
						int toklen;
						toklen = snprintf(tokbuf, sizeof tokbuf,
							"%s\n", nla_user);
						for (int i = 0; i < 16; i++)
							toklen += snprintf(tokbuf + toklen,
								sizeof tokbuf - toklen,
								"%02x", nonce[i]);
						toklen += snprintf(tokbuf + toklen,
							sizeof tokbuf - toklen, "\n");
						(void)rdp_write_full(tokfd, tokbuf, toklen);
						(void)close(tokfd);
						(void)rdp_sessmgr_nla_store(
							cfg->sessmgr_sock,
							nla_user, nonce);
					}
					explicit_bzero(nonce, sizeof nonce);
				}
				explicit_bzero(nla_pass, sizeof nla_pass);
				rdp_sessmgr_close(&sm);
				rdp_info("conn[%s]: backend fd %d", peer, be_fd);
				{
					send_error_info(t, user_id, io_channel,
						ERRINFO_NONE);
					uint8_t li[1200];
					ssize_t ln = rdp_pdu_build_save_session_logon_v2(
						li, sizeof li, user_id,
						RDP_CONN_SHARE_ID, "", nla_user, 0);
					if (ln > 0)
						(void)send_send_data(t, user_id,
							io_channel, li, (size_t)ln);
				}
				run_proxy(t, be_fd, &clip, &dynvc, &snd,
					&devr, user_id, io_channel,
					desktop_w, desktop_h,
					client_max_request,
					client_color_ptr, client_large_ptr,
					client_pointer_cache_size,
					peer);
				(void)close(be_fd);
				goto done;
			}
			rdp_sessmgr_close(&sm);
		}
		explicit_bzero(nla_pass, sizeof nla_pass);
		rdp_warn("conn[%s]: NLA auth failed via sessmgr", peer);
		send_error_info(t, user_id, io_channel,
			ERRINFO_SERVER_DENIED_CONNECTION);
		goto done;
	}

	/* Token-based auto-login: NLA verified the user on a prior
	 * connection. Open and unlink atomically to prevent a
	 * second worker from reading the same token. */
	if (!use_nla && cfg->sessmgr_sock != NULL
	    && cfg->sessmgr_sock[0] != '\0') {
		char tok_user[256] = {0};
		uint8_t tok_nonce[16] = {0};
		int _tfd = open(NTHASH_PATH ".tok", O_RDONLY);
		if (_tfd >= 0) {
			char tokbuf[512] = {0};
			ssize_t _tr;
			(void)unlink(NTHASH_PATH ".tok");
			_tr = read(_tfd, tokbuf, sizeof tokbuf - 1);
			(void)close(_tfd);
			if (_tr > 0) {
				char *nl, *nonce_line;
				tokbuf[_tr] = '\0';
				nl = strchr(tokbuf, '\n');
				if (nl != NULL) {
					*nl = '\0';
					(void)strlcpy(tok_user, tokbuf,
						sizeof tok_user);
					nonce_line = nl + 1;
					/* Parse hex nonce */
					for (int i = 0; i < 16
					    && nonce_line[i * 2]
					    && nonce_line[i * 2 + 1]; i++) {
						unsigned int b;
						if (sscanf(nonce_line + i * 2,
						    "%2x", &b) == 1)
							tok_nonce[i] = (uint8_t)b;
					}
				}
			}
			if (tok_user[0] != '\0') {
				struct rdp_sessmgr sm = { -1, {0} };
				rdp_info("conn[%s]: NLA-verified login as %s",
					peer, tok_user);
				if (rdp_sessmgr_open_nla(&sm,
				    cfg->sessmgr_sock, tok_user,
				    tok_nonce) == 0) {
					int be_fd = -1;
					if (rdp_sessmgr_spawn(&sm,
					    desktop_w, desktop_h,
					    client_lcid, client_info.timezone,
					    &be_fd) == 0
					    && be_fd >= 0) {
						rdp_sessmgr_close(&sm);
						rdp_info("conn[%s]: backend fd %d",
							peer, be_fd);
						{
							uint8_t li[1200];
							ssize_t ln = rdp_pdu_build_save_session_logon_v2(
								li, sizeof li, user_id,
								RDP_CONN_SHARE_ID,
								"", tok_user, 0);
							if (ln > 0)
								(void)send_send_data(t,
									user_id, io_channel,
									li, (size_t)ln);
						}
						run_proxy(t, be_fd, &clip,
							&dynvc, &snd, &devr,
							user_id, io_channel,
							desktop_w, desktop_h,
							client_max_request,
							client_color_ptr,
							client_large_ptr,
							client_pointer_cache_size,
							peer);
						(void)close(be_fd);
						goto send_disconnect;
					}
					rdp_sessmgr_close(&sm);
				}
			}
		}
	}

	/* Auto-login: if the client provided credentials in Client Info,
	 * skip the greeter and authenticate directly. */
	if (cfg->sessmgr_sock != NULL && cfg->sessmgr_sock[0] != '\0'
	    && client_info.username[0] != '\0'
	    && (cfg->auto_login || (client_info.have_password && ci_pw_len > 4))) {
		struct rdp_sessmgr sm = { -1, {0} };
		char pw_utf8[256] = {0};
		if (client_info.have_password && ci_pw_len > 0 && ci_pw != NULL) {
			size_t adj_len = ci_pw_len;
			while (adj_len >= 2
			    && ci_pw[adj_len - 1] == 0
			    && ci_pw[adj_len - 2] == 0)
				adj_len -= 2;
			size_t got = rdp_utf16le_to_utf8(pw_utf8,
				sizeof pw_utf8 - 1, ci_pw, adj_len);
			if (got == (size_t)-1 || got >= sizeof pw_utf8) got = 0;
			pw_utf8[got] = '\0';
		}
		rdp_info("conn[%s]: login as %s", peer,
			client_info.username);
		if (rdp_sessmgr_open_auth(&sm, cfg->sessmgr_sock,
			client_info.username,
			pw_utf8[0] ? pw_utf8 : "x", client_ip) == 0) {
			int be_fd = -1;
			if (rdp_sessmgr_spawn(&sm, desktop_w, desktop_h,
				client_lcid, client_info.timezone,
				&be_fd) == 0) {
				rdp_sessmgr_close(&sm);
				rdp_info("conn[%s]: backend fd %d",
					peer, be_fd);
				{
					uint8_t li[1200];
					ssize_t ln = rdp_pdu_build_save_session_logon_v2(
						li, sizeof li, user_id,
						RDP_CONN_SHARE_ID,
						client_info.domain,
						client_info.username, 0);
					if (ln > 0)
						(void)send_send_data(t, user_id,
							io_channel, li, (size_t)ln);
				}
				run_proxy(t, be_fd, &clip, &dynvc, &snd,
					&devr, user_id, io_channel,
					desktop_w, desktop_h,
					client_max_request,
					client_color_ptr, client_large_ptr,
					client_pointer_cache_size,
					peer);
				(void)close(be_fd);
				goto send_disconnect;
			}
			rdp_sessmgr_close(&sm);
		}
		rdp_warn("conn[%s]: auto-login auth failed, trying greeter", peer);
		explicit_bzero(pw_utf8, sizeof pw_utf8);
	}

	{
		struct rdp_greeter_result gr;
		struct rdp_sessmgr sm = { -1, {0} };
		struct sessmgr_auth_ctx actx = { cfg->sessmgr_sock, &sm, client_ip };
		rdp_greeter_auth_fn auth_fn = NULL;
		void               *auth_ctx = NULL;

		memset(&gr, 0, sizeof gr);
		if (cfg->sessmgr_sock != NULL && cfg->sessmgr_sock[0] != '\0') {
			auth_fn  = sessmgr_auth_thunk;
			auth_ctx = &actx;
		}
		if (rdp_greeter_run(t, desktop_w, desktop_h, client_lcid,
			auth_fn, auth_ctx, &gr) != 0) {
			rdp_info("conn[%s]: greeter cancelled or failed", peer);
			if (sm.fd >= 0) rdp_sessmgr_close(&sm);
			goto done;
		}
		rdp_info("conn[%s]: login as %s", peer, gr.username);

		if (sm.fd < 0) {
			rdp_info("conn[%s]: no sessmgr; skipping SPAWN", peer);
			send_error_info(t, user_id, io_channel,
				ERRINFO_SERVER_DENIED_CONNECTION);
			goto done;
		}
		{
			int be_fd = -1;
			if (rdp_sessmgr_spawn(&sm, desktop_w, desktop_h,
				client_lcid, client_info.timezone,
				&be_fd) != 0) {
				rdp_err("conn[%s]: SPAWN failed: %s",
					peer, strerror(errno));
				rdp_sessmgr_close(&sm);
				send_error_info(t, user_id, io_channel,
					ERRINFO_SERVER_DENIED_CONNECTION);
				goto done;
			}
			rdp_sessmgr_close(&sm);

			/* Issue an auto-reconnect cookie so the client can
			 * resume this session if the connection drops. */
			logon_id = rdp_rand_u32();
			rdp_rand_bytes(arc_random, sizeof arc_random);
			{
				uint8_t ssi[128];
				ssize_t sn = rdp_pdu_build_save_session_info_arc(
					ssi, sizeof ssi, user_id,
					RDP_CONN_SHARE_ID,
					logon_id, arc_random);
				if (sn > 0)
					(void)send_send_data(t, user_id,
						io_channel, ssi, (size_t)sn);
			}
			{
				uint8_t li[1200];
				ssize_t ln = rdp_pdu_build_save_session_logon_v2(
					li, sizeof li, user_id,
					RDP_CONN_SHARE_ID,
					"", gr.username, logon_id);
				if (ln > 0)
					(void)send_send_data(t, user_id,
						io_channel, li, (size_t)ln);
			}

			rdp_info("conn[%s]: backend fd %d (cliprdr=%s)",
				peer, be_fd,
				clip.enabled ? "enabled" : "off");
			run_proxy(t, be_fd, &clip, &dynvc, &snd, &devr,
				user_id, io_channel,
				desktop_w, desktop_h, client_max_request,
				client_color_ptr, client_large_ptr,
				client_pointer_cache_size, peer);

			/* On disconnect: try to SUSPEND so a reconnecting
			 * client can resume without re-authenticating. */
			if (cfg->sessmgr_sock != NULL
			    && cfg->sessmgr_sock[0] != '\0'
			    && rdp_sessmgr_suspend(cfg->sessmgr_sock,
				logon_id, arc_random, be_fd) == 0)
				rdp_info("conn[%s]: session suspended "
					"(logonId=%u)", peer,
					(unsigned)logon_id);
			(void)close(be_fd);
		}
	}

send_disconnect:

	/* Outbound MCS Disconnect Provider Ultimatum.  This is its own
	 * MCS PDU type, NOT a Send Data Indication -- wrap in X.224 DT +
	 * TPKT only.  Reason 0 = rn-user-requested. */
	{
		uint8_t body[4];
		ssize_t bn = rdp_mcs_build_disconnect(body, sizeof body, 0);
		if (bn > 0)
			(void)send_mcs_raw(t, body, (size_t)bn);
	}

done:
	rdp_cliprdr_reasm_reset(&clip.reasm);
	explicit_bzero(nla_pass, sizeof nla_pass);
	rdp_bmpcache_destroy(g_bmpcache);
	g_bmpcache = NULL;
	if (t != NULL) rdp_tls_close(t);
	(void)close(fd);
	rdp_debug("conn[%s]: done", peer);
}
