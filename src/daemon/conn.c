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
#include "../channels/rdpgfx.h"
#include "../wire/h264enc.h"
#include "../common/utf16.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <poll.h>

#include <errno.h>
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

struct proxy_input_ctx {
	int be_fd;
	int last_mouse_x, last_mouse_y;
};

struct clip_state {
	int      enabled;
	uint16_t channel_id;
	uint16_t user_id;
	int      use_long_names;
	int      caps_sent;
};

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
		int has_uc = 0, has_text = 0;
		(void)rdp_cliprdr_parse_format_list(pdu + 8,
			len > 8 ? len - 8 : 0,
			cs->use_long_names, &has_uc, &has_text);
		rdp_debug("cliprdr: client format list (unicode=%d text=%d)",
			has_uc, has_text);
		{
			uint8_t r[16];
			ssize_t rn = rdp_cliprdr_build_format_list_response(
				r, sizeof r, 1);
			if (rn > 0)
				(void)send_clip_pdu(t, cs->user_id,
					cs->channel_id, r, (size_t)rn);
		}
		if (has_uc || has_text) {
			struct rdp_be_clip_offer offer = {
				RDP_BE_CLIP_FMT_TEXT };
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
			struct rdp_be_clip_request req = {
				RDP_BE_CLIP_FMT_TEXT };
			(void)format;
			(void)rdp_be_send(be_fd, RDP_BE_CLIP_REQUEST,
				&req, sizeof req);
		}
		break;
	}
	case CB_FORMAT_DATA_RESPONSE: {
		size_t data_off = 8;
		size_t data_len = h.data_len;
		uint8_t *out;
		size_t  out_size;

		if (data_off + data_len > len) data_len = len - data_off;
		out_size = sizeof(struct rdp_be_clip_data_hdr)
			+ data_len * 2 + 1;
		out = malloc(out_size);
		if (out == NULL) break;
		{
			struct rdp_be_clip_data_hdr h2;
			size_t got;
			h2.format = RDP_BE_CLIP_FMT_TEXT;
			h2.status = (h.msg_flags & CB_RESPONSE_FAIL) ? 1 : 0;
			memcpy(out, &h2, sizeof h2);
			got = rdp_utf16le_to_utf8(
				(char *)out + sizeof h2,
				out_size - sizeof h2,
				pdu + data_off, data_len);
			if (got == (size_t)-1) got = 0;
			while (got > 0
			    && ((char *)out + sizeof h2)[got - 1] == '\0')
				got--;
			(void)rdp_be_send(be_fd, RDP_BE_CLIP_DATA,
				out, sizeof h2 + got);
		}
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
	case RDP_BE_CLIP_OFFER:
		if (!cs->enabled) return 0;
		(void)payload; (void)len;
		n = rdp_cliprdr_build_format_list_unicode_text(
			pdu, sizeof pdu);
		if (n < 0) return -1;
		return send_clip_pdu(t, cs->user_id, cs->channel_id,
			pdu, (size_t)n);
	case RDP_BE_CLIP_REQUEST:
		(void)payload; (void)len;
		n = rdp_cliprdr_build_format_data_request(pdu, sizeof pdu,
			CF_UNICODETEXT);
		if (n < 0) return -1;
		return send_clip_pdu(t, cs->user_id, cs->channel_id,
			pdu, (size_t)n);
	case RDP_BE_CLIP_DATA: {
		struct rdp_be_clip_data_hdr h;
		uint8_t *utf16;
		size_t need;
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
		need = (len - sizeof h) * 2 + 2;
		utf16 = malloc(need);
		if (utf16 == NULL) return -1;
		{
			size_t got = rdp_utf8_to_utf16le(utf16, need - 2,
				(const char *)payload + sizeof h,
				len - sizeof h);
			if (got == (size_t)-1) got = 0;
			utf16[got]     = 0;
			utf16[got + 1] = 0;
			n = rdp_cliprdr_build_format_data_response(
				pdu, sizeof pdu, utf16, got + 2, 1);
			free(utf16);
			if (n < 0) return -1;
			rc = send_clip_pdu(t, cs->user_id, cs->channel_id,
				pdu, (size_t)n);
		}
		return rc;
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
	case RDP_FP_INPUT_UNICODE:
	case RDP_FP_INPUT_SYNC:
		/* Not forwarded in v1; xterm and most apps don't care. */
		break;
	default:
		break;
	}
}

/* Tile a frame and push as fast-path bitmap updates. */
static int
push_frame_tiled(struct rdp_tls *t,
		uint16_t fx, uint16_t fy, uint16_t fw, uint16_t fh,
		const uint8_t *pixels)
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
			ssize_t n;
			size_t row;
			for (row = 0; row < th; row++) {
				memcpy(tile_pix + row * tw * 3,
					pixels + ((size_t)(y + row) * fw
						+ x) * 3,
					(size_t)tw * 3);
			}
			n = rdp_fp_build_bitmap_update(pkt, sizeof pkt,
				(uint16_t)(fx + x), (uint16_t)(fy + y),
				tw, th, tile_pix, (size_t)tw * 3);
			if (n < 0) return -1;
			if (rdp_tls_write_full(t, pkt, (size_t)n)
			    != (ssize_t)n)
				return -1;
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
};

struct snd_state {
	int      enabled;
	uint16_t channel_id;
	struct rdpsnd_state snd;
};

struct dr_state {
	int      enabled;
	uint16_t channel_id;
	struct rdpdr_state dr;
};

/* Try to recognise a channel-bearing TPKT/MCS SDR and dispatch.
 * Returns 1 if handled, 0 if not, -1 on disconnect, 2 if a resize
 * is requested (new_w/new_h set). */
static int
maybe_dispatch_clip(struct rdp_tls *t, int be_fd,
		struct clip_state *cs, struct dynvc_state *dv,
		struct snd_state *ss, struct dr_state *dr,
		const uint8_t *frame, size_t frame_len, const char *peer,
		uint16_t *new_w, uint16_t *new_h)
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

	/* If this is on the CLIPRDR channel, hand off. */
	if (cs->enabled && cid == cs->channel_id) {
		if (payload_len < 8) return 1;
		(void)clip_handle_pdu(t, be_fd, cs, payload + 8,
			payload_len - 8);
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
			if (rc == 2) return 2;
			if (rc == 3 && gfx_data != NULL && gfx_len > 0) {
				const uint8_t *gp = gfx_data;
				size_t gl = gfx_len;
				uint16_t cmdId;
				/* Strip ZGFX envelope (0xE0 single + 0x00 uncompressed) */
				if (gl >= 2 && gp[0] == 0xE0) {
					gp += 2;
					gl -= 2;
				}
				if (gl < 2) return 1;
				cmdId = (uint16_t)gp[0]
					| ((uint16_t)gp[1] << 8);
				if (cmdId == RDPGFX_CMDID_CAPSADVERTISE) {
					(void)rdp_rdpgfx_parse_caps_advertise(
						gp, gl);
					return 4;
				}
				if (cmdId == RDPGFX_CMDID_FRAMEACKNOWLEDGE) {
					rdp_debug("rdpgfx: frame ack");
				}
			}
		}
		return 1;
	}

	/* RDPSND channel: audio format negotiation + wave confirm. */
	if (ss->enabled && cid == ss->channel_id) {
		if (payload_len < 8) return 1;
		(void)rdp_rdpsnd_handle(&ss->snd, payload + 8,
			payload_len - 8);
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
			if (rc == 1 && be_fd >= 0) {
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
			RDP_CONN_SHARE_ID, new_w, new_h);
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

#define ZGFX_SEG_MAX 65535

static int
send_gfx_pdu(struct rdp_tls *t, uint16_t user_id,
		uint16_t drdynvc_mcs_chan, int dv_chan,
		const uint8_t *data, size_t len)
{
	uint8_t *wrapped;
	int rc;

	if (len <= ZGFX_SEG_MAX) {
		size_t total = 2 + len;
		wrapped = malloc(total);
		if (wrapped == NULL) return -1;
		wrapped[0] = 0xE0;
		wrapped[1] = 0x00;
		memcpy(wrapped + 2, data, len);
		rc = send_drdynvc_data(t, user_id, drdynvc_mcs_chan, dv_chan,
			wrapped, total);
		free(wrapped);
		return rc;
	}

	{
		uint16_t seg_count = (uint16_t)((len + ZGFX_SEG_MAX - 1)
			/ ZGFX_SEG_MAX);
		size_t hdr_sz = 1 + 2 + 4 + (size_t)seg_count * 4;
		size_t total = hdr_sz + (size_t)seg_count + len;
		size_t off = 0, woff;
		uint16_t i;

		wrapped = malloc(total);
		if (wrapped == NULL) return -1;
		woff = 0;
		wrapped[woff++] = 0xE1;
		wrapped[woff++] = (uint8_t)(seg_count & 0xff);
		wrapped[woff++] = (uint8_t)((seg_count >> 8) & 0xff);
		wrapped[woff++] = (uint8_t)(len & 0xff);
		wrapped[woff++] = (uint8_t)((len >> 8) & 0xff);
		wrapped[woff++] = (uint8_t)((len >> 16) & 0xff);
		wrapped[woff++] = (uint8_t)((len >> 24) & 0xff);
		for (i = 0; i < seg_count; i++) {
			size_t chunk = len - off;
			uint32_t ss;
			if (chunk > ZGFX_SEG_MAX)
				chunk = ZGFX_SEG_MAX;
			ss = (uint32_t)(1 + chunk);
			wrapped[woff++] = (uint8_t)(ss & 0xff);
			wrapped[woff++] = (uint8_t)((ss >> 8) & 0xff);
			wrapped[woff++] = (uint8_t)((ss >> 16) & 0xff);
			wrapped[woff++] = (uint8_t)((ss >> 24) & 0xff);
			wrapped[woff++] = 0x00;
			memcpy(wrapped + woff, data + off, chunk);
			woff += chunk;
			off += chunk;
		}
		rc = send_drdynvc_data(t, user_id, drdynvc_mcs_chan, dv_chan,
			wrapped, woff);
		free(wrapped);
		return rc;
	}
}

static void
run_proxy(struct rdp_tls *t, int be_fd,
		struct clip_state *cs, struct dynvc_state *dv,
		struct snd_state *ss, struct dr_state *dr,
		uint16_t user_id, uint16_t io_channel,
		uint16_t desktop_w, uint16_t desktop_h,
		const char *peer)
{
	struct proxy_input_ctx ictx = { be_fd, 0, 0 };
	uint8_t *frame_buf = NULL;
	size_t   frame_cap = 0;
	struct rdpgfx_state gfx = {0};
	struct rdp_h264 *h264 = NULL;
	gfx.surface_id = 1;
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
		if (cn > 0)
			(void)send_clip_pdu(t, user_id, dv->channel_id,
				dvcaps, (size_t)cn);
		rdp_debug("conn[%s]: drdynvc caps sent (chan=%u)",
			peer, dv->channel_id);
		cn = rdp_drdynvc_build_create_gfx(&dv->dv,
			dvcaps, sizeof dvcaps);
		if (cn > 0)
			(void)send_clip_pdu(t, user_id, dv->channel_id,
				dvcaps, (size_t)cn);
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

	for (;;) {
		struct pollfd pfd[2];
		int tls_fd = rdp_tls_fd(t);

		pfd[0].fd = tls_fd;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		pfd[1].fd = be_fd;
		pfd[1].events = POLLIN;
		pfd[1].revents = 0;
		if (poll(pfd, 2, -1) < 0) {
			if (errno == EINTR) continue;
			break;
		}

		if (pfd[0].revents & POLLIN) {
			uint8_t pdu[0x4000];
			int kind = 0;
			ssize_t n = read_one_rdp_pdu(t, pdu, sizeof pdu, &kind);
			if (n <= 0) break;
			if (kind == 1) {
				uint16_t rw = 0, rh = 0;
				int r = maybe_dispatch_clip(t, be_fd,
					cs, dv, ss, dr,
					pdu, (size_t)n, peer,
					&rw, &rh);
				if (r < 0) break;
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
				}
				if (r == 4 && !gfx.active
				    && dv->dv.gfx_channel_id >= 0) {
					/* GFX caps received; init the pipeline. */
					uint8_t gbuf[512];
					ssize_t gn;
					gn = rdp_rdpgfx_build_caps_confirm(
						gbuf, sizeof gbuf);
					if (gn > 0)
						(void)send_gfx_pdu(t,
							user_id,
							dv->channel_id,
							dv->dv.gfx_channel_id,
							gbuf, (size_t)gn);
					gn = rdp_rdpgfx_build_reset(
						gbuf, sizeof gbuf,
						desktop_w, desktop_h);
					if (gn > 0)
						(void)send_gfx_pdu(t,
							user_id,
							dv->channel_id,
							dv->dv.gfx_channel_id,
							gbuf, (size_t)gn);
					gn = rdp_rdpgfx_build_create_surface(
						gbuf, sizeof gbuf,
						gfx.surface_id,
						desktop_w, desktop_h);
					if (gn > 0)
						(void)send_gfx_pdu(t,
							user_id,
							dv->channel_id,
							dv->dv.gfx_channel_id,
							gbuf, (size_t)gn);
					gn = rdp_rdpgfx_build_map_surface(
						gbuf, sizeof gbuf,
						gfx.surface_id);
					if (gn > 0)
						(void)send_gfx_pdu(t,
							user_id,
							dv->channel_id,
							dv->dv.gfx_channel_id,
							gbuf, (size_t)gn);
					h264 = rdp_h264_open(desktop_w,
						desktop_h);
					if (h264 != NULL) {
						gfx.active = 1;
						rdp_info("conn[%s]: GFX+H.264 active",
							peer);
					}
				}
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
			if (hr <= 0) break;
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
				if (gfx.active && h264 != NULL
				    && dv->dv.gfx_channel_id >= 0) {
					const uint8_t *h264_out;
					size_t h264_len;
					int keyframe;
					if (rdp_h264_encode(h264,
						frame_buf, fhdr.w, fhdr.h,
						&h264_out, &h264_len,
						&keyframe) == 0
					    && h264_out != NULL
					    && h264_len > 0) {
						uint8_t *gpdu;
						size_t gpdu_cap = h264_len
							+ 256;
						gpdu = malloc(gpdu_cap);
						if (gpdu != NULL) {
							ssize_t gn;
							gfx.frame_id++;
							gn = rdp_rdpgfx_build_avc420_frame(
								gpdu, gpdu_cap,
								gfx.surface_id,
								gfx.frame_id,
								fhdr.w, fhdr.h,
								h264_out,
								h264_len);
							if (gn > 0)
								(void)send_gfx_pdu(
									t, user_id,
									dv->channel_id,
									dv->dv.gfx_channel_id,
									gpdu,
									(size_t)gn);
							free(gpdu);
						}
					}
				} else {
					if (push_frame_tiled(t, fhdr.x,
						fhdr.y, fhdr.w, fhdr.h,
						frame_buf) != 0)
						break;
				}
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
			    || type == RDP_BE_CLIP_DATA) {
				uint8_t *pl = NULL;
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
						uint8_t *wpdu = malloc(len + 20);
						if (wpdu != NULL) {
							ssize_t wn;
							wn = rdp_rdpsnd_build_wave2(
							    &ss->snd, wpdu,
							    len + 20,
							    pcm, len);
							if (wn > 0)
								(void)send_clip_pdu(t,
								    user_id,
								    ss->channel_id,
								    wpdu,
								    (size_t)wn);
							free(wpdu);
						}
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
			} else if (type == RDP_BE_FS_REQ
			    && dr->enabled
			    && len >= sizeof(struct rdp_be_fs_req)) {
				struct rdp_be_fs_req freq;
				char path[512];
				uint32_t path_len;
				if (rdp_read_full(be_fd, &freq,
				    sizeof freq) != sizeof freq) goto out;
				{
					uint32_t total_path = len
					    - (uint32_t)sizeof freq;
					path_len = total_path;
					if (path_len > sizeof path - 1)
						path_len = sizeof path - 1;
					if (path_len > 0
					    && rdp_read_full(be_fd, path,
					    path_len) != (ssize_t)path_len)
						goto out;
					path[path_len] = '\0';
					if (total_path > path_len) {
						uint8_t junk[256];
						uint32_t skip = total_path
						    - path_len;
						while (skip > 0) {
							uint32_t c = skip
							    > sizeof junk
							    ? sizeof junk
							    : skip;
							if (rdp_read_full(
							    be_fd, junk, c)
							    <= 0) goto out;
							skip -= c;
						}
					}
				}
				{
					uint8_t irp[2048];
					ssize_t in;
					uint32_t cid = 0;
					struct rdpdr_pending *p;
					switch (freq.op) {
					case RDP_FS_OPEN:
						in = rdp_rdpdr_build_irp_create(
						    &dr->dr, irp, sizeof irp,
						    freq.device_id, path,
						    FILE_READ_DATA | FILE_LIST_DIRECTORY,
						    FILE_OPEN, 0, &cid);
						break;
					case RDP_FS_READ:
						in = rdp_rdpdr_build_irp_read(
						    &dr->dr, irp, sizeof irp,
						    freq.device_id, freq.file_id,
						    freq.length, freq.offset, &cid);
						break;
					case RDP_FS_CLOSE:
						in = rdp_rdpdr_build_irp_close(
						    &dr->dr, irp, sizeof irp,
						    freq.device_id, freq.file_id,
						    &cid);
						break;
					case RDP_FS_LIST:
						in = rdp_rdpdr_build_irp_query_dir(
						    &dr->dr, irp, sizeof irp,
						    freq.device_id, freq.file_id,
						    path_len > 0 ? path : "*",
						    1, &cid);
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
				}
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
	if (h264 != NULL) rdp_h264_close(h264);
	free(frame_buf);
}

struct sessmgr_auth_ctx {
	const char         *sock;
	struct rdp_sessmgr *sm;       /* opened on success */
};

static int
sessmgr_auth_thunk(const char *user, const char *pass, void *ctx)
{
	struct sessmgr_auth_ctx *c = ctx;
	if (c->sm->fd >= 0)
		rdp_sessmgr_close(c->sm);
	return rdp_sessmgr_open_auth(c->sm, c->sock, user, pass);
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
	int use_nla = 0;
	char nla_user[256] = {0}, nla_pass[256] = {0};
	const uint8_t *ci_pw = NULL;
	size_t ci_pw_len = 0;
	struct rdp_tls_ctx *tls = cfg->tls;
	struct clip_state clip = {0};
	struct dynvc_state dynvc = {0};
	struct snd_state snd = {0};
	struct dr_state devr = {0};
	struct rdp_client_info client_info;
	uint32_t logon_id = 0;
	uint8_t  arc_random[16] = {0};
	clip.user_id = user_id;
	dynvc.dv.disp_channel_id = -1;
	dynvc.dv.gfx_channel_id = -1;
	memset(&client_info, 0, sizeof client_info);

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
			/* Check for pending NLA auth token (user was
			 * verified via NLA on a prior connection). */
			FILE *_tf = fopen(NTHASH_PATH ".tok", "r");
			if (_tf != NULL) {
				fclose(_tf);
				(void)unlink(NTHASH_PATH ".tok");
				selected = RDP_PROTO_SSL;
			} else {
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
	rdp_debug("conn[%s]: TLS established", peer);

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
			cr2.early_capability_flags = 0;
			if (ci.has_msgchannel)
				cr2.msgchannel_id =
					(uint16_t)(1004 + ci.channel_count);

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
			if (_jc < 3) {
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
			RDP_CONN_SHARE_ID, desktop_w, desktop_h);
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
				desktop_w, desktop_h, peer);
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
			nla_user, nla_pass) == 0) {
			int be_fd = -1;
			if (rdp_sessmgr_spawn(&sm, desktop_w, desktop_h,
			    &be_fd) == 0 && be_fd >= 0) {
				explicit_bzero(nla_pass, sizeof nla_pass);
				rdp_sessmgr_close(&sm);
				rdp_info("conn[%s]: backend fd %d", peer, be_fd);
				{
					uint8_t ei[128];
					ssize_t en = rdp_pdu_build_set_error_info(
						ei, sizeof ei, user_id,
						RDP_CONN_SHARE_ID, 0);
					if (en > 0)
						(void)send_send_data(t, user_id,
							io_channel, ei, (size_t)en);
					uint8_t li[700];
					ssize_t ln = rdp_pdu_build_save_session_logon(
						li, sizeof li, user_id,
						RDP_CONN_SHARE_ID);
					if (ln > 0)
						(void)send_send_data(t, user_id,
							io_channel, li, (size_t)ln);
				}
				run_proxy(t, be_fd, &clip, &dynvc, &snd,
					&devr, user_id, io_channel,
					desktop_w, desktop_h, peer);
				(void)close(be_fd);
				goto done;
			}
			rdp_sessmgr_close(&sm);
		}
		explicit_bzero(nla_pass, sizeof nla_pass);
		rdp_warn("conn[%s]: NLA auth failed via sessmgr", peer);
		goto done;
	}

	/* Token-based auto-login: NLA verified the user on a prior
	 * connection. Spawn session directly without password. */
	if (!use_nla && cfg->sessmgr_sock != NULL
	    && cfg->sessmgr_sock[0] != '\0') {
		char tok_user[256] = {0};
		FILE *_tf = fopen(NTHASH_PATH ".tok", "r");
		if (_tf != NULL) {
			if (fgets(tok_user, sizeof tok_user, _tf))
				tok_user[strcspn(tok_user, "\n")] = '\0';
			fclose(_tf);
			(void)unlink(NTHASH_PATH ".tok");
			if (tok_user[0] != '\0') {
				struct rdp_sessmgr sm = { -1, {0} };
				rdp_info("conn[%s]: NLA-verified login as %s",
					peer, tok_user);
				if (rdp_sessmgr_open_nla(&sm,
				    cfg->sessmgr_sock, tok_user) == 0) {
					int be_fd = -1;
					if (rdp_sessmgr_spawn(&sm,
					    desktop_w, desktop_h,
					    &be_fd) == 0 && be_fd >= 0) {
						rdp_sessmgr_close(&sm);
						rdp_info("conn[%s]: backend fd %d",
							peer, be_fd);
						run_proxy(t, be_fd, &clip,
							&dynvc, &snd, &devr,
							user_id, io_channel,
							desktop_w, desktop_h,
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
			pw_utf8[0] ? pw_utf8 : "x") == 0) {
			int be_fd = -1;
			if (rdp_sessmgr_spawn(&sm, desktop_w, desktop_h,
				&be_fd) == 0) {
				rdp_sessmgr_close(&sm);
				rdp_info("conn[%s]: backend fd %d",
					peer, be_fd);
				run_proxy(t, be_fd, &clip, &dynvc, &snd,
					&devr, user_id, io_channel,
					desktop_w, desktop_h, peer);
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
		struct sessmgr_auth_ctx actx = { cfg->sessmgr_sock, &sm };
		rdp_greeter_auth_fn auth_fn = NULL;
		void               *auth_ctx = NULL;

		memset(&gr, 0, sizeof gr);
		if (cfg->sessmgr_sock != NULL && cfg->sessmgr_sock[0] != '\0') {
			auth_fn  = sessmgr_auth_thunk;
			auth_ctx = &actx;
		}
		if (rdp_greeter_run(t, desktop_w, desktop_h,
			auth_fn, auth_ctx, &gr) != 0) {
			rdp_info("conn[%s]: greeter cancelled or failed", peer);
			if (sm.fd >= 0) rdp_sessmgr_close(&sm);
			goto done;
		}
		rdp_info("conn[%s]: login as %s", peer, gr.username);

		if (sm.fd < 0) {
			rdp_info("conn[%s]: no sessmgr; skipping SPAWN", peer);
			goto done;
		}
		{
			int be_fd = -1;
			if (rdp_sessmgr_spawn(&sm, desktop_w, desktop_h,
				&be_fd) != 0) {
				rdp_err("conn[%s]: SPAWN failed: %s",
					peer, strerror(errno));
				rdp_sessmgr_close(&sm);
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

			rdp_info("conn[%s]: backend fd %d (cliprdr=%s)",
				peer, be_fd,
				clip.enabled ? "enabled" : "off");
			run_proxy(t, be_fd, &clip, &dynvc, &snd, &devr,
				user_id, io_channel,
				desktop_w, desktop_h, peer);

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
	explicit_bzero(nla_pass, sizeof nla_pass);
	if (t != NULL) rdp_tls_close(t);
	(void)close(fd);
	rdp_debug("conn[%s]: done", peer);
}
