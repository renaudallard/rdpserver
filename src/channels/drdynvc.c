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
 * drdynvc.c -- DRDYNVC + RDPEDISP minimal implementation.
 */

#include "drdynvc.h"

#include "../include/rdp_log.h"

#include <stdlib.h>
#include <string.h>

ssize_t
rdp_drdynvc_build_caps(uint8_t *out, size_t cap)
{
	if (cap < 12) return -1;
	out[0] = (DRDYNVC_CMD_CAPS << 4) | (1 << 2);  /* Cmd=5, Sp=1, cbId=0 */
	out[1] = 0;                         /* pad */
	out[2] = 3;                         /* version LE low (v3) */
	out[3] = 0;                         /* version LE high */
	out[4] = 0; out[5] = 0;            /* PriorityCharge0 (2 bytes LE) */
	out[6] = 0; out[7] = 0;            /* PriorityCharge1 (2 bytes LE) */
	out[8] = 0; out[9] = 0;            /* PriorityCharge2 (2 bytes LE) */
	out[10] = 0; out[11] = 0;          /* PriorityCharge3 (2 bytes LE) */
	return 12;
}

static int
read_channel_id(const uint8_t *p, size_t len, uint8_t cbId,
		uint32_t *id_out, size_t *consumed)
{
	switch (cbId) {
	case 0:
		if (len < 1) return -1;
		*id_out = p[0];
		*consumed = 1;
		return 0;
	case 1:
		if (len < 2) return -1;
		*id_out = (uint32_t)p[0] | ((uint32_t)p[1] << 8);
		*consumed = 2;
		return 0;
	case 2:
		if (len < 4) return -1;
		*id_out = (uint32_t)p[0] | ((uint32_t)p[1] << 8)
			| ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
		*consumed = 4;
		return 0;
	}
	return -1;
}

static uint32_t
ld32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
		| ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int
rdp_drdynvc_handle(struct drdynvc_state *st,
		const uint8_t *pdu, size_t len,
		uint8_t *resp_out, size_t resp_cap, size_t *resp_len,
		uint16_t *new_w, uint16_t *new_h,
		const uint8_t **gfx_data, size_t *gfx_len)
{
	uint8_t hdr, cmd, cbId;
	*resp_len = 0;
	if (gfx_data) *gfx_data = NULL;
	if (gfx_len) *gfx_len = 0;

	if (len < 1) return -1;
	hdr = pdu[0];
	cmd = (uint8_t)((hdr >> 4) & 0x0f);
	cbId = (uint8_t)(hdr & 0x03);

	rdp_debug("drdynvc: recv cmd=%u cbId=%u len=%zu hdr=%02x %02x %02x %02x",
		cmd, cbId, len,
		pdu[0], len>1?pdu[1]:0, len>2?pdu[2]:0, len>3?pdu[3]:0);

	switch (cmd) {
	case DRDYNVC_CMD_CAPS: {
		uint16_t cli_ver = 0;
		if (len >= 4)
			cli_ver = (uint16_t)pdu[2] | ((uint16_t)pdu[3] << 8);
		st->caps_exchanged = 1;
		rdp_info("drdynvc: client caps ver=%u", cli_ver);
		return 5;
	}

	case DRDYNVC_CMD_CREATE: {
		uint32_t chan_id;
		size_t id_len;
		if (read_channel_id(pdu + 1, len - 1, cbId,
			&chan_id, &id_len) != 0) return -1;
		/* Create Response to our DisplayControl request: once
		 * the channel is up the caller sends the caps PDU. */
		if (st->disp_create_pending
		    && (int)chan_id == st->disp_channel_id) {
			size_t remain = len - 1 - id_len;
			int32_t status = 0;
			if (remain >= 4)
				status = (int32_t)ld32(pdu + 1 + id_len);
			st->disp_create_pending = 0;
			if (status == 0) {
				rdp_info("drdynvc: DisplayControl "
					"channel created ok");
				return 8;
			}
			rdp_warn("drdynvc: DisplayControl create "
				"failed (%d)", (int)status);
			st->disp_channel_id = -1;
			return 0;
		}
		/* Create Response to our server-initiated request. */
		if (st->gfx_create_pending
		    && (int)chan_id == st->gfx_channel_id) {
			size_t remain = len - 1 - id_len;
			int32_t status = 0;
			if (remain >= 4)
				status = (int32_t)ld32(pdu + 1 + id_len);
			st->gfx_create_pending = 0;
			if (status == 0) {
				rdp_info("drdynvc: GFX channel created ok");
			} else {
				rdp_warn("drdynvc: GFX create failed (%d)",
					(int)status);
				st->gfx_channel_id = -1;
			}
			return 0;
		}
		/* Create Response for the AUDIO_INPUT channel.  A nonzero
		 * status (client declined the mic) is not an error: we just
		 * mark the channel unavailable and no audio ever arrives. */
		if (st->audioin_create_pending
		    && (int)chan_id == st->audioin_channel_id) {
			size_t remain = len - 1 - id_len;
			int32_t status = 0;
			if (remain >= 4)
				status = (int32_t)ld32(pdu + 1 + id_len);
			st->audioin_create_pending = 0;
			if (status == 0) {
				rdp_info("drdynvc: AUDIO_INPUT channel "
					"created ok");
				/* The caller now sends the initial SNDIN
				 * Version PDU to start the negotiation. */
				return 10;
			}
			rdp_info("drdynvc: AUDIO_INPUT not opened by "
				"client (%d)", (int)status);
			st->audioin_channel_id = -1;
			return 0;
		}
		/* Client-initiated Create Request. */
		{
			const char *name = (const char *)pdu + 1 + id_len;
			size_t name_avail = len - 1 - id_len;
			if (memchr(name, 0, name_avail) == NULL) return -1;
			rdp_debug("drdynvc: Create chan=%u name='%s'",
				(unsigned)chan_id, name);
			if (strstr(name, "DisplayControl") != NULL) {
				st->disp_channel_id = (int)chan_id;
				rdp_info("drdynvc: DisplayControl on chan %u",
					(unsigned)chan_id);
			}
			if (strstr(name, "GraphicsPipeline") != NULL) {
				st->gfx_channel_id = (int)chan_id;
				rdp_info("drdynvc: GraphicsPipeline on chan %u",
					(unsigned)chan_id);
			}
			if (resp_cap >= 1 + id_len + 4) {
				resp_out[0] = hdr;
				memcpy(resp_out + 1, pdu + 1, id_len);
				memset(resp_out + 1 + id_len, 0, 4);
				*resp_len = 1 + id_len + 4;
			}
		}
		return 0;
	}

	case DRDYNVC_CMD_DATA:
	case DRDYNVC_CMD_DATA_FIRST: {
		uint32_t chan_id;
		size_t id_len;
		const uint8_t *data;
		size_t data_len;
		uint32_t total_len = 0;

		if (read_channel_id(pdu + 1, len - 1, cbId,
			&chan_id, &id_len) != 0) return -1;
		data = pdu + 1 + id_len;
		data_len = len - 1 - id_len;

		if (cmd == DRDYNVC_CMD_DATA_FIRST) {
			uint8_t lenSz = (uint8_t)((hdr >> 2) & 0x03);
			size_t skip = 0;
			switch (lenSz) {
			case 0:
				if (data_len < 1) return -1;
				total_len = data[0];
				skip = 1;
				break;
			case 1:
				if (data_len < 2) return -1;
				total_len = (uint32_t)data[0]
					| ((uint32_t)data[1] << 8);
				skip = 2;
				break;
			case 2:
				if (data_len < 4) return -1;
				total_len = ld32(data);
				skip = 4;
				break;
			}
			data += skip;
			data_len -= skip;
		}

		/* GFX channel: handle reassembly for fragmented PDUs. */
		if ((int)chan_id == st->gfx_channel_id
		    && gfx_data != NULL && gfx_len != NULL) {
			if (cmd == DRDYNVC_CMD_DATA_FIRST) {
				if (total_len == 0 || total_len > 0x400000)
					return -1;
				if (total_len > st->reasm_cap) {
					free(st->reasm_buf);
					st->reasm_buf = malloc(total_len);
					if (st->reasm_buf == NULL) {
						st->reasm_cap = 0;
						return -1;
					}
					st->reasm_cap = total_len;
				}
				st->reasm_total = total_len;
				st->reasm_len = 0;
				st->reasm_chan = (int)chan_id;
				if (data_len > total_len)
					data_len = total_len;
				memcpy(st->reasm_buf, data, data_len);
				st->reasm_len = data_len;
				if (st->reasm_len >= st->reasm_total) {
					*gfx_data = st->reasm_buf;
					*gfx_len = st->reasm_len;
					st->reasm_len = 0;
					st->reasm_total = 0;
					return 3;
				}
				return 0;
			}
			if (st->reasm_len > 0
			    && st->reasm_chan == (int)chan_id) {
				size_t remain = st->reasm_total
					- st->reasm_len;
				if (data_len > remain)
					data_len = remain;
				memcpy(st->reasm_buf + st->reasm_len,
					data, data_len);
				st->reasm_len += data_len;
				if (st->reasm_len >= st->reasm_total) {
					*gfx_data = st->reasm_buf;
					*gfx_len = st->reasm_len;
					st->reasm_len = 0;
					st->reasm_total = 0;
					return 3;
				}
				return 0;
			}
			*gfx_data = data;
			*gfx_len = data_len;
			return 3;
		}

		/* AUDIO_INPUT channel (MS-RDPEAI): one SNDIN PDU per Data PDU
		 * in the common case; reassemble a fragmented one with its own
		 * buffer so an interleaved GFX fragment sequence cannot clobber
		 * it (and vice versa). */
		if ((int)chan_id == st->audioin_channel_id
		    && st->audioin_channel_id >= 0
		    && gfx_data != NULL && gfx_len != NULL) {
			if (cmd == DRDYNVC_CMD_DATA_FIRST) {
				if (total_len == 0 || total_len > 0x400000)
					return -1;
				if (total_len > st->ai_reasm_cap) {
					free(st->ai_reasm_buf);
					st->ai_reasm_buf = malloc(total_len);
					if (st->ai_reasm_buf == NULL) {
						st->ai_reasm_cap = 0;
						return -1;
					}
					st->ai_reasm_cap = total_len;
				}
				st->ai_reasm_total = total_len;
				st->ai_reasm_len = 0;
				if (data_len > total_len)
					data_len = total_len;
				memcpy(st->ai_reasm_buf, data, data_len);
				st->ai_reasm_len = data_len;
				if (st->ai_reasm_len >= st->ai_reasm_total) {
					*gfx_data = st->ai_reasm_buf;
					*gfx_len = st->ai_reasm_len;
					st->ai_reasm_len = 0;
					st->ai_reasm_total = 0;
					return 9;
				}
				return 0;
			}
			if (st->ai_reasm_len > 0) {
				size_t remain = st->ai_reasm_total
					- st->ai_reasm_len;
				if (data_len > remain)
					data_len = remain;
				memcpy(st->ai_reasm_buf + st->ai_reasm_len,
					data, data_len);
				st->ai_reasm_len += data_len;
				if (st->ai_reasm_len >= st->ai_reasm_total) {
					*gfx_data = st->ai_reasm_buf;
					*gfx_len = st->ai_reasm_len;
					st->ai_reasm_len = 0;
					st->ai_reasm_total = 0;
					return 9;
				}
				return 0;
			}
			*gfx_data = data;
			*gfx_len = data_len;
			return 9;
		}
		if ((int)chan_id != st->disp_channel_id)
			return 0;

		/* MS-RDPEDISP Display Update: type(4) length(4)
		 * pad(4) numMonitors(4) then monitor array.
		 * Each monitor: flags(4) left(4) top(4) w(4) h(4)
		 * physW(4) physH(4) orient(4) dsfX(4) dsfY(4) = 40 bytes */
		if (data_len < 16 + 40) return 0;
		{
			uint32_t nm = ld32(data + 12);
			uint32_t mi;
			int32_t min_x = 0, min_y = 0;
			int32_t max_x = 0, max_y = 0;
			if (nm < 1 || nm > 16) return 0;
			if (data_len < 16 + nm * 40) return 0;
			for (mi = 0; mi < nm; mi++) {
				const uint8_t *m = data + 16 + mi * 40;
				int32_t ml = (int32_t)ld32(m + 4);
				int32_t mt = (int32_t)ld32(m + 8);
				uint32_t mw = ld32(m + 12);
				uint32_t mh = ld32(m + 16);
				int32_t mr = ml + (int32_t)mw;
				int32_t mb = mt + (int32_t)mh;
				if (mi == 0) {
					min_x = ml; min_y = mt;
					max_x = mr; max_y = mb;
				} else {
					if (ml < min_x) min_x = ml;
					if (mt < min_y) min_y = mt;
					if (mr > max_x) max_x = mr;
					if (mb > max_y) max_y = mb;
				}
			}
			{
				uint32_t tw = (uint32_t)(max_x - min_x);
				uint32_t th = (uint32_t)(max_y - min_y);
				if (tw >= 200 && tw <= 8192
				    && th >= 200 && th <= 8192) {
					*new_w = (uint16_t)tw;
					*new_h = (uint16_t)th;
					rdp_info("drdynvc: resize %ux%u "
						"(%u monitors)",
						(unsigned)tw, (unsigned)th,
						(unsigned)nm);
					return 1;
				}
			}
		}
		return 0;
	}

	case DRDYNVC_CMD_CLOSE: {
		uint32_t chan_id;
		size_t id_len;
		if (read_channel_id(pdu + 1, len - 1, cbId,
			&chan_id, &id_len) == 0
		    && (int)chan_id == st->gfx_channel_id) {
			rdp_info("drdynvc: GFX channel %u closed by client",
				(unsigned)chan_id);
			st->gfx_channel_id = -1;
			return 7;
		}
		return 0;
	}
	}
	return 0;
}

#define GFX_CHANNEL_NAME "Microsoft::Windows::RDS::Graphics"
#define GFX_SERVER_CHAN_ID 1
#define DISP_CHANNEL_NAME "Microsoft::Windows::RDS::DisplayControl"
#define DISP_SERVER_CHAN_ID 2
#define AUDIOIN_CHANNEL_NAME "AUDIO_INPUT"
#define AUDIOIN_SERVER_CHAN_ID 3

ssize_t
rdp_drdynvc_build_create_gfx(struct drdynvc_state *st,
		uint8_t *out, size_t cap)
{
	size_t name_len = sizeof(GFX_CHANNEL_NAME);
	size_t total = 1 + 1 + name_len;

	if (cap < total) return -1;
	out[0] = (uint8_t)((DRDYNVC_CMD_CREATE << 4) | (2 << 2) | 0);
	out[1] = GFX_SERVER_CHAN_ID;
	memcpy(out + 2, GFX_CHANNEL_NAME, name_len);
	st->gfx_channel_id = GFX_SERVER_CHAN_ID;
	st->gfx_create_pending = 1;
	return (ssize_t)total;
}

ssize_t
rdp_drdynvc_build_create_disp(struct drdynvc_state *st,
		uint8_t *out, size_t cap)
{
	size_t name_len = sizeof(DISP_CHANNEL_NAME);
	size_t total = 1 + 1 + name_len;

	if (cap < total) return -1;
	out[0] = (uint8_t)((DRDYNVC_CMD_CREATE << 4) | (2 << 2) | 0);
	out[1] = DISP_SERVER_CHAN_ID;
	memcpy(out + 2, DISP_CHANNEL_NAME, name_len);
	st->disp_channel_id = DISP_SERVER_CHAN_ID;
	st->disp_create_pending = 1;
	return (ssize_t)total;
}

ssize_t
rdp_drdynvc_build_create_audio_input(struct drdynvc_state *st,
		uint8_t *out, size_t cap)
{
	size_t name_len = sizeof(AUDIOIN_CHANNEL_NAME);
	size_t total = 1 + 1 + name_len;

	if (cap < total) return -1;
	out[0] = (uint8_t)((DRDYNVC_CMD_CREATE << 4) | (2 << 2) | 0);
	out[1] = AUDIOIN_SERVER_CHAN_ID;
	memcpy(out + 2, AUDIOIN_CHANNEL_NAME, name_len);
	st->audioin_channel_id = AUDIOIN_SERVER_CHAN_ID;
	st->audioin_create_pending = 1;
	return (ssize_t)total;
}

/* MS-RDPEDISP 2.2.2.1 DISPLAYCONTROL_CAPS_PDU: the server's monitor
 * limits, sent once the DisplayControl channel is created so the
 * client knows it may request a dynamic resize. */
ssize_t
rdp_drdynvc_build_disp_caps(uint8_t *out, size_t cap)
{
	if (cap < 20) return -1;
	memset(out, 0, 20);
	out[0]  = 0x05;   /* Type = DISPLAYCONTROL_PDU_TYPE_CAPS */
	out[4]  = 20;     /* Length */
	out[8]  = 16;     /* MaxNumMonitors */
	out[13] = 0x20;   /* MaxMonitorAreaFactorA = 8192 (0x2000) */
	out[17] = 0x20;   /* MaxMonitorAreaFactorB = 8192 (0x2000) */
	return 20;
}

void
rdp_drdynvc_cleanup(struct drdynvc_state *st)
{
	free(st->reasm_buf);
	st->reasm_buf = NULL;
	st->reasm_cap = 0;
	st->reasm_len = 0;
	st->reasm_total = 0;
	free(st->ai_reasm_buf);
	st->ai_reasm_buf = NULL;
	st->ai_reasm_cap = 0;
	st->ai_reasm_len = 0;
	st->ai_reasm_total = 0;
}
