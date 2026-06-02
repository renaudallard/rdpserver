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
 * rdpsnd.c -- RDPSND format negotiation.
 */

#include "rdpsnd.h"

#include "../include/rdp_log.h"
#include "../common/buf.h"

/* G.711 A-law encoder (ITU-T / Sun reference).  A 16-bit linear sample
 * maps to one A-law byte.  The arithmetic right shift on a signed value
 * is the standard 16-to-13-bit domain reduction. */
static const int16_t alaw_seg_end[8] = {
	0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF
};

static uint8_t
linear16_to_alaw(int16_t lin)
{
	int pcm = lin >> 3;
	int seg, mask, aval;

	if (pcm >= 0) {
		mask = 0xD5;
	} else {
		mask = 0x55;
		pcm = -pcm - 1;
	}
	for (seg = 0; seg < 8; seg++)
		if (pcm <= alaw_seg_end[seg])
			break;
	if (seg >= 8)
		return (uint8_t)(0x7F ^ mask);
	aval = seg << 4;
	if (seg < 2)
		aval |= (pcm >> 1) & 0x0F;
	else
		aval |= (pcm >> seg) & 0x0F;
	return (uint8_t)(aval ^ mask);
}

size_t
rdp_rdpsnd_alaw_encode(const uint8_t *pcm, size_t pcm_len, uint8_t *out)
{
	size_t n = pcm_len / 2, i;

	for (i = 0; i < n; i++) {
		int16_t s = (int16_t)((uint16_t)pcm[i * 2]
			| ((uint16_t)pcm[i * 2 + 1] << 8));
		out[i] = linear16_to_alaw(s);
	}
	return n;
}

ssize_t
rdp_rdpsnd_build_formats(uint8_t *out, size_t cap)
{
	struct rdp_buf b;

	/* RDPSND PDU header (4 bytes) + body.
	 * Body layout (MS-RDPEA 2.2.2.1):
	 *   dwFlags          u32
	 *   dwVolume         u32
	 *   dwPitch          u32
	 *   wDGramPort       u16
	 *   wNumberOfFormats u16
	 *   cLastBlockConfirmed u8
	 *   wVersion         u16
	 *   bPad             u8
	 * Then one AUDIO_FORMAT (18 bytes for PCM with cbSize=0):
	 *   wFormatTag       u16
	 *   nChannels        u16
	 *   nSamplesPerSec   u32
	 *   nAvgBytesPerSec  u32
	 *   nBlockAlign      u16
	 *   wBitsPerSample   u16
	 *   cbSize           u16
	 */
	uint16_t body_size = 20 + 2 * 18;
	if (cap < (size_t)4 + body_size) return -1;

	rdp_buf_init(&b, out, cap);
	/* PDU header */
	if (rdp_buf_put_u8(&b, SNDC_FORMATS) != 0) return -1;
	if (rdp_buf_put_u8(&b, 0) != 0) return -1;
	if (rdp_buf_put_u16le(&b, body_size) != 0) return -1;

	/* Body */
	if (rdp_buf_put_u32le(&b, 0) != 0) return -1;           /* dwFlags */
	if (rdp_buf_put_u32le(&b, 0xFFFFFFFF) != 0) return -1;  /* dwVolume */
	if (rdp_buf_put_u32le(&b, 0) != 0) return -1;           /* dwPitch */
	if (rdp_buf_put_u16le(&b, 0) != 0) return -1;           /* wDGramPort */
	if (rdp_buf_put_u16le(&b, 2) != 0) return -1;           /* wNumberOfFormats */
	if (rdp_buf_put_u8(&b, 0) != 0) return -1;              /* cLastBlockConfirmed */
	if (rdp_buf_put_u16le(&b, RDPSND_VERSION) != 0) return -1;
	if (rdp_buf_put_u8(&b, 0) != 0) return -1;              /* bPad */

	/* AUDIO_FORMAT[0]: PCM 16-bit stereo 44100 Hz */
	if (rdp_buf_put_u16le(&b, WAVE_FORMAT_PCM) != 0) return -1;
	if (rdp_buf_put_u16le(&b, 2) != 0) return -1;           /* nChannels */
	if (rdp_buf_put_u32le(&b, 44100) != 0) return -1;       /* nSamplesPerSec */
	if (rdp_buf_put_u32le(&b, 176400) != 0) return -1;      /* nAvgBytesPerSec */
	if (rdp_buf_put_u16le(&b, 4) != 0) return -1;           /* nBlockAlign */
	if (rdp_buf_put_u16le(&b, 16) != 0) return -1;          /* wBitsPerSample */
	if (rdp_buf_put_u16le(&b, 0) != 0) return -1;           /* cbSize */

	/* AUDIO_FORMAT[1]: G.711 A-law 8-bit stereo 44100 Hz (2:1) */
	if (rdp_buf_put_u16le(&b, WAVE_FORMAT_ALAW) != 0) return -1;
	if (rdp_buf_put_u16le(&b, 2) != 0) return -1;           /* nChannels */
	if (rdp_buf_put_u32le(&b, 44100) != 0) return -1;       /* nSamplesPerSec */
	if (rdp_buf_put_u32le(&b, 88200) != 0) return -1;       /* nAvgBytesPerSec */
	if (rdp_buf_put_u16le(&b, 2) != 0) return -1;           /* nBlockAlign */
	if (rdp_buf_put_u16le(&b, 8) != 0) return -1;           /* wBitsPerSample */
	if (rdp_buf_put_u16le(&b, 0) != 0) return -1;           /* cbSize */

	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_rdpsnd_build_training(uint8_t *out, size_t cap)
{
	struct rdp_buf b;

	if (cap < 8) return -1;
	rdp_buf_init(&b, out, cap);
	if (rdp_buf_put_u8(&b, SNDC_TRAINING) != 0) return -1;
	if (rdp_buf_put_u8(&b, 0) != 0) return -1;
	if (rdp_buf_put_u16le(&b, 4) != 0) return -1;
	if (rdp_buf_put_u16le(&b, 0) != 0) return -1;
	if (rdp_buf_put_u16le(&b, 0) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_rdpsnd_build_wave2(struct rdpsnd_state *st,
		uint8_t *out, size_t cap,
		const uint8_t *data, size_t data_len)
{
	struct rdp_buf b;
	size_t body_size = 12 + data_len;

	if (body_size > 0xFFFF) return -1;
	if (cap < 4 + body_size) return -1;
	rdp_buf_init(&b, out, cap);

	if (rdp_buf_put_u8(&b, SNDC_WAVE2) != 0) return -1;
	if (rdp_buf_put_u8(&b, 0) != 0) return -1;
	if (rdp_buf_put_u16le(&b, (uint16_t)body_size) != 0) return -1;
	if (rdp_buf_put_u16le(&b, st->timestamp) != 0) return -1;
	if (rdp_buf_put_u16le(&b, st->format_no) != 0) return -1;
	if (rdp_buf_put_u8(&b, st->block_no) != 0) return -1;
	st->block_no++;
	if (rdp_buf_put_u8(&b, 0) != 0) return -1;
	if (rdp_buf_put_u8(&b, 0) != 0) return -1;
	if (rdp_buf_put_u8(&b, 0) != 0) return -1;
	if (rdp_buf_put_u32le(&b, (uint32_t)st->timestamp) != 0) return -1;
	if (rdp_buf_put(&b, data, data_len) != 0) return -1;

	{
		uint16_t ba = st->chosen_block_align ?
			st->chosen_block_align : 4;
		uint32_t rate = st->chosen_rate ? st->chosen_rate : 44100;
		st->timestamp += (uint16_t)((uint32_t)(data_len / ba)
			* 1000 / rate);
	}
	return (ssize_t)rdp_buf_used(&b);
}

int
rdp_rdpsnd_handle(struct rdpsnd_state *st,
		const uint8_t *pdu, size_t len, int prefer_wan)
{
	uint8_t msg_type;

	if (len < 4) return -1;
	msg_type = pdu[0];   /* SNDPROLOG msgType; PDUs differ by this */

	switch (msg_type) {
	case SNDC_FORMATS: {
		/* Client Audio Formats response.  Walk the echoed
		 * AUDIO_FORMAT list and choose A-law if the operator
		 * prefers the compact format and the client accepts it;
		 * otherwise keep PCM (index 0), which is always safe. */
		uint16_t nfmt;
		size_t off, i;
		int has_alaw = 0;

		if (len < 24) return -1;
		/* wNumberOfFormats is at body offset 14 (pdu[18..19]);
		 * the first AUDIO_FORMAT follows the 20-byte body. */
		nfmt = (uint16_t)pdu[18] | ((uint16_t)pdu[19] << 8);
		off = 24;
		for (i = 0; i < nfmt && off + 18 <= len; i++) {
			uint16_t tag = (uint16_t)pdu[off]
				| ((uint16_t)pdu[off + 1] << 8);
			uint16_t ch = (uint16_t)pdu[off + 2]
				| ((uint16_t)pdu[off + 3] << 8);
			uint32_t rate = (uint32_t)pdu[off + 4]
				| ((uint32_t)pdu[off + 5] << 8)
				| ((uint32_t)pdu[off + 6] << 16)
				| ((uint32_t)pdu[off + 7] << 24);
			uint16_t cbsize = (uint16_t)pdu[off + 16]
				| ((uint16_t)pdu[off + 17] << 8);
			if (tag == WAVE_FORMAT_ALAW && ch == 2
			    && rate == 44100)
				has_alaw = 1;
			off += 18 + cbsize;
		}

		st->client_format_count = nfmt;
		/* Default to PCM index 0 (byte-for-byte as before). */
		st->format_no = 0;
		st->chosen_tag = WAVE_FORMAT_PCM;
		st->chosen_rate = 44100;
		st->chosen_block_align = 4;
		if (prefer_wan && has_alaw) {
			st->format_no = 1;
			st->chosen_tag = WAVE_FORMAT_ALAW;
			st->chosen_block_align = 2;
		}
		st->negotiated = 1;
		rdp_info("rdpsnd: %u client formats; streaming %s",
			(unsigned)nfmt,
			st->chosen_tag == WAVE_FORMAT_ALAW ? "A-law" : "PCM");
		break;
	}
	case SNDC_TRAINING:
		/* Inbound Training Confirm (msgType 0x06). */
		rdp_debug("rdpsnd: training confirm");
		break;
	case SNDC_WAVECONFIRM:
		rdp_debug("rdpsnd: wave confirm");
		break;
	case SNDC_QUALITYMODE:
		rdp_debug("rdpsnd: quality mode");
		break;
	default:
		rdp_debug("rdpsnd: msg %u (len %zu)", (unsigned)msg_type, len);
		break;
	}
	return 0;
}
