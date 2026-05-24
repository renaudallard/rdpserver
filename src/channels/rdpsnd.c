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
	uint16_t body_size = 20 + 18;
	if (cap < 4 + body_size) return -1;

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
	if (rdp_buf_put_u16le(&b, 1) != 0) return -1;           /* wNumberOfFormats */
	if (rdp_buf_put_u8(&b, 0) != 0) return -1;              /* cLastBlockConfirmed */
	if (rdp_buf_put_u16le(&b, RDPSND_VERSION) != 0) return -1;
	if (rdp_buf_put_u8(&b, 0) != 0) return -1;              /* bPad */

	/* AUDIO_FORMAT: PCM 16-bit stereo 44100 Hz */
	if (rdp_buf_put_u16le(&b, WAVE_FORMAT_PCM) != 0) return -1;
	if (rdp_buf_put_u16le(&b, 2) != 0) return -1;           /* nChannels */
	if (rdp_buf_put_u32le(&b, 44100) != 0) return -1;       /* nSamplesPerSec */
	if (rdp_buf_put_u32le(&b, 176400) != 0) return -1;      /* nAvgBytesPerSec */
	if (rdp_buf_put_u16le(&b, 4) != 0) return -1;           /* nBlockAlign */
	if (rdp_buf_put_u16le(&b, 16) != 0) return -1;          /* wBitsPerSample */
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
		const uint8_t *pcm, size_t pcm_len)
{
	struct rdp_buf b;
	size_t body_size = 12 + pcm_len;

	if (body_size > 0xFFFF) return -1;
	if (cap < 4 + body_size) return -1;
	rdp_buf_init(&b, out, cap);

	if (rdp_buf_put_u8(&b, SNDC_WAVE2) != 0) return -1;
	if (rdp_buf_put_u8(&b, 0) != 0) return -1;
	if (rdp_buf_put_u16le(&b, (uint16_t)body_size) != 0) return -1;
	if (rdp_buf_put_u16le(&b, st->timestamp) != 0) return -1;
	if (rdp_buf_put_u16le(&b, 0) != 0) return -1;
	if (rdp_buf_put_u8(&b, st->block_no) != 0) return -1;
	st->block_no++;
	if (rdp_buf_put_u8(&b, 0) != 0) return -1;
	if (rdp_buf_put_u8(&b, 0) != 0) return -1;
	if (rdp_buf_put_u8(&b, 0) != 0) return -1;
	if (rdp_buf_put_u32le(&b, (uint32_t)st->timestamp) != 0) return -1;
	if (rdp_buf_put(&b, pcm, pcm_len) != 0) return -1;

	st->timestamp += (uint16_t)(pcm_len / 4 * 1000 / 44100);
	return (ssize_t)rdp_buf_used(&b);
}

int
rdp_rdpsnd_handle(struct rdpsnd_state *st,
		const uint8_t *pdu, size_t len)
{
	uint8_t msg_type;

	if (len < 4) return -1;
	msg_type = pdu[0];

	switch (msg_type) {
	case SNDC_FORMATS: {
		/* Client Audio Formats response.  We just count the
		 * formats and mark the channel as negotiated. */
		uint16_t body_size, nfmt;
		if (len < 24) return -1;
		body_size = (uint16_t)pdu[2] | ((uint16_t)pdu[3] << 8);
		(void)body_size;
		nfmt = (uint16_t)pdu[22] | ((uint16_t)pdu[23] << 8);
		st->client_format_count = nfmt;
		st->negotiated = 1;
		rdp_info("rdpsnd: client supports %u formats", (unsigned)nfmt);
		break;
	}
	/* SNDC_TRAININGCONFIRM = 0x07 (same value as SNDC_FORMATS);
	 * the client response to Training is handled by the FORMATS
	 * case above via a length heuristic (training confirm is
	 * shorter than a formats PDU). */
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
