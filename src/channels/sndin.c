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
 * sndin.c -- MS-RDPEAI audio input (microphone) negotiation and parse.
 */

#include "sndin.h"

#include "../include/rdp_log.h"
#include "../common/buf.h"

/* The single PCM format we offer and capture: 16-bit LE stereo 44100 Hz.
 * This mirrors the WAVEFORMATEX RDPSND advertises for audio output. */
#define SNDIN_PCM_CHANNELS     2
#define SNDIN_PCM_RATE         44100u
#define SNDIN_PCM_BITS         16
#define SNDIN_PCM_BLOCK_ALIGN  4       /* nChannels * wBitsPerSample / 8 */
#define SNDIN_PCM_AVG_BYTES    176400u /* nSamplesPerSec * nBlockAlign */

void
rdp_sndin_init(struct sndin_state *st)
{
	st->phase = SNDIN_INIT;
	st->nChannels = SNDIN_PCM_CHANNELS;
	st->nSamplesPerSec = SNDIN_PCM_RATE;
	st->wBitsPerSample = SNDIN_PCM_BITS;
	st->nBlockAlign = SNDIN_PCM_BLOCK_ALIGN;
}

/* Append one PCM WAVEFORMATEX (18 bytes, cbSize=0) to a buffer. */
static int
put_pcm_format(struct rdp_buf *b)
{
	if (rdp_buf_put_u16le(b, SNDIN_WAVE_FORMAT_PCM) != 0) return -1;
	if (rdp_buf_put_u16le(b, SNDIN_PCM_CHANNELS) != 0) return -1;
	if (rdp_buf_put_u32le(b, SNDIN_PCM_RATE) != 0) return -1;
	if (rdp_buf_put_u32le(b, SNDIN_PCM_AVG_BYTES) != 0) return -1;
	if (rdp_buf_put_u16le(b, SNDIN_PCM_BLOCK_ALIGN) != 0) return -1;
	if (rdp_buf_put_u16le(b, SNDIN_PCM_BITS) != 0) return -1;
	if (rdp_buf_put_u16le(b, 0) != 0) return -1;          /* cbSize */
	return 0;
}

ssize_t
rdp_sndin_build_version(uint8_t *out, size_t cap)
{
	struct rdp_buf b;

	if (cap < 5) return -1;
	rdp_buf_init(&b, out, cap);
	if (rdp_buf_put_u8(&b, SNDIN_MSG_VERSION) != 0) return -1;
	if (rdp_buf_put_u32le(&b, SNDIN_VERSION) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_sndin_build_formats(uint8_t *out, size_t cap)
{
	struct rdp_buf b;
	/* One AUDIO_FORMAT of 18 bytes (PCM, cbSize=0).  cbSizeFormatsPacket
	 * is the count of bytes from NumFormats through the format array, i.e.
	 * 4 (NumFormats) + 4 (cbSizeFormatsPacket) + 18 (format). */
	uint32_t fmt_bytes = 18;
	uint32_t cb_size = 4 + 4 + fmt_bytes;

	if (cap < (size_t)1 + cb_size) return -1;
	rdp_buf_init(&b, out, cap);
	if (rdp_buf_put_u8(&b, SNDIN_MSG_FORMATS) != 0) return -1;
	if (rdp_buf_put_u32le(&b, 1) != 0) return -1;          /* NumFormats */
	if (rdp_buf_put_u32le(&b, cb_size) != 0) return -1;    /* cbSizeFormatsPacket */
	if (put_pcm_format(&b) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_sndin_build_open(uint8_t *out, size_t cap,
		uint32_t frames_per_packet, uint32_t initial_format)
{
	struct rdp_buf b;

	/* MessageId(1) + FramesPerPacket(4) + initialFormat(4) + WAVEFORMATEX(18). */
	if (cap < 9 + 18) return -1;
	rdp_buf_init(&b, out, cap);
	if (rdp_buf_put_u8(&b, SNDIN_MSG_OPEN) != 0) return -1;
	if (rdp_buf_put_u32le(&b, frames_per_packet) != 0) return -1;
	if (rdp_buf_put_u32le(&b, initial_format) != 0) return -1;
	if (put_pcm_format(&b) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

/* Validate that a Formats PDU body (after the MessageId) is well formed:
 * the declared NumFormats AUDIO_FORMAT records, each WAVEFORMATEX of
 * 18 + cbSize bytes, must all lie within the PDU.  Returns 0 if sane,
 * -1 on any truncation/overflow.  We only need that the client returned
 * a non-empty, parseable list; we do not pick among the formats because
 * we offered exactly one. */
static int
validate_formats(const uint8_t *body, size_t body_len)
{
	struct rdp_buf b;
	uint32_t num_formats, cb_size, i;

	rdp_buf_init(&b, (uint8_t *)(uintptr_t)body, body_len);
	if (rdp_buf_get_u32le(&b, &num_formats) != 0) return -1;
	if (rdp_buf_get_u32le(&b, &cb_size) != 0) return -1;
	(void)cb_size;   /* advisory; we bound on the array walk below */
	if (num_formats == 0 || num_formats > 256) return -1;
	for (i = 0; i < num_formats; i++) {
		uint16_t cbsize16;
		/* Skip wFormatTag(2) nChannels(2) nSamplesPerSec(4)
		 * nAvgBytesPerSec(4) nBlockAlign(2) wBitsPerSample(2). */
		if (rdp_buf_skip(&b, 16) != 0) return -1;
		if (rdp_buf_get_u16le(&b, &cbsize16) != 0) return -1;
		if (rdp_buf_skip(&b, cbsize16) != 0) return -1;
	}
	return 0;
}

int
rdp_sndin_handle(struct sndin_state *st,
		const uint8_t *in, size_t in_len,
		uint8_t *out, size_t out_cap, size_t *out_len,
		const uint8_t **audio_out, size_t *audio_len)
{
	uint8_t msg;

	*out_len = 0;
	if (audio_out) *audio_out = NULL;
	if (audio_len) *audio_len = 0;

	if (in_len < 1) return -1;
	msg = in[0];

	switch (msg) {
	case SNDIN_MSG_VERSION: {
		struct rdp_buf b;
		uint32_t client_ver = 0;
		/* Client Version reply: MessageId(1) + Version(4). */
		rdp_buf_init(&b, (uint8_t *)(uintptr_t)in, in_len);
		if (rdp_buf_skip(&b, 1) != 0) return -1;
		if (rdp_buf_get_u32le(&b, &client_ver) != 0) return -1;
		rdp_info("sndin: client version %u", (unsigned)client_ver);
		/* Advance: emit Formats. */
		{
			ssize_t fn = rdp_sndin_build_formats(out, out_cap);
			if (fn > 0) {
				*out_len = (size_t)fn;
				st->phase = SNDIN_FORMATS_SENT;
			}
		}
		return SNDIN_MSG_VERSION;
	}

	case SNDIN_MSG_FORMATS: {
		/* Client Formats reply: body after the MessageId byte. */
		if (validate_formats(in + 1, in_len - 1) != 0) return -1;
		rdp_info("sndin: client formats accepted; opening capture");
		{
			/* FramesPerPacket: a small capture buffer; 0 lets the
			 * client choose.  We select client format index 0,
			 * which is the PCM format we offered (we sent one). */
			ssize_t on = rdp_sndin_build_open(out, out_cap, 0, 0);
			if (on > 0) {
				*out_len = (size_t)on;
				st->phase = SNDIN_OPEN_SENT;
			}
		}
		return SNDIN_MSG_FORMATS;
	}

	case SNDIN_MSG_OPEN_REPLY: {
		struct rdp_buf b;
		uint32_t result = 0;
		/* MessageId(1) + Result(4, HRESULT). */
		rdp_buf_init(&b, (uint8_t *)(uintptr_t)in, in_len);
		if (rdp_buf_skip(&b, 1) != 0) return -1;
		if (rdp_buf_get_u32le(&b, &result) != 0) return -1;
		if (result == 0) {
			st->phase = SNDIN_STREAMING;
			rdp_info("sndin: capture open, streaming microphone");
		} else {
			rdp_warn("sndin: open failed (HRESULT 0x%08x)",
				(unsigned)result);
		}
		return SNDIN_MSG_OPEN_REPLY;
	}

	case SNDIN_MSG_DATA_INCOMING:
		/* Announces that a Data PDU follows; nothing to emit. */
		return SNDIN_MSG_DATA_INCOMING;

	case SNDIN_MSG_DATA:
		/* Audio payload follows the MessageId byte.  Hand the bytes
		 * to the caller; they are valid only until the next call. */
		if (audio_out && audio_len && in_len > 1) {
			*audio_out = in + 1;
			*audio_len = in_len - 1;
		}
		return SNDIN_MSG_DATA;

	case SNDIN_MSG_FORMATCHANGE: {
		struct rdp_buf b;
		uint32_t new_fmt = 0;
		rdp_buf_init(&b, (uint8_t *)(uintptr_t)in, in_len);
		if (rdp_buf_skip(&b, 1) != 0) return -1;
		if (rdp_buf_get_u32le(&b, &new_fmt) != 0) return -1;
		rdp_debug("sndin: format change to %u", (unsigned)new_fmt);
		return SNDIN_MSG_FORMATCHANGE;
	}

	default:
		rdp_debug("sndin: unknown msg %u (len %zu)",
			(unsigned)msg, in_len);
		return -1;
	}
}
