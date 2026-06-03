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
 * sndin_test.c -- MS-RDPEAI (audio input) PDU build/parse and state machine.
 *
 * Drives rdp_sndin_handle through the full negotiation: a client Version
 * yields a Formats PDU; client Formats yields an Open PDU; an Open Reply
 * S_OK moves to STREAMING; a Data PDU returns the audio bytes.  Also feeds
 * truncated and oversize PDUs to confirm the bounds checks never over-read
 * (build with ASan/UBSan via $(TEST_SAN)).
 */

#include "../../src/channels/sndin.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                              \
	(void)fprintf(stderr, "fail: " __VA_ARGS__);  \
	(void)fputc('\n', stderr);                    \
	exit(1);                                       \
} while (0)

static uint32_t
ld32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
		| ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t
ld16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* The server builders emit the documented byte layouts. */
static void
test_builders(void)
{
	uint8_t buf[128];
	ssize_t n;

	n = rdp_sndin_build_version(buf, sizeof buf);
	if (n != 5) FAIL("version len %zd", n);
	if (buf[0] != SNDIN_MSG_VERSION) FAIL("version msgid %u", buf[0]);
	if (ld32(buf + 1) != SNDIN_VERSION) FAIL("version value %u",
		ld32(buf + 1));

	n = rdp_sndin_build_formats(buf, sizeof buf);
	/* 1 (msgid) + 4 (NumFormats) + 4 (cbSize) + 18 (one PCM format). */
	if (n != 27) FAIL("formats len %zd", n);
	if (buf[0] != SNDIN_MSG_FORMATS) FAIL("formats msgid %u", buf[0]);
	if (ld32(buf + 1) != 1) FAIL("formats NumFormats %u", ld32(buf + 1));
	if (ld32(buf + 5) != 26) FAIL("formats cbSize %u", ld32(buf + 5));
	/* WAVEFORMATEX: PCM 16-bit stereo 44100 Hz, cbSize 0. */
	if (ld16(buf + 9) != 0x0001) FAIL("formats tag %u", ld16(buf + 9));
	if (ld16(buf + 11) != 2) FAIL("formats channels %u", ld16(buf + 11));
	if (ld32(buf + 13) != 44100) FAIL("formats rate %u", ld32(buf + 13));
	if (ld32(buf + 17) != 176400) FAIL("formats avg %u", ld32(buf + 17));
	if (ld16(buf + 21) != 4) FAIL("formats blockalign %u", ld16(buf + 21));
	if (ld16(buf + 23) != 16) FAIL("formats bits %u", ld16(buf + 23));
	if (ld16(buf + 25) != 0) FAIL("formats cbSize16 %u", ld16(buf + 25));

	n = rdp_sndin_build_open(buf, sizeof buf, 0, 0);
	/* 1 + 4 (FramesPerPacket) + 4 (initialFormat) + 18 (WAVEFORMATEX). */
	if (n != 27) FAIL("open len %zd", n);
	if (buf[0] != SNDIN_MSG_OPEN) FAIL("open msgid %u", buf[0]);
	if (ld32(buf + 1) != 0) FAIL("open frames %u", ld32(buf + 1));
	if (ld32(buf + 5) != 0) FAIL("open initfmt %u", ld32(buf + 5));
	if (ld16(buf + 9) != 0x0001) FAIL("open tag %u", ld16(buf + 9));

	/* A too-small output buffer is a clean refusal, never a write past. */
	if (rdp_sndin_build_version(buf, 4) != -1) FAIL("version no bound");
	if (rdp_sndin_build_formats(buf, 10) != -1) FAIL("formats no bound");
	if (rdp_sndin_build_open(buf, 20, 0, 0) != -1) FAIL("open no bound");

	printf("  builders: version/formats/open layouts ok\n");
}

/* The full negotiation walks INIT.. through STREAMING, emitting the right
 * server PDU at each client message. */
static void
test_state_machine(void)
{
	struct sndin_state st;
	uint8_t out[64];
	size_t out_len;
	const uint8_t *aud;
	size_t aud_len;
	int rc;

	rdp_sndin_init(&st);
	if (st.phase != SNDIN_INIT) FAIL("init phase %d", st.phase);

	/* Client Version -> server emits Formats. */
	{
		uint8_t ver[5] = { SNDIN_MSG_VERSION, 1, 0, 0, 0 };
		out_len = 99; aud = (void *)1; aud_len = 99;
		rc = rdp_sndin_handle(&st, ver, sizeof ver,
			out, sizeof out, &out_len, &aud, &aud_len);
		if (rc != SNDIN_MSG_VERSION) FAIL("ver rc %d", rc);
		if (out_len == 0 || out[0] != SNDIN_MSG_FORMATS)
			FAIL("ver did not emit Formats (len %zu)", out_len);
		if (st.phase != SNDIN_FORMATS_SENT)
			FAIL("ver phase %d", st.phase);
		if (aud != NULL || aud_len != 0)
			FAIL("ver set audio out");
	}

	/* Client Formats (one echoed PCM format) -> server emits Open. */
	{
		uint8_t fmts[1 + 8 + 18];
		size_t i = 0;
		fmts[i++] = SNDIN_MSG_FORMATS;
		fmts[i++] = 1; fmts[i++] = 0; fmts[i++] = 0; fmts[i++] = 0; /* NumFormats=1 */
		fmts[i++] = 26; fmts[i++] = 0; fmts[i++] = 0; fmts[i++] = 0; /* cbSize */
		/* WAVEFORMATEX PCM stereo 44100, cbSize 0 (18 bytes). */
		memset(fmts + i, 0, 18);
		fmts[i + 0] = 0x01;                /* wFormatTag */
		fmts[i + 2] = 2;                   /* nChannels */
		fmts[i + 4] = 0x44; fmts[i + 5] = 0xAC; /* 44100 */
		fmts[i + 14] = 16;                 /* wBitsPerSample low */
		i += 18;
		out_len = 0;
		rc = rdp_sndin_handle(&st, fmts, i,
			out, sizeof out, &out_len, &aud, &aud_len);
		if (rc != SNDIN_MSG_FORMATS) FAIL("fmts rc %d", rc);
		if (out_len == 0 || out[0] != SNDIN_MSG_OPEN)
			FAIL("fmts did not emit Open (len %zu)", out_len);
		if (st.phase != SNDIN_OPEN_SENT)
			FAIL("fmts phase %d", st.phase);
	}

	/* Open Reply S_OK -> STREAMING, no PDU emitted. */
	{
		uint8_t rep[5] = { SNDIN_MSG_OPEN_REPLY, 0, 0, 0, 0 };
		out_len = 0;
		rc = rdp_sndin_handle(&st, rep, sizeof rep,
			out, sizeof out, &out_len, &aud, &aud_len);
		if (rc != SNDIN_MSG_OPEN_REPLY) FAIL("reply rc %d", rc);
		if (out_len != 0) FAIL("reply emitted a PDU (len %zu)", out_len);
		if (st.phase != SNDIN_STREAMING) FAIL("reply phase %d", st.phase);
	}

	/* Data PDU -> the audio bytes after the MessageId are returned. */
	{
		uint8_t data[1 + 6] = { SNDIN_MSG_DATA,
			0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
		out_len = 0; aud = NULL; aud_len = 0;
		rc = rdp_sndin_handle(&st, data, sizeof data,
			out, sizeof out, &out_len, &aud, &aud_len);
		if (rc != SNDIN_MSG_DATA) FAIL("data rc %d", rc);
		if (out_len != 0) FAIL("data emitted a PDU");
		if (aud == NULL || aud_len != 6)
			FAIL("data audio len %zu", aud_len);
		if (aud != data + 1) FAIL("data audio not in place");
		if (memcmp(aud, data + 1, 6) != 0) FAIL("data audio bytes");
	}

	/* Data Incoming -> no audio, no PDU. */
	{
		uint8_t di[1] = { SNDIN_MSG_DATA_INCOMING };
		out_len = 0; aud = NULL; aud_len = 0;
		rc = rdp_sndin_handle(&st, di, sizeof di,
			out, sizeof out, &out_len, &aud, &aud_len);
		if (rc != SNDIN_MSG_DATA_INCOMING) FAIL("incoming rc %d", rc);
		if (out_len != 0 || aud != NULL) FAIL("incoming produced output");
	}

	printf("  state machine: VERSION->FORMATS->OPEN->STREAMING->DATA ok\n");
}

/* An Open Reply with a nonzero HRESULT does not enter STREAMING. */
static void
test_open_reply_failure(void)
{
	struct sndin_state st;
	uint8_t out[64];
	size_t out_len = 0;
	const uint8_t *aud = NULL;
	size_t aud_len = 0;
	uint8_t rep[5] = { SNDIN_MSG_OPEN_REPLY, 0x01, 0x00, 0x07, 0x80 };
	int rc;

	rdp_sndin_init(&st);
	st.phase = SNDIN_OPEN_SENT;
	rc = rdp_sndin_handle(&st, rep, sizeof rep,
		out, sizeof out, &out_len, &aud, &aud_len);
	if (rc != SNDIN_MSG_OPEN_REPLY) FAIL("fail reply rc %d", rc);
	if (st.phase == SNDIN_STREAMING) FAIL("entered STREAMING on failure");
	printf("  open reply failure: stays out of STREAMING ok\n");
}

/* Truncated and malformed PDUs are rejected without an over-read. */
static void
test_bounds(void)
{
	struct sndin_state st;
	uint8_t out[64];
	size_t out_len;
	const uint8_t *aud;
	size_t aud_len;

	/* Empty PDU. */
	rdp_sndin_init(&st);
	if (rdp_sndin_handle(&st, (const uint8_t *)"", 0,
		out, sizeof out, &out_len, &aud, &aud_len) != -1)
		FAIL("empty not rejected");

	/* Version with a truncated 4-byte field (only 2 present). */
	{
		uint8_t v[3] = { SNDIN_MSG_VERSION, 1, 0 };
		if (rdp_sndin_handle(&st, v, sizeof v,
			out, sizeof out, &out_len, &aud, &aud_len) != -1)
			FAIL("short version not rejected");
	}

	/* Open Reply truncated. */
	{
		uint8_t r[2] = { SNDIN_MSG_OPEN_REPLY, 0 };
		if (rdp_sndin_handle(&st, r, sizeof r,
			out, sizeof out, &out_len, &aud, &aud_len) != -1)
			FAIL("short open reply not rejected");
	}

	/* Formats claiming a format whose WAVEFORMATEX runs past the PDU. */
	{
		uint8_t f[1 + 8 + 4];
		size_t i = 0;
		f[i++] = SNDIN_MSG_FORMATS;
		f[i++] = 1; f[i++] = 0; f[i++] = 0; f[i++] = 0; /* NumFormats=1 */
		f[i++] = 0; f[i++] = 0; f[i++] = 0; f[i++] = 0; /* cbSize */
		f[i++] = 0; f[i++] = 0; f[i++] = 0; f[i++] = 0; /* only 4 of 18 */
		if (rdp_sndin_handle(&st, f, i,
			out, sizeof out, &out_len, &aud, &aud_len) != -1)
			FAIL("truncated formats not rejected");
	}

	/* Formats with an absurd NumFormats is rejected, no allocation walk. */
	{
		uint8_t f[1 + 8];
		size_t i = 0;
		f[i++] = SNDIN_MSG_FORMATS;
		f[i++] = 0xff; f[i++] = 0xff; f[i++] = 0xff; f[i++] = 0xff;
		f[i++] = 0; f[i++] = 0; f[i++] = 0; f[i++] = 0;
		if (rdp_sndin_handle(&st, f, i,
			out, sizeof out, &out_len, &aud, &aud_len) != -1)
			FAIL("huge NumFormats not rejected");
	}

	/* A Formats with cbSize extra bytes that fit is accepted (and walks
	 * past the variable region without reading beyond the PDU). */
	{
		uint8_t f[1 + 8 + 18 + 4];
		size_t i = 0;
		f[i++] = SNDIN_MSG_FORMATS;
		f[i++] = 1; f[i++] = 0; f[i++] = 0; f[i++] = 0; /* NumFormats=1 */
		f[i++] = 0; f[i++] = 0; f[i++] = 0; f[i++] = 0; /* cbSize */
		memset(f + i, 0, 18 + 4);
		f[i + 0] = 0x01;        /* wFormatTag PCM */
		f[i + 16] = 4;          /* cbSize = 4 extra bytes */
		f[i + 17] = 0;
		i += 18 + 4;
		out_len = 0;
		if (rdp_sndin_handle(&st, f, i,
			out, sizeof out, &out_len, &aud, &aud_len)
			!= SNDIN_MSG_FORMATS)
			FAIL("valid cbSize formats rejected");
		if (out_len == 0 || out[0] != SNDIN_MSG_OPEN)
			FAIL("cbSize formats did not emit Open");
	}

	/* Data with no payload after the MessageId returns no audio. */
	{
		uint8_t d[1] = { SNDIN_MSG_DATA };
		aud = (const uint8_t *)1; aud_len = 99;
		if (rdp_sndin_handle(&st, d, sizeof d,
			out, sizeof out, &out_len, &aud, &aud_len)
			!= SNDIN_MSG_DATA)
			FAIL("empty data rejected");
		if (aud != NULL || aud_len != 0) FAIL("empty data set audio");
	}

	printf("  bounds: truncated/oversize PDUs rejected, no over-read ok\n");
}

int
main(void)
{
	printf("sndin_test:\n");
	test_builders();
	test_state_machine();
	test_open_reply_failure();
	test_bounds();
	printf("sndin_test: all ok\n");
	return 0;
}
