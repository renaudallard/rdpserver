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
 * cliprdr_test.c -- CLIPRDR channel reassembly unit tests.
 *
 * Exercises rdp_cliprdr_reasm_feed, which stitches CHANNEL_FLAG_FIRST..
 * LAST fragments of a large clipboard PDU back together.  The fragment
 * lengths and the declared total are attacker-controlled, so the bounds
 * checks matter; build with ASan/UBSan to catch any over-read/leak.
 */

#include "../../src/channels/cliprdr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                              \
	(void)fprintf(stderr, "fail: " __VA_ARGS__);  \
	(void)fputc('\n', stderr);                    \
	exit(1);                                       \
} while (0)

#define FIRST CHANNEL_FLAG_FIRST
#define LAST  CHANNEL_FLAG_LAST

/* A single self-contained fragment is returned in place, no allocation. */
static void
test_single_fragment(void)
{
	struct rdp_cliprdr_reasm r;
	const uint8_t body[] = { 1, 2, 3, 4, 5 };
	const uint8_t *pdu = NULL;
	size_t pdu_len = 0;
	int rc;

	rdp_cliprdr_reasm_init(&r, 1024);
	rc = rdp_cliprdr_reasm_feed(&r, body, sizeof body, sizeof body,
		FIRST | LAST, &pdu, &pdu_len);
	if (rc != 1) FAIL("single: rc %d", rc);
	if (pdu != body) FAIL("single: not returned in place");
	if (pdu_len != sizeof body) FAIL("single: len %zu", pdu_len);
	if (r.buf != NULL) FAIL("single: allocated a buffer needlessly");
	rdp_cliprdr_reasm_reset(&r);
	printf("  single fragment: returned in place, no alloc ok\n");
}

/* FIRST + NEXT + LAST reassemble into one contiguous PDU. */
static void
test_three_fragments(void)
{
	struct rdp_cliprdr_reasm r;
	const uint8_t a[] = { 'A', 'A', 'A', 'A' };
	const uint8_t b[] = { 'B', 'B', 'B', 'B' };
	const uint8_t c[] = { 'C', 'C', 'C', 'C' };
	const uint8_t want[] = "AAAABBBBCCCC";
	const uint8_t *pdu = NULL;
	size_t pdu_len = 0;
	int rc;

	rdp_cliprdr_reasm_init(&r, 1024);
	rc = rdp_cliprdr_reasm_feed(&r, a, sizeof a, 12, FIRST,
		&pdu, &pdu_len);
	if (rc != 0) FAIL("three: FIRST rc %d", rc);
	rc = rdp_cliprdr_reasm_feed(&r, b, sizeof b, 12, 0, &pdu, &pdu_len);
	if (rc != 0) FAIL("three: NEXT rc %d", rc);
	rc = rdp_cliprdr_reasm_feed(&r, c, sizeof c, 12, LAST,
		&pdu, &pdu_len);
	if (rc != 1) FAIL("three: LAST rc %d", rc);
	if (pdu_len != 12) FAIL("three: len %zu", pdu_len);
	if (memcmp(pdu, want, 12) != 0) FAIL("three: content mismatch");
	rdp_cliprdr_reasm_reset(&r);
	printf("  three fragments: reassembled 12 bytes ok\n");
}

/* A declared total above max_pdu is refused before allocation. */
static void
test_oversize_total(void)
{
	struct rdp_cliprdr_reasm r;
	const uint8_t body[4] = { 0 };
	const uint8_t *pdu = NULL;
	size_t pdu_len = 0;
	int rc;

	rdp_cliprdr_reasm_init(&r, 64);
	rc = rdp_cliprdr_reasm_feed(&r, body, sizeof body, 1000000, FIRST,
		&pdu, &pdu_len);
	if (rc != -1) FAIL("oversize: rc %d", rc);
	if (r.buf != NULL) FAIL("oversize: buffer allocated");
	rdp_cliprdr_reasm_reset(&r);
	printf("  oversize total: refused, no alloc ok\n");
}

/* total == 0 is rejected. */
static void
test_zero_total(void)
{
	struct rdp_cliprdr_reasm r;
	const uint8_t body[1] = { 0 };
	const uint8_t *pdu = NULL;
	size_t pdu_len = 0;
	int rc;

	rdp_cliprdr_reasm_init(&r, 64);
	rc = rdp_cliprdr_reasm_feed(&r, body, 0, 0, FIRST, &pdu, &pdu_len);
	if (rc != -1) FAIL("zero total: rc %d", rc);
	rdp_cliprdr_reasm_reset(&r);
	printf("  zero total: rejected ok\n");
}

/* A NEXT/LAST fragment with no preceding FIRST is rejected. */
static void
test_orphan_continuation(void)
{
	struct rdp_cliprdr_reasm r;
	const uint8_t body[4] = { 0 };
	const uint8_t *pdu = NULL;
	size_t pdu_len = 0;
	int rc;

	rdp_cliprdr_reasm_init(&r, 64);
	rc = rdp_cliprdr_reasm_feed(&r, body, sizeof body, 8, LAST,
		&pdu, &pdu_len);
	if (rc != -1) FAIL("orphan: rc %d", rc);
	rdp_cliprdr_reasm_reset(&r);
	printf("  orphan continuation: rejected ok\n");
}

/* A fragment that overruns the declared total is refused and the
 * accumulator is reset (no over-write). */
static void
test_fragment_overrun(void)
{
	struct rdp_cliprdr_reasm r;
	const uint8_t a[2] = { 1, 2 };
	const uint8_t b[8] = { 0 };   /* 8 bytes into a 4-byte total */
	const uint8_t *pdu = NULL;
	size_t pdu_len = 0;
	int rc;

	rdp_cliprdr_reasm_init(&r, 64);
	rc = rdp_cliprdr_reasm_feed(&r, a, sizeof a, 4, FIRST,
		&pdu, &pdu_len);
	if (rc != 0) FAIL("overrun: FIRST rc %d", rc);
	rc = rdp_cliprdr_reasm_feed(&r, b, sizeof b, 4, LAST,
		&pdu, &pdu_len);
	if (rc != -1) FAIL("overrun: LAST rc %d", rc);
	if (r.buf != NULL) FAIL("overrun: not reset");
	rdp_cliprdr_reasm_reset(&r);
	printf("  fragment overrun: refused and reset ok\n");
}

/* After an aborted multi-fragment stream, a fresh FIRST works and leaves
 * no leak (under LSan). */
static void
test_recover_after_abort(void)
{
	struct rdp_cliprdr_reasm r;
	const uint8_t a[4] = { 0 };
	const uint8_t b[3] = { 7, 8, 9 };
	const uint8_t *pdu = NULL;
	size_t pdu_len = 0;
	int rc;

	rdp_cliprdr_reasm_init(&r, 64);
	/* Start a multi-fragment PDU but never finish it. */
	rc = rdp_cliprdr_reasm_feed(&r, a, sizeof a, 16, FIRST,
		&pdu, &pdu_len);
	if (rc != 0) FAIL("recover: first FIRST rc %d", rc);
	/* A new FIRST resets the prior partial (frees it) and starts over. */
	rc = rdp_cliprdr_reasm_feed(&r, b, sizeof b, 3, FIRST | LAST,
		&pdu, &pdu_len);
	if (rc != 1) FAIL("recover: restart rc %d", rc);
	if (pdu_len != 3 || memcmp(pdu, b, 3) != 0)
		FAIL("recover: wrong restart content");
	rdp_cliprdr_reasm_reset(&r);
	printf("  recover after abort: clean restart, no leak ok\n");
}

/* Exact-fit two-fragment PDU stresses the cap arithmetic boundary. */
static void
test_exact_fill(void)
{
	struct rdp_cliprdr_reasm r;
	uint8_t a[32], b[32];
	const uint8_t *pdu = NULL;
	size_t pdu_len = 0;
	size_t i;
	int rc;

	for (i = 0; i < 32; i++) { a[i] = (uint8_t)i; b[i] = (uint8_t)(i + 32); }
	rdp_cliprdr_reasm_init(&r, 64);
	rc = rdp_cliprdr_reasm_feed(&r, a, 32, 64, FIRST, &pdu, &pdu_len);
	if (rc != 0) FAIL("exact: FIRST rc %d", rc);
	rc = rdp_cliprdr_reasm_feed(&r, b, 32, 64, LAST, &pdu, &pdu_len);
	if (rc != 1) FAIL("exact: LAST rc %d", rc);
	if (pdu_len != 64) FAIL("exact: len %zu", pdu_len);
	for (i = 0; i < 64; i++)
		if (pdu[i] != (uint8_t)i) FAIL("exact: byte %zu", i);
	rdp_cliprdr_reasm_reset(&r);
	printf("  exact fill: 32+32 = 64 bytes, boundary ok\n");
}

/* A format list with text, the named HTML format, and an image round-trips
 * through build then parse, in both naming modes. */
static void
test_format_list_roundtrip(void)
{
	uint8_t buf[256];
	struct rdp_clip_fmt fmts[3] = {
		{ CF_UNICODETEXT, NULL },
		{ CB_FMT_HTML_ID, CB_FMT_NAME_HTML },
		{ CF_DIB, NULL },
	};
	struct rdp_cliprdr_formats p;
	ssize_t n;

	n = rdp_cliprdr_build_format_list(buf, sizeof buf, 1, fmts, 3);
	if (n < 8) FAIL("build long n=%lld", (long long)n);
	rdp_cliprdr_parse_format_list(buf + 8, (size_t)n - 8, 1, &p);
	if (!p.has_unicode_text) FAIL("long: missing unicode text");
	if (!p.has_html || p.html_id != CB_FMT_HTML_ID)
		FAIL("long: html id %u", p.html_id);
	if (!p.has_dib || p.dib_id != CF_DIB) FAIL("long: missing dib");
	printf("  format list long-names: text+html+dib round-trip ok\n");

	n = rdp_cliprdr_build_format_list(buf, sizeof buf, 0, fmts, 3);
	if (n < 8) FAIL("build short n=%lld", (long long)n);
	rdp_cliprdr_parse_format_list(buf + 8, (size_t)n - 8, 0, &p);
	if (!p.has_unicode_text || !p.has_html
	    || p.html_id != CB_FMT_HTML_ID || !p.has_dib)
		FAIL("short: round-trip incomplete");
	printf("  format list short-names: text+html+dib round-trip ok\n");
}

/* The CF_HTML envelope preserves the fragment bytes exactly. */
static void
test_html_roundtrip(void)
{
	uint8_t buf[512];
	const char *html = "<b>hi &amp; bye</b>";
	size_t hl = strlen(html), fo = 0, fl = 0;
	ssize_t n;

	n = rdp_cliprdr_html_wrap(buf, sizeof buf, (const uint8_t *)html, hl);
	if (n < 0) FAIL("html wrap");
	if (rdp_cliprdr_html_unwrap(buf, (size_t)n, &fo, &fl) != 0)
		FAIL("html unwrap");
	if (fl != hl || memcmp(buf + fo, html, hl) != 0)
		FAIL("html fragment mismatch (fl=%zu hl=%zu)", fl, hl);
	printf("  html wrap/unwrap: fragment preserved ok\n");
}

/* unwrap falls back to the comment markers, and passes raw HTML through. */
static void
test_html_unwrap_fallback(void)
{
	const char *marked =
		"x<!--StartFragment-->HELLO<!--EndFragment-->y";
	const char *plain = "just plain html";
	size_t fo = 0, fl = 0;

	rdp_cliprdr_html_unwrap((const uint8_t *)marked, strlen(marked),
		&fo, &fl);
	if (fl != 5 || memcmp(marked + fo, "HELLO", 5) != 0)
		FAIL("html fallback markers (fl=%zu)", fl);
	rdp_cliprdr_html_unwrap((const uint8_t *)plain, strlen(plain),
		&fo, &fl);
	if (fo != 0 || fl != strlen(plain))
		FAIL("html no-envelope passthrough (fo=%zu fl=%zu)", fo, fl);
	printf("  html unwrap fallback: markers + passthrough ok\n");
}

static void put_le16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put_le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static uint32_t get_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
		| ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* A 24bpp DIB gains a 14-byte BITMAPFILEHEADER and round-trips back. */
static void
test_dib_bmp_roundtrip(void)
{
	uint8_t dib[56];
	uint8_t bmp[128];
	size_t i, doff = 0, dl = 0;
	ssize_t bl;

	memset(dib, 0, sizeof dib);
	put_le32(dib + 0, 40);      /* biSize = BITMAPINFOHEADER */
	put_le32(dib + 4, 2);       /* biWidth */
	put_le32(dib + 8, 2);       /* biHeight */
	put_le16(dib + 12, 1);      /* biPlanes */
	put_le16(dib + 14, 24);     /* biBitCount (no palette) */
	for (i = 40; i < sizeof dib; i++)
		dib[i] = (uint8_t)i;

	bl = rdp_cliprdr_dib_to_bmp(dib, sizeof dib, bmp, sizeof bmp);
	if (bl != (ssize_t)(14 + sizeof dib)) FAIL("dib_to_bmp len %lld",
		(long long)bl);
	if (bmp[0] != 'B' || bmp[1] != 'M') FAIL("bmp magic");
	if (get_le32(bmp + 2) != 14 + sizeof dib) FAIL("bfSize %u",
		get_le32(bmp + 2));
	if (get_le32(bmp + 10) != 14 + 40) FAIL("bfOffBits %u want 54",
		get_le32(bmp + 10));
	if (memcmp(bmp + 14, dib, sizeof dib) != 0) FAIL("dib not copied");

	if (rdp_cliprdr_bmp_to_dib(bmp, (size_t)bl, &doff, &dl) != 0)
		FAIL("bmp_to_dib");
	if (dl != sizeof dib || memcmp(bmp + doff, dib, sizeof dib) != 0)
		FAIL("dib round-trip mismatch (dl=%zu)", dl);
	printf("  dib<->bmp: 24bpp round-trip, bfOffBits=54 ok\n");
}

/* An 8bpp DIB places bfOffBits past the 256-entry palette. */
static void
test_dib_bmp_palette(void)
{
	uint8_t dib[40 + 256 * 4 + 4];
	uint8_t bmp[sizeof dib + 14];
	ssize_t bl;

	memset(dib, 0, sizeof dib);
	put_le32(dib + 0, 40);
	put_le16(dib + 14, 8);      /* 8bpp -> 256-colour palette */
	bl = rdp_cliprdr_dib_to_bmp(dib, sizeof dib, bmp, sizeof bmp);
	if (bl < 0) FAIL("palette dib_to_bmp");
	if (get_le32(bmp + 10) != 14 + 40 + 256 * 4)
		FAIL("palette bfOffBits %u want %u", get_le32(bmp + 10),
			14u + 40u + 256u * 4u);
	printf("  dib->bmp: 8bpp palette bfOffBits past 256 colours ok\n");
}

/* Malformed DIB/BMP inputs are refused, not over-read. */
static void
test_dib_bmp_bounds(void)
{
	uint8_t buf[64], out[128];
	size_t doff = 0, dl = 0;

	memset(buf, 0, sizeof buf);
	put_le32(buf, 1000);   /* biSize beyond the buffer */
	if (rdp_cliprdr_dib_to_bmp(buf, sizeof buf, out, sizeof out) != -1)
		FAIL("oversize biSize not refused");
	if (rdp_cliprdr_dib_to_bmp(buf, 2, out, sizeof out) != -1)
		FAIL("short dib not refused");
	put_le32(buf, 40);
	if (rdp_cliprdr_dib_to_bmp(buf, sizeof buf, out, 10) != -1)
		FAIL("small cap not refused");
	out[0] = 'X'; out[1] = 'Y';
	if (rdp_cliprdr_bmp_to_dib(out, 64, &doff, &dl) != -1)
		FAIL("non-BM accepted");
	out[0] = 'B'; out[1] = 'M';
	if (rdp_cliprdr_bmp_to_dib(out, 14, &doff, &dl) != -1)
		FAIL("header-only bmp accepted");
	printf("  dib/bmp bounds: oversize/short/small-cap/non-BM refused ok\n");
}

/* A length that would overflow the offset arithmetic, or simply not fit,
 * must be refused before any copy. */
static void
test_html_wrap_overflow(void)
{
	uint8_t buf[256];
	ssize_t n;

	n = rdp_cliprdr_html_wrap(buf, sizeof buf, (const uint8_t *)"x",
		(size_t)-8);
	if (n != -1) FAIL("html wrap overflow not refused (n=%lld)",
		(long long)n);
	n = rdp_cliprdr_html_wrap(buf, sizeof buf, (const uint8_t *)"x", 1024);
	if (n != -1) FAIL("html wrap oversize not refused");
	printf("  html wrap overflow/oversize: refused ok\n");
}

int
main(void)
{
	test_single_fragment();
	test_three_fragments();
	test_oversize_total();
	test_zero_total();
	test_orphan_continuation();
	test_fragment_overrun();
	test_recover_after_abort();
	test_exact_fill();
	test_format_list_roundtrip();
	test_html_roundtrip();
	test_html_unwrap_fallback();
	test_html_wrap_overflow();
	test_dib_bmp_roundtrip();
	test_dib_bmp_palette();
	test_dib_bmp_bounds();
	printf("cliprdr_test: all ok\n");
	return 0;
}
