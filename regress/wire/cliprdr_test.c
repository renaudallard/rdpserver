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
	printf("cliprdr_test: all ok\n");
	return 0;
}
