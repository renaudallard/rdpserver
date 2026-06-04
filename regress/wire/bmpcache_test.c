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
 * bmpcache_test.c -- Bitmap Cache Persistent List PDU parser.
 */

#include "../../src/wire/bmpcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                                \
	(void)fprintf(stderr, "fail: " __VA_ARGS__);  \
	(void)fputc('\n', stderr);                    \
	exit(1);                                       \
} while (0)

static void
put64le(uint8_t *p, uint64_t v)
{
	int i;
	for (i = 0; i < 8; i++)
		p[i] = (uint8_t)((v >> (i * 8)) & 0xFF);
}

/* Build a persistent-list PDU body with `count` keys in cache 0. */
static size_t
build(uint8_t *out, const uint64_t *keys, uint16_t count, uint8_t mask)
{
	size_t i;
	memset(out, 0, 24);
	out[0] = (uint8_t)(count & 0xFF);          /* numEntriesCache0 */
	out[1] = (uint8_t)((count >> 8) & 0xFF);
	out[10] = (uint8_t)(count & 0xFF);         /* totalEntriesCache0 */
	out[11] = (uint8_t)((count >> 8) & 0xFF);
	out[20] = mask;                            /* bBitMask */
	for (i = 0; i < count; i++)
		put64le(out + 24 + i * 8, keys[i]);
	return 24 + (size_t)count * 8;
}

static void test_manager(void);

int
main(void)
{
	uint8_t buf[256];
	uint64_t keys[8];
	uint64_t got[8];
	size_t n, blen;
	int first = 0, last = 0;

	keys[0] = 0x1122334455667788ULL;
	keys[1] = 0xAABBCCDDEEFF0011ULL;

	/* Two keys, FIRST|LAST. */
	blen = build(buf, keys, 2, RDP_PERSIST_FIRST_PDU | RDP_PERSIST_LAST_PDU);
	if (rdp_bmpcache_parse_persistent_list(buf, blen, got, 8, &n,
	    &first, &last) != 0) FAIL("parse");
	if (n != 2) FAIL("n=%zu", n);
	if (got[0] != keys[0] || got[1] != keys[1]) FAIL("keys");
	if (!first || !last) FAIL("flags");

	/* Count-only query (keys == NULL). */
	if (rdp_bmpcache_parse_persistent_list(buf, blen, NULL, 0, &n,
	    NULL, NULL) != 0) FAIL("count parse");
	if (n != 2) FAIL("count n=%zu", n);

	/* A small output buffer stores only what fits. */
	if (rdp_bmpcache_parse_persistent_list(buf, blen, got, 1, &n,
	    NULL, NULL) != 0) FAIL("capped parse");
	if (n != 1 || got[0] != keys[0]) FAIL("capped");

	/* A header that claims more keys than the body holds is rejected. */
	{
		uint8_t bad[64];
		memset(bad, 0, sizeof bad);
		bad[0] = 4;            /* numEntriesCache0 = 4 */
		/* body only 24 + 1*8 = 32 bytes -> 1 key present, 4 claimed */
		if (rdp_bmpcache_parse_persistent_list(bad, 32, got, 8, &n,
		    NULL, NULL) != -1) FAIL("overrun accepted");
	}

	/* A header shorter than 24 bytes is rejected. */
	if (rdp_bmpcache_parse_persistent_list(buf, 23, got, 8, &n,
	    NULL, NULL) != -1) FAIL("short header accepted");

	/* An empty list (zero keys) parses cleanly. */
	blen = build(buf, keys, 0, RDP_PERSIST_FIRST_PDU);
	if (rdp_bmpcache_parse_persistent_list(buf, blen, got, 8, &n,
	    &first, &last) != 0) FAIL("empty parse");
	if (n != 0 || !first || last) FAIL("empty fields");

	test_manager();
	(void)printf("bmpcache_test: all ok\n");
	return 0;
}

static void
test_manager(void)
{
	struct rdp_bmpcache *c;
	uint8_t buf[256];
	uint64_t keys[2];
	uint8_t pix_a[64], pix_b[64];
	uint8_t id;
	uint16_t idx;
	uint64_t ka, kb;
	size_t i;
	size_t blen;

	memset(pix_a, 0x11, sizeof pix_a);
	memset(pix_b, 0x22, sizeof pix_b);

	/* The key is deterministic and distinguishes different tiles. */
	ka = rdp_bmpcache_key(pix_a, sizeof pix_a);
	kb = rdp_bmpcache_key(pix_b, sizeof pix_b);
	if (ka != rdp_bmpcache_key(pix_a, sizeof pix_a)) FAIL("key nondeterministic");
	if (ka == kb) FAIL("key collision on distinct tiles");

	c = rdp_bmpcache_create();
	if (c == NULL) FAIL("create");

	/* First lookup of a key misses and allocates; the second hits the same
	 * slot. */
	if (rdp_bmpcache_lookup(c, ka, &id, &idx) != 0) FAIL("first miss");
	{
		uint8_t id2; uint16_t idx2;
		if (rdp_bmpcache_lookup(c, ka, &id2, &idx2) != 1) FAIL("second hit");
		if (id2 != id || idx2 != idx) FAIL("hit slot moved");
	}
	/* A different key gets a different slot. */
	{
		uint8_t idb; uint16_t idxb;
		if (rdp_bmpcache_lookup(c, kb, &idb, &idxb) != 0) FAIL("kb miss");
		if (idb == id && idxb == idx) FAIL("kb reused ka slot");
	}

	/* Eviction: after enough distinct misses the oldest key is evicted, so a
	 * fresh lookup of it misses again. */
	for (i = 0; i < 600; i++) {
		uint8_t xid; uint16_t xidx;
		(void)rdp_bmpcache_lookup(c, 0x1000000ULL + i, &xid, &xidx);
	}
	if (rdp_bmpcache_lookup(c, ka, &id, &idx) != 0) FAIL("ka not evicted");
	rdp_bmpcache_destroy(c);

	/* Persistent ingest places cache-0 keys at slots (0,0) and (0,1). */
	c = rdp_bmpcache_create();
	keys[0] = 0xDEADBEEF00000001ULL;
	keys[1] = 0xDEADBEEF00000002ULL;
	blen = build(buf, keys, 2,
	    RDP_PERSIST_FIRST_PDU | RDP_PERSIST_LAST_PDU);
	if (rdp_bmpcache_ingest_persistent(c, buf, blen) != 0) FAIL("ingest");
	if (rdp_bmpcache_lookup(c, keys[0], &id, &idx) != 1
	    || id != 0 || idx != 0) FAIL("persistent slot 0");
	if (rdp_bmpcache_lookup(c, keys[1], &id, &idx) != 1
	    || id != 0 || idx != 1) FAIL("persistent slot 1");
	rdp_bmpcache_destroy(c);

	/* Persistent keys must not be evicted while the cache still has empty
	 * slots: a miss prefers a free slot, so the client keeps recalling its
	 * disk-cached tiles instead of being made to re-receive them. */
	c = rdp_bmpcache_create();
	keys[0] = 0xBEEF000000000001ULL;
	keys[1] = 0xBEEF000000000002ULL;
	blen = build(buf, keys, 2,
	    RDP_PERSIST_FIRST_PDU | RDP_PERSIST_LAST_PDU);
	if (rdp_bmpcache_ingest_persistent(c, buf, blen) != 0) FAIL("ingest2");
	/* Fill every remaining slot (576 total, 2 already persistent). */
	for (i = 0; i < 576 - 2; i++) {
		uint8_t xid; uint16_t xidx;
		if (rdp_bmpcache_lookup(c, 0x2000000ULL + i, &xid, &xidx) != 0)
			FAIL("fill miss");
	}
	if (rdp_bmpcache_lookup(c, keys[0], &id, &idx) != 1)
		FAIL("persistent evicted while slots free 0");
	if (rdp_bmpcache_lookup(c, keys[1], &id, &idx) != 1)
		FAIL("persistent evicted while slots free 1");
	/* One more distinct tile now that the cache is full does evict. */
	{
		uint8_t xid; uint16_t xidx;
		if (rdp_bmpcache_lookup(c, 0x3000000ULL, &xid, &xidx) != 0)
			FAIL("full miss");
	}
	rdp_bmpcache_destroy(c);
}
