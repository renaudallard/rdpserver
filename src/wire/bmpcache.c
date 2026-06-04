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
 * bmpcache.c -- persistent bitmap cache helpers.
 */

#include "bmpcache.h"

#include <stdlib.h>
#include <string.h>

/* Slot counts of the three persistent cells; must match the advertised cap. */
static const uint16_t cell_slots[RDP_BMPCACHE_NUM_CELLS] = { 120, 120, 336 };

static uint16_t
ld16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint64_t
ld64(const uint8_t *p)
{
	return (uint64_t)p[0] | ((uint64_t)p[1] << 8)
	    | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24)
	    | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40)
	    | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

/* Validate the 24-byte persistent-list header and that the declared keys fit
 * the body.  Fills num[5] (per-cache key counts), total, and first/last.
 * Returns 0 / -1. */
static int
parse_pl_header(const uint8_t *p, size_t len, uint16_t num[5], size_t *total,
    int *first, int *last)
{
	size_t i, sum = 0;

	if (len < 24) return -1;
	for (i = 0; i < 5; i++) {
		num[i] = ld16(p + i * 2);
		sum += num[i];
	}
	if (sum > (len - 24) / 8) return -1;  /* keys must fit the body */
	if (total) *total = sum;
	if (first) *first = (p[20] & RDP_PERSIST_FIRST_PDU) != 0;
	if (last)  *last  = (p[20] & RDP_PERSIST_LAST_PDU) != 0;
	return 0;
}

int
rdp_bmpcache_parse_persistent_list(const uint8_t *p, size_t len,
    uint64_t *keys, size_t max, size_t *n_keys, int *first, int *last)
{
	uint16_t num[5];
	size_t total, store, i;

	if (n_keys) *n_keys = 0;
	if (first) *first = 0;
	if (last) *last = 0;
	if (parse_pl_header(p, len, num, &total, first, last) != 0)
		return -1;
	if (keys == NULL || max == 0) {
		if (n_keys) *n_keys = total;
		return 0;
	}
	store = total > max ? max : total;
	for (i = 0; i < store; i++)
		keys[i] = ld64(p + 24 + i * 8);
	if (n_keys) *n_keys = store;
	return 0;
}

/* ---- per-connection cache manager ------------------------------------- */

struct cache_slot {
	uint64_t key;
	int      occupied;
};

struct rdp_bmpcache {
	struct cache_slot slot[120 + 120 + 336];   /* 576 = sum(cell_slots) */
	size_t   total;
	size_t   offset[RDP_BMPCACHE_NUM_CELLS];    /* first slot of each cell */
	size_t   next;                              /* round-robin allocator */
	size_t   ingest[RDP_BMPCACHE_NUM_CELLS];    /* persistent fill cursor */
};

struct rdp_bmpcache *
rdp_bmpcache_create(void)
{
	struct rdp_bmpcache *c = calloc(1, sizeof *c);
	size_t i, off = 0;

	if (c == NULL) return NULL;
	for (i = 0; i < RDP_BMPCACHE_NUM_CELLS; i++) {
		c->offset[i] = off;
		off += cell_slots[i];
	}
	c->total = off;
	return c;
}

void
rdp_bmpcache_destroy(struct rdp_bmpcache *c)
{
	free(c);
}

uint64_t
rdp_bmpcache_key(const uint8_t *pixels, size_t len)
{
	/* FNV-1a (64-bit): a deterministic hash so a repeated tile resolves to
	 * the same key within and across sessions. */
	uint64_t h = 0xcbf29ce484222325ULL;
	size_t i;

	for (i = 0; i < len; i++) {
		h ^= pixels[i];
		h *= 0x100000001b3ULL;
	}
	return h;
}

/* Map a flat slot index to its (cacheId, cacheIndex). */
static void
slot_to_cell(const struct rdp_bmpcache *c, size_t pool, uint8_t *id,
    uint16_t *idx)
{
	size_t cell = RDP_BMPCACHE_NUM_CELLS - 1;
	size_t i;

	for (i = 0; i < RDP_BMPCACHE_NUM_CELLS; i++) {
		if (pool < c->offset[i] + cell_slots[i]) { cell = i; break; }
	}
	*id = (uint8_t)cell;
	*idx = (uint16_t)(pool - c->offset[cell]);
}

int
rdp_bmpcache_ingest_persistent(struct rdp_bmpcache *c, const uint8_t *p,
    size_t len)
{
	uint16_t num[5];
	size_t off, cell, i;
	int first = 0;

	if (c == NULL) return -1;
	if (parse_pl_header(p, len, num, NULL, &first, NULL) != 0)
		return -1;
	/* The keys for a cache are listed in cacheIndex order; the FIRST PDU of
	 * the sequence restarts the fill at slot 0. */
	if (first) {
		for (i = 0; i < RDP_BMPCACHE_NUM_CELLS; i++)
			c->ingest[i] = 0;
	}
	off = 24;
	for (cell = 0; cell < 5; cell++) {
		for (i = 0; i < num[cell]; i++, off += 8) {
			uint64_t key = ld64(p + off);
			if (cell >= RDP_BMPCACHE_NUM_CELLS)
				continue;
			if (c->ingest[cell] >= cell_slots[cell])
				continue;          /* more keys than slots */
			{
				size_t pool = c->offset[cell] + c->ingest[cell];
				c->slot[pool].key = key;
				c->slot[pool].occupied = 1;
				c->ingest[cell]++;
			}
		}
	}
	return 0;
}

int
rdp_bmpcache_lookup(struct rdp_bmpcache *c, uint64_t key, uint8_t *cache_id,
    uint16_t *cache_index)
{
	size_t i, pool;

	if (c == NULL) return 0;
	for (i = 0; i < c->total; i++) {
		if (c->slot[i].occupied && c->slot[i].key == key) {
			slot_to_cell(c, i, cache_id, cache_index);
			return 1;                  /* hit: MemBlt only */
		}
	}
	/* Miss: take the next slot round-robin, evicting whatever it held. */
	pool = c->next;
	c->next = (c->next + 1) % c->total;
	c->slot[pool].key = key;
	c->slot[pool].occupied = 1;
	slot_to_cell(c, pool, cache_id, cache_index);
	return 0;                                  /* miss: Cache Bitmap + MemBlt */
}
