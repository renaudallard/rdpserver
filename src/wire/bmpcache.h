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
 * bmpcache.h -- persistent bitmap cache (MS-RDPBCGR) server-side helpers.
 *
 * The client tells the server which cached tiles it already holds (on disk,
 * from a previous session) via a Bitmap Cache Persistent List PDU; this parses
 * the 64-bit keys out of it.  Later stages add the cache slot manager.
 */
#ifndef RDP_BMPCACHE_H
#define RDP_BMPCACHE_H

#include <stddef.h>
#include <stdint.h>

/* PERSIST_FIRST_PDU / PERSIST_LAST_PDU in the PDU's bBitMask. */
#define RDP_PERSIST_FIRST_PDU 0x01
#define RDP_PERSIST_LAST_PDU  0x02

/* Parse a Bitmap Cache Persistent List PDU body (PDUTYPE2 0x2B; the bytes after
 * the share-data header).  When keys is non-NULL it receives up to max 64-bit
 * cache keys and *n_keys is the number stored; when keys is NULL *n_keys is the
 * total key count.  first and last receive the PERSIST_FIRST and PERSIST_LAST
 * bits.  Returns 0 on success, -1 on a malformed or truncated PDU. */
int rdp_bmpcache_parse_persistent_list(const uint8_t *p, size_t len,
    uint64_t *keys, size_t max, size_t *n_keys, int *first, int *last);

/* ---- per-connection cache manager ------------------------------------- */

/* Three persistent cells whose slot counts match the advertised Rev2 cap.
 * A tile is identified to the client by (cacheId, cacheIndex) and across
 * sessions by a 64-bit key. */
#define RDP_BMPCACHE_NUM_CELLS 3

struct rdp_bmpcache;

struct rdp_bmpcache *rdp_bmpcache_create(void);
void rdp_bmpcache_destroy(struct rdp_bmpcache *c);

/* The deterministic 64-bit cache key of a tile's raw pixel bytes. */
uint64_t rdp_bmpcache_key(const uint8_t *pixels, size_t len);

/* Ingest one Bitmap Cache Persistent List PDU body (the bytes after the
 * share-data header): pre-load the slots the client already holds so a matching
 * tile is recalled with MemBlt and never re-sent.  Accumulates across the
 * multi-PDU sequence (reset on the PERSIST_FIRST PDU).  Returns 0 / -1. */
int rdp_bmpcache_ingest_persistent(struct rdp_bmpcache *c,
    const uint8_t *p, size_t len);

/* Look up a tile by key.  On a hit (the client already holds it) *cache_id and
 * *cache_index name its slot and the caller emits only a MemBlt; returns 1.  On
 * a miss a slot is allocated (evicting the oldest) and returned, and the caller
 * emits a Cache Bitmap then a MemBlt; returns 0. */
int rdp_bmpcache_lookup(struct rdp_bmpcache *c, uint64_t key,
    uint8_t *cache_id, uint16_t *cache_index);

#endif /* RDP_BMPCACHE_H */
