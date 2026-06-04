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

static uint16_t
ld16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

int
rdp_bmpcache_parse_persistent_list(const uint8_t *p, size_t len,
    uint64_t *keys, size_t max, size_t *n_keys, int *first, int *last)
{
	size_t i, total = 0, avail, store;

	if (n_keys) *n_keys = 0;
	if (first) *first = 0;
	if (last) *last = 0;
	/* 5x numEntries u16 + 5x totalEntries u16 + bBitMask u8 + pad1 u8 +
	 * pad3 u16 = 24 bytes, then the keys. */
	if (len < 24) return -1;
	for (i = 0; i < 5; i++)
		total += ld16(p + i * 2);
	if (first) *first = (p[20] & RDP_PERSIST_FIRST_PDU) != 0;
	if (last)  *last  = (p[20] & RDP_PERSIST_LAST_PDU) != 0;

	avail = (len - 24) / 8;
	if (total > avail) return -1;     /* the keys must fit the PDU body */

	if (keys == NULL || max == 0) {
		if (n_keys) *n_keys = total;
		return 0;
	}
	store = total > max ? max : total;
	for (i = 0; i < store; i++) {
		const uint8_t *q = p + 24 + i * 8;
		keys[i] = (uint64_t)q[0] | ((uint64_t)q[1] << 8)
		    | ((uint64_t)q[2] << 16) | ((uint64_t)q[3] << 24)
		    | ((uint64_t)q[4] << 32) | ((uint64_t)q[5] << 40)
		    | ((uint64_t)q[6] << 48) | ((uint64_t)q[7] << 56);
	}
	if (n_keys) *n_keys = store;
	return 0;
}
