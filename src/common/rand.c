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
 * rand.c -- secure random.
 *
 * Backed by arc4random_buf when present (BSD, glibc >= 2.36); falls
 * back to getrandom(2) on older Linux.  Provides both
 * arc4random_buf-style and the simple u32/byte helpers.
 */

#include "rand.h"

#include "../include/compat.h"
#include "../include/rdp_log.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#if !HAVE_ARC4RANDOM && HAVE_GETRANDOM
#include <sys/random.h>
#endif

void
rdp_rand_bytes(void *buf, size_t n)
{
#if HAVE_ARC4RANDOM
	arc4random_buf(buf, n);
#else
	uint8_t *p = buf;
	while (n > 0) {
		ssize_t r = getrandom(p, n, 0);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			rdp_err("getrandom: %s", strerror(errno));
			abort();
		}
		p += r;
		n -= (size_t)r;
	}
#endif
}

uint32_t
rdp_rand_u32(void)
{
	uint32_t v;
	rdp_rand_bytes(&v, sizeof v);
	return v;
}

#if !HAVE_ARC4RANDOM
uint32_t
arc4random(void)
{
	return rdp_rand_u32();
}

uint32_t
arc4random_uniform(uint32_t upper_bound)
{
	uint32_t r, min;

	if (upper_bound < 2)
		return 0;
	min = -upper_bound % upper_bound;
	for (;;) {
		r = rdp_rand_u32();
		if (r >= min)
			return r % upper_bound;
	}
}

void
arc4random_buf(void *buf, size_t len)
{
	rdp_rand_bytes(buf, len);
}
#endif
