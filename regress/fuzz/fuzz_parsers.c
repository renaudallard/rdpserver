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
 * fuzz_parsers.c -- in-tree mini-fuzzer for protocol parsers.
 *
 * No external dependencies: a tight loop feeds random bytes (with
 * varying length) to each parser and expects either a clean
 * structured return (success or -1) without a crash, without
 * out-of-bounds reads, without overflows.  Build under -fsanitize=
 * address,undefined to make any escape from those invariants
 * crash loudly.
 *
 * Usage:
 *   fuzz_parsers <parser> <iterations> [seed]
 * where <parser> is one of: tpkt, x224, ber, per, mcs, cliprdr, fp_input
 * or "all" to run a short pass over each.
 */

#include "../../src/wire/tpkt.h"
#include "../../src/wire/x224.h"
#include "../../src/wire/mcs.h"
#include "../../src/wire/fastpath.h"
#include "../../src/common/ber.h"
#include "../../src/common/per.h"
#include "../../src/channels/cliprdr.h"
#include "../../src/sec/cssp.h"
#include "../../src/sec/ntlm.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t prng;

static uint32_t
xorshift32(void)
{
	prng ^= prng << 13;
	prng ^= prng >> 7;
	prng ^= prng << 17;
	return (uint32_t)prng;
}

static void
fill_random(uint8_t *buf, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++)
		buf[i] = (uint8_t)(xorshift32() & 0xff);
}

static size_t
pick_len(size_t max)
{
	uint32_t r = xorshift32();
	uint32_t bucket = r & 0x7;
	switch (bucket) {
	case 0: return 0;
	case 1: return 1;
	case 2: return 2;
	case 3: return (size_t)((r >> 3) % 16);
	case 4: return (size_t)((r >> 3) % 64);
	case 5: return (size_t)((r >> 3) % 256);
	case 6: return (size_t)((r >> 3) % 2048);
	default: return (size_t)((r >> 3) % max);
	}
}

#define BUF_MAX (4 * 1024)

static void
fuzz_tpkt(size_t iters)
{
	uint8_t buf[BUF_MAX];
	size_t i;
	for (i = 0; i < iters; i++) {
		size_t len = pick_len(64);
		struct rdp_tpkt h;
		fill_random(buf, len);
		if (len >= 4)
			(void)rdp_tpkt_parse_hdr(&h, buf);
	}
}

static void
fuzz_x224(size_t iters)
{
	uint8_t buf[BUF_MAX];
	size_t i;
	for (i = 0; i < iters; i++) {
		size_t len = pick_len(512);
		struct rdp_x224_cr cr;
		fill_random(buf, len);
		(void)rdp_x224_parse_cr(&cr, buf, len);
		(void)rdp_x224_parse_dt(buf, len);
	}
}

static void
fuzz_ber(size_t iters)
{
	uint8_t buf[BUF_MAX];
	size_t i;
	for (i = 0; i < iters; i++) {
		size_t len = pick_len(256), vlen;
		uint32_t v;
		uint8_t e;
		int b;
		const uint8_t *od;
		size_t odl;
		fill_random(buf, len);
		(void)rdp_ber_read_length(buf, len, &vlen);
		(void)rdp_ber_read_universal_tag(buf, len,
			RDP_BER_PRIMITIVE, RDP_BER_TAG_INTEGER, &vlen);
		(void)rdp_ber_read_app_tag(buf, len,
			RDP_BER_CONSTRUCTED, 101, &vlen);
		(void)rdp_ber_read_integer(buf, len, &v);
		(void)rdp_ber_read_enumerated(buf, len, &e);
		(void)rdp_ber_read_boolean(buf, len, &b);
		(void)rdp_ber_read_octet_string(buf, len, &od, &odl);
	}
}

static void
fuzz_per(size_t iters)
{
	uint8_t buf[BUF_MAX];
	size_t i;
	for (i = 0; i < iters; i++) {
		size_t len = pick_len(64), vlen;
		uint8_t c;
		uint16_t u16;
		uint32_t u32;
		char key[4];
		uint8_t cnt;
		fill_random(buf, len);
		(void)rdp_per_read_length(buf, len, &vlen);
		(void)rdp_per_read_choice(buf, len, &c);
		(void)rdp_per_read_object_identifier_gcc(buf, len);
		(void)rdp_per_read_u16(buf, len, &u16);
		(void)rdp_per_read_u32(buf, len, &u32);
		(void)rdp_per_read_h221_key(buf, len, key);
		(void)rdp_per_read_user_data_count(buf, len, &cnt);
	}
}

static void
fuzz_mcs(size_t iters)
{
	uint8_t buf[BUF_MAX];
	size_t i;
	for (i = 0; i < iters; i++) {
		size_t len = pick_len(1024);
		struct rdp_mcs_connect_initial ci;
		uint16_t uid, cid;
		uint8_t reason;
		const uint8_t *payload;
		size_t payload_len;
		fill_random(buf, len);
		(void)rdp_mcs_parse_connect_initial(buf, len, &ci);
		(void)rdp_mcs_parse_erect_domain(buf, len);
		(void)rdp_mcs_parse_attach_user_request(buf, len);
		(void)rdp_mcs_parse_channel_join_request(buf, len, &uid, &cid);
		(void)rdp_mcs_parse_disconnect(buf, len, &reason);
		(void)rdp_mcs_parse_send_data_request(buf, len, &uid, &cid,
			&payload, &payload_len);
	}
}

static void
fuzz_cliprdr(size_t iters)
{
	uint8_t buf[BUF_MAX];
	size_t i;
	for (i = 0; i < iters; i++) {
		size_t len = pick_len(2048);
		struct rdp_cliprdr_hdr h;
		struct rdp_cliprdr_formats fmts;
		uint32_t fmt;
		size_t fo, fl;
		fill_random(buf, len);
		(void)rdp_cliprdr_parse_hdr(buf, len, &h);
		(void)rdp_cliprdr_parse_format_list(buf, len, 1, &fmts);
		(void)rdp_cliprdr_parse_format_list(buf, len, 0, &fmts);
		(void)rdp_cliprdr_parse_format_data_request(buf, len, &fmt);
		(void)rdp_cliprdr_html_unwrap(buf, len, &fo, &fl);
		(void)rdp_cliprdr_bmp_to_dib(buf, len, &fo, &fl);
		{
			/* The DIB header is attacker-controlled; the encoder must
			 * never over-read it.  Give a generous output buffer. */
			static uint8_t bmpout[BUF_MAX + 16];
			(void)rdp_cliprdr_dib_to_bmp(buf, len, bmpout,
				sizeof bmpout);
		}

		/* Drive the channel reassembler with a fragment stream
		 * derived from the random buffer: each record is a flags
		 * byte, a 4-byte declared total, then a variable body. */
		{
			struct rdp_cliprdr_reasm r;
			const uint8_t *pdu;
			size_t pdu_len, off = 0;
			rdp_cliprdr_reasm_init(&r, 1u << 20);
			while (off + 5 <= len) {
				uint32_t flags = buf[off] & 0x3u;
				uint32_t total = (uint32_t)buf[off + 1]
					| ((uint32_t)buf[off + 2] << 8)
					| ((uint32_t)buf[off + 3] << 16)
					| ((uint32_t)buf[off + 4] << 24);
				size_t avail = len - (off + 5);
				size_t fl = avail ? (buf[off] % (avail + 1)) : 0;
				off += 5;
				if (rdp_cliprdr_reasm_feed(&r, buf + off, fl,
					total, flags, &pdu, &pdu_len) == 1)
					rdp_cliprdr_reasm_reset(&r);
				off += fl;
			}
			rdp_cliprdr_reasm_reset(&r);
		}
	}
}

static void
fp_cb(void *ctx, const struct rdp_fp_input_event *ev)
{
	(void)ctx; (void)ev;
}

static void
fuzz_fp_input(size_t iters)
{
	uint8_t buf[BUF_MAX];
	size_t i;
	for (i = 0; i < iters; i++) {
		size_t len = pick_len(256);
		unsigned n;
		fill_random(buf, len);
		(void)rdp_fp_parse_input(buf, len, fp_cb, NULL, &n);
		(void)rdp_fp_looks_like(buf, len);
	}
}

static void
fuzz_cssp(size_t iters)
{
	uint8_t buf[BUF_MAX];
	size_t i;
	for (i = 0; i < iters; i++) {
		size_t len = pick_len(2048);
		struct rdp_tsrequest req;
		struct rdp_tscredentials tc;
		fill_random(buf, len);
		(void)rdp_cssp_parse(buf, len, &req);
		(void)rdp_cssp_parse_tscredentials(buf, len, &tc);
	}
}

static void
fuzz_ntlm(size_t iters)
{
	uint8_t buf[BUF_MAX];
	size_t i;
	for (i = 0; i < iters; i++) {
		size_t len = pick_len(2048);
		struct ntlm_negotiate neg;
		struct ntlm_authenticate auth;
		fill_random(buf, len);
		(void)ntlm_parse_negotiate(buf, len, &neg);
		(void)ntlm_parse_authenticate(buf, len, &auth);
	}
}

struct fuzzer { const char *name; void (*fn)(size_t); };

static const struct fuzzer fuzzers[] = {
	{ "tpkt",     fuzz_tpkt     },
	{ "x224",     fuzz_x224     },
	{ "ber",      fuzz_ber      },
	{ "per",      fuzz_per      },
	{ "mcs",      fuzz_mcs      },
	{ "cliprdr",  fuzz_cliprdr  },
	{ "fp_input", fuzz_fp_input },
	{ "cssp",     fuzz_cssp     },
	{ "ntlm",     fuzz_ntlm     },
};

static const size_t nfuzzers = sizeof fuzzers / sizeof fuzzers[0];

int
main(int argc, char *argv[])
{
	const char *which = "all";
	size_t iters = 1000;
	size_t i;

	if (argc >= 2) which = argv[1];
	if (argc >= 3) iters = (size_t)strtoull(argv[2], NULL, 10);
	if (argc >= 4) prng = strtoull(argv[3], NULL, 10);
	if (prng == 0) prng = (uint64_t)time(NULL);

	if (strcmp(which, "all") == 0) {
		for (i = 0; i < nfuzzers; i++) {
			fprintf(stderr, "fuzz %s x %zu... ", fuzzers[i].name,
				iters);
			fuzzers[i].fn(iters);
			fprintf(stderr, "ok\n");
		}
		return 0;
	}
	for (i = 0; i < nfuzzers; i++) {
		if (strcmp(fuzzers[i].name, which) == 0) {
			fprintf(stderr, "fuzz %s x %zu (seed=%llu)... ",
				fuzzers[i].name, iters,
				(unsigned long long)prng);
			fuzzers[i].fn(iters);
			fprintf(stderr, "ok\n");
			return 0;
		}
	}
	fprintf(stderr, "unknown parser '%s'\n", which);
	return 1;
}
