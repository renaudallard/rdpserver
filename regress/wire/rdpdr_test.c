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
 * rdpdr_test.c -- byte-exact checks for the write and metadata IRP
 * builders (MS-RDPEFS DR_WRITE / DR_QUERY_INFORMATION_REQ /
 * DR_SET_INFORMATION_REQ).
 */

#include "../../src/channels/rdpdr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                            \
	(void)fprintf(stderr, "fail: " __VA_ARGS__); \
	(void)fputc('\n', stderr);                  \
	exit(1);                                    \
} while (0)

static uint32_t
rd32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
		| ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t
rd16(const uint8_t *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/* Validate the shared 24-byte IRP header against expected fields. */
static void
check_irp_header(const uint8_t *b, uint32_t device_id, uint32_t file_id,
		uint32_t major)
{
	if (rd16(b) != RDPDR_CTYP_CORE)
		FAIL("component 0x%04x", rd16(b));
	if (rd16(b + 2) != PAKID_CORE_DEVICE_IOREQUEST)
		FAIL("packetId 0x%04x", rd16(b + 2));
	if (rd32(b + 4) != device_id)
		FAIL("deviceId %u", rd32(b + 4));
	if (rd32(b + 8) != file_id)
		FAIL("fileId %u", rd32(b + 8));
	/* completionId at +12 is allocator assigned; not checked here. */
	if (rd32(b + 16) != major)
		FAIL("major %u", rd32(b + 16));
	if (rd32(b + 20) != 0)
		FAIL("minor %u", rd32(b + 20));
}

static void
check_zero(const uint8_t *b, size_t from, size_t to, const char *what)
{
	size_t i;
	for (i = from; i < to; i++)
		if (b[i] != 0)
			FAIL("%s: byte %zu = 0x%02x", what, i, b[i]);
}

static void
test_write(void)
{
	struct rdpdr_state st;
	uint8_t buf[256];
	const uint8_t data[5] = { 0xde, 0xad, 0xbe, 0xef, 0x42 };
	uint64_t offset = 0x1122334455667788ull;
	uint32_t cid = 0;
	ssize_t n;

	memset(&st, 0, sizeof st);
	n = rdp_rdpdr_build_irp_write(&st, buf, sizeof buf,
		0x11, 0x22, offset, data, sizeof data, &cid);
	if (n != (ssize_t)(56 + sizeof data))
		FAIL("write return %lld", (long long)n);
	check_irp_header(buf, 0x11, 0x22, IRP_MJ_WRITE);
	/* completionId echoes the allocated id. */
	if (rd32(buf + 12) != cid)
		FAIL("write cid %u != %u", rd32(buf + 12), cid);
	/* +24 Length = bytes of WriteData. */
	if (rd32(buf + 24) != sizeof data)
		FAIL("write length %u", rd32(buf + 24));
	/* +28/+32 Offset low/high. */
	if (rd32(buf + 28) != (uint32_t)(offset & 0xFFFFFFFF))
		FAIL("write offset lo");
	if (rd32(buf + 32) != (uint32_t)(offset >> 32))
		FAIL("write offset hi");
	/* +36..+55 are 20 bytes of zero padding. */
	check_zero(buf, 36, 56, "write pad");
	/* +56 WriteData. */
	if (memcmp(buf + 56, data, sizeof data) != 0)
		FAIL("write data mismatch");

	/* Cap one byte short of total must fail without writing. */
	memset(&st, 0, sizeof st);
	n = rdp_rdpdr_build_irp_write(&st, buf, 56 + sizeof data - 1,
		0x11, 0x22, offset, data, sizeof data, &cid);
	if (n != -1)
		FAIL("write cap-short return %lld", (long long)n);
	/* A failed build must not consume a pending slot. */
	if (st.pending[0].in_use)
		FAIL("write cap-short leaked pending slot");

	/* Zero-length write is legal (total = 56, no data copy). */
	memset(&st, 0, sizeof st);
	n = rdp_rdpdr_build_irp_write(&st, buf, sizeof buf,
		0x11, 0x22, 0, NULL, 0, &cid);
	if (n != 56)
		FAIL("write zero-len return %lld", (long long)n);
	if (rd32(buf + 24) != 0)
		FAIL("write zero-len length");
	check_zero(buf, 36, 56, "write zero-len pad");
}

static void
test_query_info(void)
{
	struct rdpdr_state st;
	uint8_t buf[64];
	uint32_t cid = 0;
	ssize_t n;

	memset(&st, 0, sizeof st);
	n = rdp_rdpdr_build_irp_query_info(&st, buf, sizeof buf,
		0x33, 0x44, FileStandardInformation, &cid);
	if (n != 56)
		FAIL("query_info return %lld", (long long)n);
	check_irp_header(buf, 0x33, 0x44, IRP_MJ_QUERY_INFORMATION);
	if (rd32(buf + 12) != cid)
		FAIL("query_info cid");
	/* +24 FileInformationClass. */
	if (rd32(buf + 24) != FileStandardInformation)
		FAIL("query_info class %u", rd32(buf + 24));
	/* +28 Length must be 0 (no query buffer). */
	if (rd32(buf + 28) != 0)
		FAIL("query_info length %u", rd32(buf + 28));
	/* +32..+55 are 24 bytes of zero padding. */
	check_zero(buf, 32, 56, "query_info pad");

	/* Cap one byte short must fail and not leak a pending slot. */
	memset(&st, 0, sizeof st);
	n = rdp_rdpdr_build_irp_query_info(&st, buf, 55,
		0x33, 0x44, FileStandardInformation, &cid);
	if (n != -1)
		FAIL("query_info cap-short return %lld", (long long)n);
	if (st.pending[0].in_use)
		FAIL("query_info cap-short leaked pending slot");
}

static void
test_set_info(void)
{
	struct rdpdr_state st;
	uint8_t buf[128];
	/* Stand-in FileEndOfFileInformation: a single u64. */
	const uint8_t sb[8] = { 1, 0, 0, 0, 0, 0, 0, 0 };
	uint32_t cid = 0;
	ssize_t n;

	memset(&st, 0, sizeof st);
	n = rdp_rdpdr_build_irp_set_info(&st, buf, sizeof buf,
		0x55, 0x66, FileEndOfFileInformation, sb, sizeof sb, &cid);
	if (n != (ssize_t)(56 + sizeof sb))
		FAIL("set_info return %lld", (long long)n);
	check_irp_header(buf, 0x55, 0x66, IRP_MJ_SET_INFORMATION);
	if (rd32(buf + 12) != cid)
		FAIL("set_info cid");
	/* +24 FileInformationClass. */
	if (rd32(buf + 24) != FileEndOfFileInformation)
		FAIL("set_info class %u", rd32(buf + 24));
	/* +28 Length = SetBuffer length. */
	if (rd32(buf + 28) != sizeof sb)
		FAIL("set_info length %u", rd32(buf + 28));
	/* +32..+55 are 24 bytes of zero padding. */
	check_zero(buf, 32, 56, "set_info pad");
	/* +56 SetBuffer copied verbatim. */
	if (memcmp(buf + 56, sb, sizeof sb) != 0)
		FAIL("set_info buffer mismatch");

	/* Cap one byte short must fail and not leak a pending slot. */
	memset(&st, 0, sizeof st);
	n = rdp_rdpdr_build_irp_set_info(&st, buf, 56 + sizeof sb - 1,
		0x55, 0x66, FileEndOfFileInformation, sb, sizeof sb, &cid);
	if (n != -1)
		FAIL("set_info cap-short return %lld", (long long)n);
	if (st.pending[0].in_use)
		FAIL("set_info cap-short leaked pending slot");
}

/*
 * Completion bounds: rdp_rdpdr_handle exposes the IOCOMPLETION body as
 * comp->data with comp->data_len.  A truncated completion (body shorter
 * than the 4-byte Length the caller wants to read) must report a short
 * data_len so the caller's >= 4 guard in conn.c rejects the over-read.
 */
static void
test_completion_bounds(void)
{
	struct rdpdr_state st;
	uint8_t out[64];
	size_t out_len = 0;
	struct rdpdr_completion comp;
	uint32_t cid = 0;
	ssize_t n;
	uint8_t pdu[20];
	int rc;

	memset(&st, 0, sizeof st);
	/* Register a pending write so the completion correlates. */
	n = rdp_rdpdr_build_irp_write(&st, out, sizeof out,
		0x11, 0x22, 0, NULL, 0, &cid);
	if (n <= 0)
		FAIL("completion setup build failed");

	/* IOCOMPLETION: component+packetId(4) deviceId(4) completionId(4)
	 * ioStatus(4) then body.  Truncate so body is only 2 bytes. */
	memset(pdu, 0, sizeof pdu);
	pdu[0] = (uint8_t)(RDPDR_CTYP_CORE & 0xff);
	pdu[1] = (uint8_t)(RDPDR_CTYP_CORE >> 8);
	pdu[2] = (uint8_t)(PAKID_CORE_DEVICE_IOCOMPLETION & 0xff);
	pdu[3] = (uint8_t)(PAKID_CORE_DEVICE_IOCOMPLETION >> 8);
	pdu[4] = 0x11;                     /* deviceId */
	pdu[8] = (uint8_t)(cid & 0xff);   /* completionId low byte */
	pdu[9] = (uint8_t)((cid >> 8) & 0xff);
	pdu[10] = (uint8_t)((cid >> 16) & 0xff);
	pdu[11] = (uint8_t)((cid >> 24) & 0xff);
	/* ioStatus at +12 = 0 (success); body starts at +16. */

	memset(&comp, 0, sizeof comp);
	/* Pass a length of 18: header 16 + only 2 body bytes. */
	rc = rdp_rdpdr_handle(&st, pdu, 18, out, sizeof out, &out_len, &comp);
	if (rc != 1)
		FAIL("completion not reported (rc=%d)", rc);
	if (comp.data_len != 2)
		FAIL("completion data_len %zu (expected 2)", comp.data_len);
	if (comp.data != pdu + 16)
		FAIL("completion data ptr wrong");
	/* The conn.c forwarder only reads Length when data_len >= 4; here
	 * it is 2, so no over-read of comp->data occurs. */
}

/*
 * Regression: the worker (conn.c) sizes the IRP scratch buffer as
 * IRP_HDR_SIZE + 32 + (payload_len + 1) * 2, where payload_len is the
 * UTF-8 path/pattern length.  OPEN and LIST expand that path to UTF-16LE
 * (roughly doubling it), so the cap MUST account for the expansion or
 * those ops are rejected by the builder's cap guard.  Mirror the conn.c
 * formula here and assert the builders succeed.
 */
static size_t
conn_irp_cap(size_t payload_len)
{
	return (size_t)IRP_HDR_SIZE + 32 + (payload_len + 1) * 2;
}

static void
test_irp_cap_sizing(void)
{
	struct rdpdr_state st;
	uint8_t buf[256];
	uint32_t cid = 0;
	const char *paths[] = { "", "\\dir\\file.txt", "a" };
	const char *patterns[] = { "*", "*.c", "" };
	size_t i;

	for (i = 0; i < sizeof paths / sizeof paths[0]; i++) {
		size_t pl = strlen(paths[i]);
		size_t cap = conn_irp_cap(pl);
		memset(&st, 0, sizeof st);
		if (rdp_rdpdr_build_irp_create(&st, buf, cap, 0x11, paths[i],
		    FILE_READ_DATA | FILE_LIST_DIRECTORY, FILE_OPEN, 0,
		    &cid) <= 0)
			FAIL("OPEN rejected at conn cap for path len %zu", pl);
	}
	for (i = 0; i < sizeof patterns / sizeof patterns[0]; i++) {
		/* conn.c substitutes "*" for an empty pattern. */
		const char *pat = patterns[i][0] ? patterns[i] : "*";
		size_t pl = strlen(patterns[i]);
		size_t cap = conn_irp_cap(pl);
		memset(&st, 0, sizeof st);
		if (rdp_rdpdr_build_irp_query_dir(&st, buf, cap, 0x11, 0x22,
		    pat, 1, &cid) <= 0)
			FAIL("LIST rejected at conn cap for pattern len %zu",
			    pl);
	}
}

int
main(void)
{
	test_write();
	test_query_info();
	test_set_info();
	test_completion_bounds();
	test_irp_cap_sizing();
	return 0;
}
