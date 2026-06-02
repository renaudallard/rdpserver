/*
 * Copyright (c) 2026 Renaud Allard <renaud@allard.it>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and this disclaimer.
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
 * fuse_drive_test.c -- raw /dev/fuse read-path checks for the RDPDR
 * drive presentation.  Drives fuse_drive.c on in-memory FUSE requests
 * (no real fd) via its RDP_FUSE_TEST hooks, and feeds canned RDP_BE_FS_RSP
 * replies, asserting both the emitted FS_REQ and the FUSE reply bytes.
 * Built with ASan + UBSan so any over-read of the untrusted FSCC/read
 * decode is caught.
 */

#include "../../src/session/fuse_drive.h"
#include "../../src/backend/proto.h"
#include "../../src/channels/rdpdr.h"   /* FileBothDirectoryInformation */

#include <linux/fuse.h>

#include <sys/stat.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                               \
	(void)fprintf(stderr, "fail: " __VA_ARGS__); \
	(void)fputc('\n', stderr);                   \
	exit(1);                                     \
} while (0)

/* Test hooks exported by fuse_drive.c under -DRDP_FUSE_TEST. */
struct fuse_drive *fuse_drive_test_new(void);
void fuse_drive_test_reset(void);
void fuse_drive_test_dispatch(struct fuse_drive *, const uint8_t *, size_t);
int fuse_drive_test_have_req(void);
uint32_t fuse_drive_test_req_op(void);
uint32_t fuse_drive_test_req_id(void);
uint32_t fuse_drive_test_req_device(void);
uint32_t fuse_drive_test_req_file_id(void);
uint32_t fuse_drive_test_req_length(void);
uint64_t fuse_drive_test_req_offset(void);
const uint8_t *fuse_drive_test_req_payload(size_t *);
const uint8_t *fuse_drive_test_reply(size_t *);

static void
put32le(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

/* Build a fuse_in_header in-place; returns total length written. */
static size_t
build_in(uint8_t *buf, uint32_t opcode, uint64_t unique, uint64_t nodeid,
		const void *body, size_t body_len)
{
	struct fuse_in_header ih;
	memset(&ih, 0, sizeof ih);
	ih.len = (uint32_t)(sizeof ih + body_len);
	ih.opcode = opcode;
	ih.unique = unique;
	ih.nodeid = nodeid;
	memcpy(buf, &ih, sizeof ih);
	if (body_len > 0)
		memcpy(buf + sizeof ih, body, body_len);
	return sizeof ih + body_len;
}

/* Read the fuse_out_header at the front of the captured reply. */
static void
get_out(struct fuse_out_header *oh)
{
	size_t len;
	const uint8_t *r = fuse_drive_test_reply(&len);
	if (len < sizeof *oh)
		FAIL("reply shorter than out header (%zu)", len);
	memcpy(oh, r, sizeof *oh);
	if (oh->len != len)
		FAIL("out header len %u != captured %zu", oh->len, len);
}

/* --- INIT --- */
static void
test_init(struct fuse_drive *fd)
{
	uint8_t buf[256];
	struct fuse_init_in in;
	struct fuse_init_out out;
	struct fuse_out_header oh;
	size_t len, rlen;
	const uint8_t *r;

	memset(&in, 0, sizeof in);
	in.major = FUSE_KERNEL_VERSION;
	in.minor = 40;            /* kernel newer than us; expect clamp */
	in.max_readahead = 131072;
	fuse_drive_test_reset();
	len = build_in(buf, FUSE_INIT, 1, 0, &in, sizeof in);
	fuse_drive_test_dispatch(fd, buf, len);

	get_out(&oh);
	if (oh.error != 0)
		FAIL("INIT error %d", oh.error);
	if (oh.unique != 1)
		FAIL("INIT unique %llu", (unsigned long long)oh.unique);
	r = fuse_drive_test_reply(&rlen);
	if (rlen != sizeof oh + sizeof out)
		FAIL("INIT reply size %zu", rlen);
	memcpy(&out, r + sizeof oh, sizeof out);
	if (out.major != FUSE_KERNEL_VERSION)
		FAIL("INIT major %u", out.major);
	if (out.minor > 40)
		FAIL("INIT minor %u not clamped", out.minor);
	if (out.max_write == 0)
		FAIL("INIT max_write 0");
	printf("  init: major=%u minor=%u max_write=%u ok\n",
		out.major, out.minor, out.max_write);
}

/* --- GETATTR on root --- */
static void
test_getattr_root(struct fuse_drive *fd)
{
	uint8_t buf[256];
	struct fuse_getattr_in gi;
	struct fuse_attr_out ao;
	struct fuse_out_header oh;
	size_t len, rlen;
	const uint8_t *r;

	memset(&gi, 0, sizeof gi);
	fuse_drive_test_reset();
	len = build_in(buf, FUSE_GETATTR, 2, FUSE_ROOT_ID, &gi, sizeof gi);
	fuse_drive_test_dispatch(fd, buf, len);

	get_out(&oh);
	if (oh.error != 0)
		FAIL("root GETATTR error %d", oh.error);
	r = fuse_drive_test_reply(&rlen);
	if (rlen != sizeof oh + sizeof ao)
		FAIL("root GETATTR reply size %zu", rlen);
	memcpy(&ao, r + sizeof oh, sizeof ao);
	if ((ao.attr.mode & S_IFMT) != S_IFDIR)
		FAIL("root not a dir, mode 0%o", ao.attr.mode);
	if (ao.attr.ino != FUSE_ROOT_ID)
		FAIL("root ino %llu", (unsigned long long)ao.attr.ino);
	printf("  getattr root: S_IFDIR mode 0%o ok\n", ao.attr.mode);
}

/* --- READDIR on root with two announced drives --- */
static void
test_readdir_root(struct fuse_drive *fd)
{
	uint8_t buf[256];
	struct fuse_read_in ri;
	struct fuse_out_header oh;
	size_t len, rlen, off;
	const uint8_t *r, *p;
	int saw_c = 0, saw_d = 0, count = 0;

	fuse_drive_add_device(fd, 100, RDPDR_DTYP_FILESYSTEM, "C       ", 1);
	fuse_drive_add_device(fd, 101, RDPDR_DTYP_FILESYSTEM, "DOCS    ", 1);

	memset(&ri, 0, sizeof ri);
	ri.size = 4096;
	ri.offset = 0;
	fuse_drive_test_reset();
	len = build_in(buf, FUSE_READDIR, 3, FUSE_ROOT_ID, &ri, sizeof ri);
	fuse_drive_test_dispatch(fd, buf, len);

	get_out(&oh);
	if (oh.error != 0)
		FAIL("root READDIR error %d", oh.error);
	r = fuse_drive_test_reply(&rlen);
	p = r + sizeof oh;
	off = 0;
	while (off + FUSE_NAME_OFFSET <= rlen - sizeof oh) {
		struct fuse_dirent de;
		size_t reclen;
		char nm[256];
		memcpy(&de, p + off, FUSE_NAME_OFFSET);
		if (de.namelen > 255)
			FAIL("dirent namelen %u", de.namelen);
		reclen = FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + de.namelen);
		if (off + reclen > rlen - sizeof oh)
			FAIL("dirent overruns reply");
		memcpy(nm, p + off + FUSE_NAME_OFFSET, de.namelen);
		nm[de.namelen] = '\0';
		if (de.type != (S_IFDIR >> 12))
			FAIL("drive dirent '%s' not DT_DIR", nm);
		if (strcmp(nm, "C") == 0) saw_c = 1;
		if (strcmp(nm, "DOCS") == 0) saw_d = 1;
		count++;
		off += reclen;
	}
	if (off != rlen - sizeof oh)
		FAIL("dirent buffer not exactly consumed (%zu of %zu)",
			off, rlen - sizeof oh);
	if (!saw_c || !saw_d || count != 2)
		FAIL("root readdir missing drives (c=%d d=%d n=%d)",
			saw_c, saw_d, count);
	printf("  readdir root: 2 aligned drive dirents ok\n");
}

/* Drive C is node 2 (first announced after root id 1).  Helper to find
 * the nodeid the module assigned to a drive label by reading the root
 * READDIR ino.  We rely on deterministic allocation: first announced
 * drive gets nodeid 2. */
#define DRIVE_C_NODE 2u

/* --- LOOKUP under a drive emits an OPEN FS_REQ --- */
static uint64_t
test_lookup_emits_open(struct fuse_drive *fd)
{
	uint8_t buf[256];
	const char *name = "file.txt";
	size_t len;
	size_t plen;
	const uint8_t *pl;

	fuse_drive_test_reset();
	len = build_in(buf, FUSE_LOOKUP, 10, DRIVE_C_NODE,
		name, strlen(name) + 1);
	fuse_drive_test_dispatch(fd, buf, len);

	if (!fuse_drive_test_have_req())
		FAIL("LOOKUP did not emit an FS_REQ");
	if (fuse_drive_test_req_op() != RDP_FS_OPEN)
		FAIL("LOOKUP FS_REQ op %u != OPEN", fuse_drive_test_req_op());
	if (fuse_drive_test_req_device() != 100)
		FAIL("LOOKUP device %u", fuse_drive_test_req_device());
	pl = fuse_drive_test_req_payload(&plen);
	if (plen == 0 || strcmp((const char *)pl, "\\file.txt") != 0)
		FAIL("LOOKUP path '%.*s'", (int)plen, pl);
	printf("  lookup file.txt: OPEN '\\file.txt' on device 100 ok\n");
	return fuse_drive_test_req_id();
}

/* Feed an OPEN success FS_RSP and check the LOOKUP got a fuse_entry_out. */
static void
test_lookup_open_reply(struct fuse_drive *fd, uint32_t req_id)
{
	struct rdp_be_fs_rsp rsp;
	struct fuse_entry_out eo;
	struct fuse_out_header oh;
	size_t rlen;
	const uint8_t *r;

	memset(&rsp, 0, sizeof rsp);
	rsp.req_id = req_id;
	rsp.status = STATUS_SUCCESS;
	rsp.file_id = 0x4242;
	fuse_drive_test_reset();
	fuse_drive_handle_fs_rsp(fd, &rsp, NULL, 0);

	get_out(&oh);
	if (oh.error != 0)
		FAIL("LOOKUP reply error %d", oh.error);
	if (oh.unique != 10)
		FAIL("LOOKUP reply unique %llu",
			(unsigned long long)oh.unique);
	r = fuse_drive_test_reply(&rlen);
	if (rlen != sizeof oh + sizeof eo)
		FAIL("LOOKUP entry reply size %zu", rlen);
	memcpy(&eo, r + sizeof oh, sizeof eo);
	if (eo.nodeid == 0 || eo.nodeid == FUSE_ROOT_ID)
		FAIL("LOOKUP child nodeid %llu",
			(unsigned long long)eo.nodeid);
	printf("  lookup reply: entry nodeid %llu ok\n",
		(unsigned long long)eo.nodeid);
}

/* --- OPEN of the looked-up file emits an OPEN, reply gives open_out --- */
static uint64_t
test_open_node(struct fuse_drive *fd, uint64_t child_node)
{
	uint8_t buf[256];
	struct fuse_open_in oi;
	size_t len;

	memset(&oi, 0, sizeof oi);
	fuse_drive_test_reset();
	len = build_in(buf, FUSE_OPEN, 20, child_node, &oi, sizeof oi);
	fuse_drive_test_dispatch(fd, buf, len);

	/* The LOOKUP already opened the handle, so OPEN replies immediately
	 * with the cached handle and emits no new FS_REQ. */
	if (fuse_drive_test_have_req())
		FAIL("OPEN re-issued an FS_REQ for an already-open node");
	{
		struct fuse_out_header oh;
		struct fuse_open_out oo;
		size_t rlen;
		const uint8_t *r;
		get_out(&oh);
		if (oh.error != 0)
			FAIL("OPEN error %d", oh.error);
		r = fuse_drive_test_reply(&rlen);
		if (rlen != sizeof oh + sizeof oo)
			FAIL("OPEN reply size %zu", rlen);
		memcpy(&oo, r + sizeof oh, sizeof oo);
		if (oo.fh != child_node)
			FAIL("OPEN fh %llu", (unsigned long long)oo.fh);
	}
	printf("  open file: cached handle reused, open_out ok\n");
	return child_node;
}

/* --- READ emits an FS_REQ READ, reply returns the data --- */
static void
test_read(struct fuse_drive *fd, uint64_t child_node)
{
	uint8_t buf[256];
	struct fuse_read_in ri;
	size_t len;
	uint32_t req_id;

	memset(&ri, 0, sizeof ri);
	ri.fh = child_node;
	ri.offset = 16;
	ri.size = 8;
	fuse_drive_test_reset();
	len = build_in(buf, FUSE_READ, 30, child_node, &ri, sizeof ri);
	fuse_drive_test_dispatch(fd, buf, len);

	if (!fuse_drive_test_have_req())
		FAIL("READ did not emit an FS_REQ");
	if (fuse_drive_test_req_op() != RDP_FS_READ)
		FAIL("READ op %u", fuse_drive_test_req_op());
	if (fuse_drive_test_req_file_id() != 0x4242)
		FAIL("READ file_id 0x%x", fuse_drive_test_req_file_id());
	if (fuse_drive_test_req_offset() != 16)
		FAIL("READ offset %llu",
			(unsigned long long)fuse_drive_test_req_offset());
	if (fuse_drive_test_req_length() != 8)
		FAIL("READ length %u", fuse_drive_test_req_length());
	req_id = fuse_drive_test_req_id();

	/* Canned READ FS_RSP: FSCC Length(u32) + ReadData. */
	{
		struct rdp_be_fs_rsp rsp;
		uint8_t pl[4 + 8];
		struct fuse_out_header oh;
		size_t rlen;
		const uint8_t *r;
		const char data[8] = { 'a','b','c','d','e','f','g','h' };

		put32le(pl, 8);
		memcpy(pl + 4, data, 8);
		memset(&rsp, 0, sizeof rsp);
		rsp.req_id = req_id;
		rsp.status = STATUS_SUCCESS;
		rsp.length = 8;
		fuse_drive_test_reset();
		fuse_drive_handle_fs_rsp(fd, &rsp, pl, sizeof pl);

		get_out(&oh);
		if (oh.error != 0)
			FAIL("READ reply error %d", oh.error);
		if (oh.unique != 30)
			FAIL("READ unique %llu",
				(unsigned long long)oh.unique);
		r = fuse_drive_test_reply(&rlen);
		if (rlen != sizeof oh + 8)
			FAIL("READ reply size %zu", rlen);
		if (memcmp(r + sizeof oh, data, 8) != 0)
			FAIL("READ data mismatch");
	}
	printf("  read: FS_REQ READ + reply 8 bytes ok\n");
}

/* Build one FILE_BOTH_DIR_INFORMATION record into buf. */
static size_t
build_fdi(uint8_t *buf, uint32_t next, uint32_t attrs, const char *name)
{
	size_t nlen = strlen(name);
	size_t i;
	memset(buf, 0, 94);
	put32le(buf + 0, next);
	put32le(buf + 56, attrs);
	put32le(buf + 60, (uint32_t)(nlen * 2));
	for (i = 0; i < nlen; i++) {
		buf[94 + i * 2] = (uint8_t)name[i];
		buf[94 + i * 2 + 1] = 0;
	}
	return 94 + nlen * 2;
}

/* --- READDIR on a drive: LIST FS_REQ, reply decodes FSCC dirents --- */
static void
test_readdir_drive(struct fuse_drive *fd)
{
	uint8_t buf[512];
	struct fuse_open_in oi;
	struct fuse_read_in ri;
	size_t len;
	uint32_t open_req, list_req;

	/* OPENDIR the drive root to get a real handle. */
	memset(&oi, 0, sizeof oi);
	fuse_drive_test_reset();
	len = build_in(buf, FUSE_OPENDIR, 40, DRIVE_C_NODE, &oi, sizeof oi);
	fuse_drive_test_dispatch(fd, buf, len);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_OPEN)
		FAIL("OPENDIR did not emit an OPEN FS_REQ");
	open_req = fuse_drive_test_req_id();
	{
		struct rdp_be_fs_rsp rsp;
		memset(&rsp, 0, sizeof rsp);
		rsp.req_id = open_req;
		rsp.status = STATUS_SUCCESS;
		rsp.file_id = 0x9001;
		fuse_drive_test_reset();
		fuse_drive_handle_fs_rsp(fd, &rsp, NULL, 0);  /* opendir reply */
	}

	/* READDIR now emits a LIST. */
	memset(&ri, 0, sizeof ri);
	ri.size = 4096;
	ri.offset = 0;
	fuse_drive_test_reset();
	len = build_in(buf, FUSE_READDIR, 41, DRIVE_C_NODE, &ri, sizeof ri);
	fuse_drive_test_dispatch(fd, buf, len);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_LIST)
		FAIL("drive READDIR did not emit a LIST FS_REQ");
	list_req = fuse_drive_test_req_id();

	/* Canned LIST reply: Length(u32) + two FDI records (a dir and a
	 * file), plus the "." and ".." entries the module must drop. */
	{
		uint8_t fscc[512];
		uint8_t pl[516];
		size_t off = 0, total;
		struct fuse_out_header oh;
		size_t rlen, doff;
		const uint8_t *r;
		int saw_sub = 0, saw_file = 0, count = 0;
		struct rdp_be_fs_rsp rsp;

		off += build_fdi(fscc + off, 94 + 2, 0x10, ".");
		off += build_fdi(fscc + off, 94 + 4, 0x10, "..");
		off += build_fdi(fscc + off, (uint32_t)(94 + 6), 0x10, "sub");
		off += build_fdi(fscc + off, 0, 0x20, "a.txt");
		total = off;

		put32le(pl, (uint32_t)total);
		memcpy(pl + 4, fscc, total);

		memset(&rsp, 0, sizeof rsp);
		rsp.req_id = list_req;
		rsp.status = STATUS_SUCCESS;
		fuse_drive_test_reset();
		fuse_drive_handle_fs_rsp(fd, &rsp, pl, 4 + total);

		get_out(&oh);
		if (oh.error != 0)
			FAIL("drive READDIR reply error %d", oh.error);
		r = fuse_drive_test_reply(&rlen);
		doff = 0;
		while (doff + FUSE_NAME_OFFSET <= rlen - sizeof oh) {
			struct fuse_dirent de;
			size_t reclen;
			char nm[256];
			memcpy(&de, r + sizeof oh + doff, FUSE_NAME_OFFSET);
			if (de.namelen > 255)
				FAIL("drive dirent namelen %u", de.namelen);
			reclen = FUSE_DIRENT_ALIGN(
				FUSE_NAME_OFFSET + de.namelen);
			if (doff + reclen > rlen - sizeof oh)
				FAIL("drive dirent overruns reply");
			memcpy(nm, r + sizeof oh + doff + FUSE_NAME_OFFSET,
				de.namelen);
			nm[de.namelen] = '\0';
			if (strcmp(nm, "sub") == 0) {
				saw_sub = 1;
				if (de.type != (S_IFDIR >> 12))
					FAIL("'sub' not DT_DIR");
			}
			if (strcmp(nm, "a.txt") == 0) {
				saw_file = 1;
				if (de.type != (S_IFREG >> 12))
					FAIL("'a.txt' not DT_REG");
			}
			count++;
			doff += reclen;
		}
		if (!saw_sub || !saw_file || count != 2)
			FAIL("drive readdir decode (sub=%d file=%d n=%d)",
				saw_sub, saw_file, count);
		printf("  readdir drive: decoded 'sub' (dir) + 'a.txt' "
			"(file), skipped . / .. ok\n");
	}
}

/* --- Bounds: a truncated and an oversized FSCC LIST must not over-read
 * (ASan/UBSan guard).  We just assert the module produces a reply and
 * never crashes; the sanitizers fail the run on any OOB. --- */
static void
test_bounds(struct fuse_drive *fd)
{
	uint8_t buf[256];
	struct fuse_open_in oi;
	struct fuse_read_in ri;
	size_t len;
	uint32_t open_req, list_req;
	struct fuse_out_header oh;

	/* Use the DOCS drive (node 3) for an independent open handle. */
	memset(&oi, 0, sizeof oi);
	fuse_drive_test_reset();
	len = build_in(buf, FUSE_OPENDIR, 50, 3, &oi, sizeof oi);
	fuse_drive_test_dispatch(fd, buf, len);
	if (!fuse_drive_test_have_req())
		FAIL("bounds OPENDIR no FS_REQ");
	open_req = fuse_drive_test_req_id();
	{
		struct rdp_be_fs_rsp rsp;
		memset(&rsp, 0, sizeof rsp);
		rsp.req_id = open_req;
		rsp.status = STATUS_SUCCESS;
		rsp.file_id = 0x7;
		fuse_drive_test_reset();
		fuse_drive_handle_fs_rsp(fd, &rsp, NULL, 0);
	}
	memset(&ri, 0, sizeof ri);
	ri.size = 4096;
	fuse_drive_test_reset();
	len = build_in(buf, FUSE_READDIR, 51, 3, &ri, sizeof ri);
	fuse_drive_test_dispatch(fd, buf, len);
	list_req = fuse_drive_test_req_id();

	/* Oversized declared Length and a name length claiming more bytes
	 * than the record carries.  The decode must clamp and stop. */
	{
		uint8_t fscc[94 + 8];
		uint8_t pl[4 + sizeof fscc];
		struct rdp_be_fs_rsp rsp;
		memset(fscc, 0, sizeof fscc);
		put32le(fscc + 0, 0);            /* last record */
		put32le(fscc + 56, 0x20);        /* file attrs */
		put32le(fscc + 60, 0xFFFFFFF0u); /* name length far too big */
		/* declared inner length larger than what we actually send */
		put32le(pl, 0x10000u);
		memcpy(pl + 4, fscc, sizeof fscc);
		memset(&rsp, 0, sizeof rsp);
		rsp.req_id = list_req;
		rsp.status = STATUS_SUCCESS;
		fuse_drive_test_reset();
		fuse_drive_handle_fs_rsp(fd, &rsp, pl, sizeof pl);
		get_out(&oh);   /* must produce a well-formed reply, no crash */
	}

	/* A READ reply whose declared length exceeds the bytes present must
	 * not over-read. */
	{
		uint8_t buf2[256];
		struct fuse_read_in ri2;
		uint32_t rreq;
		struct rdp_be_fs_rsp rsp;
		uint8_t pl[4 + 2];
		size_t len2, rlen2;
		struct fuse_entry_out eo2;
		uint64_t xnode;
		const uint8_t *rr;

		/* Open a regular file under DOCS first; read the assigned
		 * nodeid from the entry reply rather than assuming it. */
		fuse_drive_test_reset();
		len2 = build_in(buf2, FUSE_LOOKUP, 60, 3,
			"x", strlen("x") + 1);
		fuse_drive_test_dispatch(fd, buf2, len2);
		rreq = fuse_drive_test_req_id();
		memset(&rsp, 0, sizeof rsp);
		rsp.req_id = rreq;
		rsp.status = STATUS_SUCCESS;
		rsp.file_id = 0x55;
		fuse_drive_test_reset();
		fuse_drive_handle_fs_rsp(fd, &rsp, NULL, 0);  /* entry */
		rr = fuse_drive_test_reply(&rlen2);
		if (rlen2 != sizeof oh + sizeof eo2)
			FAIL("bounds LOOKUP entry size %zu", rlen2);
		memcpy(&eo2, rr + sizeof oh, sizeof eo2);
		xnode = eo2.nodeid;

		memset(&ri2, 0, sizeof ri2);
		ri2.size = 4096;
		fuse_drive_test_reset();
		len2 = build_in(buf2, FUSE_READ, 61, xnode, &ri2, sizeof ri2);
		fuse_drive_test_dispatch(fd, buf2, len2);
		if (!fuse_drive_test_have_req())
			FAIL("bounds READ no FS_REQ");
		rreq = fuse_drive_test_req_id();

		put32le(pl, 0x10000u);   /* claims 64 KiB, only 2 present */
		pl[4] = 0xAA;
		pl[5] = 0xBB;
		memset(&rsp, 0, sizeof rsp);
		rsp.req_id = rreq;
		rsp.status = STATUS_SUCCESS;
		fuse_drive_test_reset();
		fuse_drive_handle_fs_rsp(fd, &rsp, pl, sizeof pl);
		get_out(&oh);
		if (oh.error != 0)
			FAIL("bounds READ reply error %d", oh.error);
		if (oh.len != sizeof oh + 2)
			FAIL("bounds READ clamped to wrong size %u", oh.len);
	}
	printf("  bounds: truncated/oversized FSCC + over-claimed READ "
		"clamped, no over-read ok\n");
}

/* --- Re-LOOKUP of an already-open node reuses the handle (no new OPEN) --- */
static void
test_relookup_open(struct fuse_drive *fd, uint64_t child_node)
{
	uint8_t buf[256];
	const char *name = "file.txt";
	struct fuse_out_header oh;
	struct fuse_entry_out eo;
	size_t len, rlen;
	const uint8_t *r;

	fuse_drive_test_reset();
	len = build_in(buf, FUSE_LOOKUP, 70, DRIVE_C_NODE,
		name, strlen(name) + 1);
	fuse_drive_test_dispatch(fd, buf, len);

	if (fuse_drive_test_have_req())
		FAIL("re-LOOKUP re-issued an OPEN for an already-open node");
	get_out(&oh);
	if (oh.error != 0)
		FAIL("re-LOOKUP reply error %d", oh.error);
	r = fuse_drive_test_reply(&rlen);
	if (rlen != sizeof oh + sizeof eo)
		FAIL("re-LOOKUP entry reply size %zu", rlen);
	memcpy(&eo, r + sizeof oh, sizeof eo);
	if (eo.nodeid != child_node)
		FAIL("re-LOOKUP nodeid %llu != %llu",
			(unsigned long long)eo.nodeid,
			(unsigned long long)child_node);
	printf("  re-lookup file.txt: cached handle reused, no new OPEN ok\n");
}

/* --- BATCH_FORGET drops a node so a later LOOKUP re-opens it --- */
static void
test_batch_forget(struct fuse_drive *fd, uint64_t child_node)
{
	uint8_t buf[256];
	struct fuse_batch_forget_in bf;
	struct fuse_forget_one one;
	const char *name = "file.txt";
	size_t off, len;

	/* Forget the node with a large nlookup so the saturating count hits
	 * zero and the slot is freed (closing its RDPDR handle). */
	memset(&bf, 0, sizeof bf);
	bf.count = 1;
	memset(&one, 0, sizeof one);
	one.nodeid = child_node;
	one.nlookup = 1000000;
	memcpy(buf + sizeof(struct fuse_in_header), &bf, sizeof bf);
	memcpy(buf + sizeof(struct fuse_in_header) + sizeof bf,
		&one, sizeof one);
	off = sizeof bf + sizeof one;
	fuse_drive_test_reset();
	len = build_in(buf, FUSE_BATCH_FORGET, 80, FUSE_ROOT_ID, NULL, 0);
	(void)len;
	/* build_in wrote only the header for NULL body; rewrite the header
	 * length to cover the records we copied in above. */
	{
		struct fuse_in_header ih;
		memcpy(&ih, buf, sizeof ih);
		ih.len = (uint32_t)(sizeof ih + off);
		memcpy(buf, &ih, sizeof ih);
	}
	fuse_drive_test_dispatch(fd, buf, sizeof(struct fuse_in_header) + off);

	/* BATCH_FORGET emits no FUSE reply; the dropped node closes its
	 * handle, which is a CLOSE FS_REQ. */
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_CLOSE)
		FAIL("BATCH_FORGET did not close the forgotten node's handle");

	/* A fresh LOOKUP of the same name must now re-open (node was freed). */
	fuse_drive_test_reset();
	len = build_in(buf, FUSE_LOOKUP, 81, DRIVE_C_NODE,
		name, strlen(name) + 1);
	fuse_drive_test_dispatch(fd, buf, len);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_OPEN)
		FAIL("post-BATCH_FORGET LOOKUP did not re-issue an OPEN");
	printf("  batch_forget: node freed, handle closed, re-lookup "
		"re-opens ok\n");
}

int
main(void)
{
	struct fuse_drive *fd = fuse_drive_test_new();
	uint64_t child;
	uint32_t lookup_req;

	if (fd == NULL)
		FAIL("fuse_drive_test_new");

	printf("fuse_drive_test:\n");
	test_init(fd);
	test_getattr_root(fd);
	test_readdir_root(fd);
	lookup_req = (uint32_t)test_lookup_emits_open(fd);
	test_lookup_open_reply(fd, lookup_req);
	/* The looked-up child is the next node after the two drives: id 4. */
	child = 4;
	test_open_node(fd, child);
	test_read(fd, child);
	test_readdir_drive(fd);
	test_bounds(fd);
	test_relookup_open(fd, child);
	test_batch_forget(fd, child);

	fuse_drive_free(fd);
	printf("fuse_drive_test: all ok\n");
	return 0;
}
