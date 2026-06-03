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

#include <errno.h>
#include <fcntl.h>
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
uint32_t fuse_drive_test_req_info_class(void);
uint32_t fuse_drive_test_req_access(void);
uint32_t fuse_drive_test_req_disposition(void);
uint32_t fuse_drive_test_req_options(void);
const uint8_t *fuse_drive_test_req_payload(size_t *);
const uint8_t *fuse_drive_test_reply(size_t *);
int fuse_drive_test_reply_writes(void);
uint64_t fuse_drive_test_find_child(struct fuse_drive *, uint64_t,
		const char *);

/* FSCC info-class and FileAttributes constants used by the metadata tests
 * (mirrors src/channels/rdpdr.h and the FSCC bit we honour). */
#define IC_FILE_BASIC      0x00000004u
#define IC_FILE_STANDARD   0x00000005u
#define IC_FILE_EOF        0x00000014u
#define IC_FILE_RENAME     0x0000000Au
#define IC_FILE_DISP       0x0000000Du
#define FATTR_DIRECTORY    0x00000010u

/* CreateDisposition / CreateOptions mirrored from rdpdr.h for the
 * namespace-op assertions. */
#define DISP_FILE_CREATE   0x00000002u
#define OPT_DIRECTORY_FILE 0x00000001u
#define OPT_NON_DIR_FILE   0x00000040u
#define OPT_DELETE_ON_CLOSE 0x00001000u
#define ACC_DELETE         0x00010000u

static void
put32le(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static void
put64le(uint8_t *p, uint64_t v)
{
	int i;
	for (i = 0; i < 8; i++)
		p[i] = (uint8_t)(v >> (i * 8));
}

/* Feed an FS_RSP carrying a forwarded payload to the module. */
static void
feed_rsp(struct fuse_drive *fd, uint32_t req_id, uint32_t status,
		uint32_t file_id, uint32_t length,
		const uint8_t *payload, size_t payload_len)
{
	struct rdp_be_fs_rsp rsp;
	memset(&rsp, 0, sizeof rsp);
	rsp.req_id = req_id;
	rsp.status = status;
	rsp.file_id = file_id;
	rsp.length = length;
	fuse_drive_test_reset();
	fuse_drive_handle_fs_rsp(fd, &rsp, payload, payload_len);
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
	/* The dirent batch must reach the kernel in one write. */
	if (fuse_drive_test_reply_writes() != 1)
		FAIL("root READDIR used %d writes, want 1",
			fuse_drive_test_reply_writes());
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

/* A FILETIME for 2000-01-01 00:00:00 UTC and its unix-seconds image. */
#define MTIME_FILETIME  125911584000000000ull
#define MTIME_UNIX_SEC  946684800ull

/*
 * Drive the getattr chain that a LOOKUP/GETATTR starts.  open_req is the
 * req_id of the already-emitted OPEN; this feeds the OPEN success (with
 * file_id), then the FileStandardInformation reply (EndOfFile=size,
 * Directory flag), then the FileBasicInformation reply (LastWriteTime),
 * asserting the query the module emits at each step.  The final FUSE
 * reply (entry or attr) is left in the capture for the caller to read.
 */
static void
drive_getattr_chain(struct fuse_drive *fd, uint32_t open_req,
		uint32_t file_id, uint64_t size, int directory)
{
	uint32_t std_req, basic_req;
	uint8_t std[4 + 24];
	uint8_t basic[4 + 36];

	/* OPEN completion must emit the FileStandardInformation query. */
	feed_rsp(fd, open_req, STATUS_SUCCESS, file_id, 0, NULL, 0);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_QUERY_INFO)
		FAIL("getattr chain: OPEN did not emit a QUERY_INFO");
	if (fuse_drive_test_req_info_class() != IC_FILE_STANDARD)
		FAIL("getattr chain: first query class 0x%x not Standard",
			fuse_drive_test_req_info_class());
	if (fuse_drive_test_req_file_id() != file_id)
		FAIL("getattr chain: query file_id 0x%x",
			fuse_drive_test_req_file_id());
	std_req = fuse_drive_test_req_id();

	/* Canned FileStandardInformation: Length(u32) + 24-byte struct. */
	memset(std, 0, sizeof std);
	put32le(std, 24);
	put64le(std + 4 + 8, size);                 /* EndOfFile */
	std[4 + 21] = (uint8_t)(directory ? 1 : 0); /* Directory (+21) */

	/* The Standard reply must chain to the FileBasicInformation query. */
	feed_rsp(fd, std_req, STATUS_SUCCESS, 0, 0, std, sizeof std);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_QUERY_INFO)
		FAIL("getattr chain: Standard reply did not emit a QUERY_INFO");
	if (fuse_drive_test_req_info_class() != IC_FILE_BASIC)
		FAIL("getattr chain: second query class 0x%x not Basic",
			fuse_drive_test_req_info_class());
	basic_req = fuse_drive_test_req_id();

	/* Canned FileBasicInformation: Length(u32) + 36-byte struct with a
	 * known LastWriteTime and the directory attribute reflecting the
	 * Standard reply (the module keys is_dir off Basic FileAttributes). */
	memset(basic, 0, sizeof basic);
	put32le(basic, 36);
	put64le(basic + 4 + 16, MTIME_FILETIME);    /* LastWriteTime */
	put32le(basic + 4 + 32, directory ? FATTR_DIRECTORY : 0);

	/* The Basic reply produces the final FUSE reply, left in the capture. */
	feed_rsp(fd, basic_req, STATUS_SUCCESS, 0, 0, basic, sizeof basic);
}

/*
 * Feed an OPEN success FS_RSP and drive the getattr chain the LOOKUP now
 * starts (OPEN -> Standard -> Basic), then check the resulting
 * fuse_entry_out carries the real size, S_IFREG, and converted mtime.
 */
static void
test_lookup_open_reply(struct fuse_drive *fd, uint32_t req_id)
{
	struct fuse_entry_out eo;
	struct fuse_out_header oh;
	size_t rlen;
	const uint8_t *r;

	drive_getattr_chain(fd, req_id, 0x4242, 12345, 0);

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
	if ((eo.attr.mode & S_IFMT) != S_IFREG)
		FAIL("LOOKUP attr not S_IFREG, mode 0%o", eo.attr.mode);
	if (eo.attr.size != 12345)
		FAIL("LOOKUP attr size %llu != 12345",
			(unsigned long long)eo.attr.size);
	if (eo.attr.mtime != MTIME_UNIX_SEC)
		FAIL("LOOKUP attr mtime %llu != %llu",
			(unsigned long long)eo.attr.mtime,
			(unsigned long long)MTIME_UNIX_SEC);
	printf("  lookup reply: getattr chain -> nodeid %llu size 12345 "
		"S_IFREG mtime ok\n", (unsigned long long)eo.nodeid);
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
		/* The kernel reads each reply as one message; a data-bearing
		 * reply must be a single write_reply (header + body together). */
		if (fuse_drive_test_reply_writes() != 1)
			FAIL("READ reply used %d writes, want 1",
				fuse_drive_test_reply_writes());
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
		if (fuse_drive_test_reply_writes() != 1)
			FAIL("drive READDIR used %d writes, want 1",
				fuse_drive_test_reply_writes());
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

		/* Open a regular file under DOCS first; the LOOKUP starts the
		 * getattr chain, so drive it to completion (file_id 0x55) and
		 * read the assigned nodeid from the entry reply. */
		fuse_drive_test_reset();
		len2 = build_in(buf2, FUSE_LOOKUP, 60, 3,
			"x", strlen("x") + 1);
		fuse_drive_test_dispatch(fd, buf2, len2);
		rreq = fuse_drive_test_req_id();
		drive_getattr_chain(fd, rreq, 0x55, 0, 0);
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

/*
 * Re-LOOKUP of an already-open node reuses the RDPDR handle (it does not
 * re-OPEN) but still refreshes metadata over the held handle, so it emits
 * a QUERY_INFO directly rather than an OPEN.  Feeding the Standard/Basic
 * replies yields the entry for the same nodeid.
 */
static void
test_relookup_open(struct fuse_drive *fd, uint64_t child_node)
{
	uint8_t buf[256];
	const char *name = "file.txt";
	struct fuse_out_header oh;
	struct fuse_entry_out eo;
	uint32_t std_req, basic_req;
	uint8_t std[4 + 24];
	uint8_t basic[4 + 36];
	size_t len, rlen;
	const uint8_t *r;

	fuse_drive_test_reset();
	len = build_in(buf, FUSE_LOOKUP, 70, DRIVE_C_NODE,
		name, strlen(name) + 1);
	fuse_drive_test_dispatch(fd, buf, len);

	/* No OPEN: the held handle is reused, so the first emit is the
	 * FileStandardInformation query straight away. */
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_QUERY_INFO)
		FAIL("re-LOOKUP did not query over the held handle");
	if (fuse_drive_test_req_op() == RDP_FS_OPEN)
		FAIL("re-LOOKUP re-issued an OPEN for an already-open node");
	if (fuse_drive_test_req_info_class() != IC_FILE_STANDARD)
		FAIL("re-LOOKUP first query not Standard");
	std_req = fuse_drive_test_req_id();

	memset(std, 0, sizeof std);
	put32le(std, 24);
	put64le(std + 4 + 8, 12345);
	feed_rsp(fd, std_req, STATUS_SUCCESS, 0, 0, std, sizeof std);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_info_class() != IC_FILE_BASIC)
		FAIL("re-LOOKUP did not chain to Basic");
	basic_req = fuse_drive_test_req_id();

	memset(basic, 0, sizeof basic);
	put32le(basic, 36);
	put64le(basic + 4 + 16, MTIME_FILETIME);
	feed_rsp(fd, basic_req, STATUS_SUCCESS, 0, 0, basic, sizeof basic);

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
	printf("  re-lookup file.txt: handle reused, metadata refreshed, "
		"no new OPEN ok\n");
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

/*
 * LOOKUP a fresh file under drive C and drive its getattr chain so the
 * node ends up open read-only with the given file_id.  Returns the
 * assigned nodeid.  Used to set up the write/setattr tests on an
 * independent node.
 */
static uint64_t
lookup_open_file(struct fuse_drive *fd, const char *name, uint32_t file_id,
		uint64_t unique)
{
	uint8_t buf[256];
	struct fuse_entry_out eo;
	struct fuse_out_header oh;
	uint32_t open_req;
	size_t len, rlen;
	const uint8_t *r;

	fuse_drive_test_reset();
	len = build_in(buf, FUSE_LOOKUP, unique, DRIVE_C_NODE,
		name, strlen(name) + 1);
	fuse_drive_test_dispatch(fd, buf, len);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_OPEN)
		FAIL("lookup_open_file('%s') did not emit an OPEN", name);
	open_req = fuse_drive_test_req_id();
	drive_getattr_chain(fd, open_req, file_id, 0, 0);
	get_out(&oh);
	if (oh.error != 0)
		FAIL("lookup_open_file('%s') entry error %d", name, oh.error);
	r = fuse_drive_test_reply(&rlen);
	if (rlen != sizeof oh + sizeof eo)
		FAIL("lookup_open_file('%s') entry size %zu", name, rlen);
	memcpy(&eo, r + sizeof oh, sizeof eo);
	return eo.nodeid;
}

/* --- FUSE_OPEN with O_WRONLY requests FILE_WRITE_DATA --- */
static void
test_open_wronly(struct fuse_drive *fd, uint64_t node, uint32_t new_file_id)
{
	uint8_t buf[256];
	struct fuse_open_in oi;
	size_t len;

	/* The node is currently open read-only (from lookup_open_file), so an
	 * O_WRONLY open upgrades: it closes and reopens with write access. */
	memset(&oi, 0, sizeof oi);
	oi.flags = O_WRONLY;
	fuse_drive_test_reset();
	len = build_in(buf, FUSE_OPEN, 200, node, &oi, sizeof oi);
	fuse_drive_test_dispatch(fd, buf, len);

	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_OPEN)
		FAIL("O_WRONLY open did not emit an OPEN FS_REQ");
	if ((fuse_drive_test_req_access() & FILE_WRITE_DATA) == 0)
		FAIL("O_WRONLY open access 0x%x lacks FILE_WRITE_DATA",
			fuse_drive_test_req_access());
	printf("  open O_WRONLY: OPEN desired_access 0x%x includes "
		"FILE_WRITE_DATA ok\n", fuse_drive_test_req_access());

	/* Complete the reopen so the node is write-open for the write test. */
	{
		struct fuse_out_header oh;
		uint32_t open_req = fuse_drive_test_req_id();
		feed_rsp(fd, open_req, STATUS_SUCCESS, new_file_id, 0, NULL, 0);
		get_out(&oh);
		if (oh.error != 0)
			FAIL("O_WRONLY open reply error %d", oh.error);
	}
}

/* --- FUSE_WRITE emits RDP_FS_WRITE and reports bytes written --- */
static void
test_write(struct fuse_drive *fd, uint64_t node, uint32_t file_id)
{
	uint8_t buf[256];
	struct fuse_write_in wi;
	const uint8_t data[5] = { 'h', 'e', 'l', 'l', 'o' };
	uint32_t write_req;
	size_t plen;
	const uint8_t *pl;

	memset(&wi, 0, sizeof wi);
	wi.fh = node;
	wi.offset = 100;
	wi.size = 5;
	fuse_drive_test_reset();
	(void)build_in(buf, FUSE_WRITE, 210, node, &wi, sizeof wi);
	/* Append the 5 write-data bytes after the fuse_write_in. */
	memcpy(buf + sizeof(struct fuse_in_header) + sizeof wi, data, 5);
	{
		struct fuse_in_header ih;
		memcpy(&ih, buf, sizeof ih);
		ih.len = (uint32_t)(sizeof ih + sizeof wi + 5);
		memcpy(buf, &ih, sizeof ih);
	}
	fuse_drive_test_dispatch(fd, buf, sizeof(struct fuse_in_header)
		+ sizeof wi + 5);

	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_WRITE)
		FAIL("FUSE_WRITE did not emit an RDP_FS_WRITE");
	if (fuse_drive_test_req_file_id() != file_id)
		FAIL("WRITE file_id 0x%x != 0x%x",
			fuse_drive_test_req_file_id(), file_id);
	if (fuse_drive_test_req_offset() != 100)
		FAIL("WRITE offset %llu != 100",
			(unsigned long long)fuse_drive_test_req_offset());
	pl = fuse_drive_test_req_payload(&plen);
	if (plen != 5 || memcmp(pl, data, 5) != 0)
		FAIL("WRITE payload (%zu bytes) mismatch", plen);
	write_req = fuse_drive_test_req_id();

	/* DR_WRITE_RSP: Length(u32)=bytes written, then a Padding byte. */
	{
		struct fuse_out_header oh;
		struct fuse_write_out wo;
		uint8_t rsp_pl[5];
		size_t rlen;
		const uint8_t *r;
		put32le(rsp_pl, 5);
		rsp_pl[4] = 0;
		feed_rsp(fd, write_req, STATUS_SUCCESS, 0, 5,
			rsp_pl, sizeof rsp_pl);
		get_out(&oh);
		if (oh.error != 0)
			FAIL("WRITE reply error %d", oh.error);
		r = fuse_drive_test_reply(&rlen);
		if (rlen != sizeof oh + sizeof wo)
			FAIL("WRITE reply size %zu", rlen);
		memcpy(&wo, r + sizeof oh, sizeof wo);
		if (wo.size != 5)
			FAIL("WRITE reported %u bytes != 5", wo.size);
	}
	printf("  write: RDP_FS_WRITE offset 100 + 5-byte payload, "
		"fuse_write_out.size==5 ok\n");
}

/* --- FUSE_SETATTR FATTR_SIZE=0 emits a FileEndOfFileInformation set --- */
static void
test_setattr_truncate(struct fuse_drive *fd, uint64_t node)
{
	uint8_t buf[256];
	struct fuse_setattr_in si;
	size_t len, plen;
	const uint8_t *pl;
	uint32_t set_req;

	memset(&si, 0, sizeof si);
	si.valid = FATTR_SIZE;
	si.size = 0;
	fuse_drive_test_reset();
	len = build_in(buf, FUSE_SETATTR, 220, node, &si, sizeof si);
	fuse_drive_test_dispatch(fd, buf, len);

	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_SET_INFO)
		FAIL("SETATTR size did not emit an RDP_FS_SET_INFO");
	if (fuse_drive_test_req_info_class() != IC_FILE_EOF)
		FAIL("SETATTR info_class 0x%x not FileEndOfFileInformation",
			fuse_drive_test_req_info_class());
	pl = fuse_drive_test_req_payload(&plen);
	if (plen != 8)
		FAIL("SETATTR EOF SetBuffer %zu bytes != 8", plen);
	{
		uint64_t eof = 0;
		int i;
		for (i = 0; i < 8; i++)
			eof |= (uint64_t)pl[i] << (i * 8);
		if (eof != 0)
			FAIL("SETATTR EndOfFile %llu != 0",
				(unsigned long long)eof);
	}
	set_req = fuse_drive_test_req_id();

	/* Completing the set triggers a re-query (Standard) for the new attr. */
	{
		uint8_t rsp_pl[5];
		put32le(rsp_pl, 0);
		rsp_pl[4] = 0;
		feed_rsp(fd, set_req, STATUS_SUCCESS, 0, 0, rsp_pl, sizeof rsp_pl);
		if (!fuse_drive_test_have_req()
		    || fuse_drive_test_req_op() != RDP_FS_QUERY_INFO
		    || fuse_drive_test_req_info_class() != IC_FILE_STANDARD)
			FAIL("SETATTR did not re-query after the set");
	}
	printf("  setattr truncate: RDP_FS_SET_INFO "
		"FileEndOfFileInformation EndOfFile==0 ok\n");
}

/* Open `node` with the given open(2) flags; the held handle already covers
 * the access so the reuse fast-path replies immediately and emits no
 * FS_REQ.  Asserts the open_out fh matches the node. */
static void
open_reuse(struct fuse_drive *fd, uint64_t node, uint32_t oflags,
		uint64_t unique)
{
	uint8_t buf[256];
	struct fuse_open_in oi;
	struct fuse_out_header oh;
	struct fuse_open_out oo;
	size_t len, rlen;
	const uint8_t *r;

	memset(&oi, 0, sizeof oi);
	oi.flags = oflags;
	fuse_drive_test_reset();
	len = build_in(buf, FUSE_OPEN, unique, node, &oi, sizeof oi);
	fuse_drive_test_dispatch(fd, buf, len);
	if (fuse_drive_test_have_req())
		FAIL("open_reuse: reuse fast-path emitted an FS_REQ");
	get_out(&oh);
	if (oh.error != 0)
		FAIL("open_reuse: error %d", oh.error);
	r = fuse_drive_test_reply(&rlen);
	if (rlen != sizeof oh + sizeof oo)
		FAIL("open_reuse: reply size %zu", rlen);
	memcpy(&oo, r + sizeof oh, sizeof oo);
	if (oo.fh != node)
		FAIL("open_reuse: fh %llu != %llu",
			(unsigned long long)oo.fh, (unsigned long long)node);
}

/* Send a FUSE_RELEASE for `node` and return whether it emitted a CLOSE. */
static int
release_emits_close(struct fuse_drive *fd, uint64_t node, uint64_t unique)
{
	uint8_t buf[256];
	struct fuse_release_in rl;
	struct fuse_out_header oh;
	size_t len;

	memset(&rl, 0, sizeof rl);
	rl.fh = node;
	fuse_drive_test_reset();
	len = build_in(buf, FUSE_RELEASE, unique, node, &rl, sizeof rl);
	fuse_drive_test_dispatch(fd, buf, len);
	get_out(&oh);
	if (oh.error != 0)
		FAIL("RELEASE error %d", oh.error);
	return fuse_drive_test_have_req()
		&& fuse_drive_test_req_op() == RDP_FS_CLOSE;
}

/*
 * Open refcount: two opens of the same node share one RDPDR handle, so the
 * first RELEASE must NOT close it (another fd is still open) and a read on
 * the surviving fd must still issue an RDP_FS_READ.  The second RELEASE
 * (last fd) then closes the handle.
 */
static void
test_open_refcount(struct fuse_drive *fd, uint64_t node, uint32_t file_id)
{
	uint8_t buf[256];
	struct fuse_read_in ri;
	size_t len;

	/* The node is open read-only from lookup_open_file.  Two read opens
	 * both reuse the held handle, raising open_refs to 2. */
	open_reuse(fd, node, O_RDONLY, 400);
	open_reuse(fd, node, O_RDONLY, 401);

	/* First RELEASE drops refs 2 -> 1: the shared handle must survive. */
	if (release_emits_close(fd, node, 402))
		FAIL("first RELEASE closed a still-shared handle");

	/* A read on the surviving fd must still reach the client. */
	memset(&ri, 0, sizeof ri);
	ri.fh = node;
	ri.offset = 0;
	ri.size = 4;
	fuse_drive_test_reset();
	len = build_in(buf, FUSE_READ, 403, node, &ri, sizeof ri);
	fuse_drive_test_dispatch(fd, buf, len);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_READ)
		FAIL("read after first RELEASE did not issue RDP_FS_READ");
	if (fuse_drive_test_req_file_id() != file_id)
		FAIL("read after RELEASE file_id 0x%x != 0x%x",
			fuse_drive_test_req_file_id(), file_id);
	/* Drain the read so the in-flight slot is freed. */
	{
		struct rdp_be_fs_rsp rsp;
		uint8_t pl[4 + 4] = { 0 };
		uint32_t rreq = fuse_drive_test_req_id();
		put32le(pl, 4);
		memset(&rsp, 0, sizeof rsp);
		rsp.req_id = rreq;
		rsp.status = STATUS_SUCCESS;
		rsp.length = 4;
		fuse_drive_test_reset();
		fuse_drive_handle_fs_rsp(fd, &rsp, pl, sizeof pl);
	}

	/* Second RELEASE drops refs 1 -> 0: now the handle closes. */
	if (!release_emits_close(fd, node, 404))
		FAIL("last RELEASE did not close the handle");

	printf("  open refcount: two opens share one handle, first RELEASE "
		"keeps it (read ok), last RELEASE closes ok\n");
}

/*
 * Combined size + time SETATTR.  A single SETATTR carrying both FATTR_SIZE
 * and FATTR_MTIME must emit BOTH a FileEndOfFileInformation set and then a
 * FileBasicInformation set, and produce exactly one fuse_attr_out reply.
 */
static void
test_setattr_size_and_time(struct fuse_drive *fd, uint64_t node)
{
	uint8_t buf[256];
	struct fuse_setattr_in si;
	size_t len, plen;
	const uint8_t *pl;
	uint32_t eof_req, basic_req, std_req;

	memset(&si, 0, sizeof si);
	si.valid = FATTR_SIZE | FATTR_MTIME;
	si.size = 1234;
	si.mtime = MTIME_UNIX_SEC;
	si.mtimensec = 0;
	fuse_drive_test_reset();
	len = build_in(buf, FUSE_SETATTR, 230, node, &si, sizeof si);
	fuse_drive_test_dispatch(fd, buf, len);

	/* Step 1: the EOF set goes first, tagged so its reply finishes the op. */
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_SET_INFO)
		FAIL("combined SETATTR did not emit a SET_INFO first");
	if (fuse_drive_test_req_info_class() != IC_FILE_EOF)
		FAIL("combined SETATTR first set 0x%x not EOF",
			fuse_drive_test_req_info_class());
	pl = fuse_drive_test_req_payload(&plen);
	if (plen != 8)
		FAIL("combined SETATTR EOF SetBuffer %zu != 8", plen);
	{
		uint64_t eof = 0;
		int i;
		for (i = 0; i < 8; i++)
			eof |= (uint64_t)pl[i] << (i * 8);
		if (eof != 1234)
			FAIL("combined SETATTR EndOfFile %llu != 1234",
				(unsigned long long)eof);
	}
	eof_req = fuse_drive_test_req_id();

	/* Step 2: completing the EOF set must emit the FileBasicInformation
	 * set carrying the requested LastWriteTime, NOT a re-query yet. */
	{
		uint8_t rsp_pl[5];
		put32le(rsp_pl, 0);
		rsp_pl[4] = 0;
		feed_rsp(fd, eof_req, STATUS_SUCCESS, 0, 0, rsp_pl, sizeof rsp_pl);
	}
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_SET_INFO)
		FAIL("combined SETATTR EOF completion did not emit the time set");
	if (fuse_drive_test_req_info_class() != IC_FILE_BASIC)
		FAIL("combined SETATTR second set 0x%x not Basic",
			fuse_drive_test_req_info_class());
	pl = fuse_drive_test_req_payload(&plen);
	if (plen != 36)
		FAIL("combined SETATTR Basic SetBuffer %zu != 36", plen);
	{
		uint64_t lwt = 0;
		int i;
		for (i = 0; i < 8; i++)
			lwt |= (uint64_t)pl[16 + i] << (i * 8);
		if (lwt != MTIME_FILETIME)
			FAIL("combined SETATTR LastWriteTime %llu != %llu",
				(unsigned long long)lwt,
				(unsigned long long)MTIME_FILETIME);
	}
	basic_req = fuse_drive_test_req_id();

	/* Step 3: completing the time set must run the single re-query
	 * (Standard) whose chain produces the one fuse reply. */
	{
		uint8_t rsp_pl[5];
		put32le(rsp_pl, 0);
		rsp_pl[4] = 0;
		feed_rsp(fd, basic_req, STATUS_SUCCESS, 0, 0, rsp_pl, sizeof rsp_pl);
	}
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_QUERY_INFO
	    || fuse_drive_test_req_info_class() != IC_FILE_STANDARD)
		FAIL("combined SETATTR did not re-query after the time set");
	std_req = fuse_drive_test_req_id();

	/* Drive the re-query chain to the single fuse_attr_out reply. */
	{
		uint8_t std[4 + 24];
		uint8_t basic[4 + 36];
		uint32_t bq;
		struct fuse_out_header oh;
		struct fuse_attr_out ao;
		size_t rlen;
		const uint8_t *r;

		memset(std, 0, sizeof std);
		put32le(std, 24);
		put64le(std + 4 + 8, 1234);
		feed_rsp(fd, std_req, STATUS_SUCCESS, 0, 0, std, sizeof std);
		if (!fuse_drive_test_have_req()
		    || fuse_drive_test_req_info_class() != IC_FILE_BASIC)
			FAIL("combined SETATTR re-query did not chain to Basic");
		bq = fuse_drive_test_req_id();

		memset(basic, 0, sizeof basic);
		put32le(basic, 36);
		put64le(basic + 4 + 16, MTIME_FILETIME);
		feed_rsp(fd, bq, STATUS_SUCCESS, 0, 0, basic, sizeof basic);

		get_out(&oh);
		if (oh.error != 0)
			FAIL("combined SETATTR final reply error %d", oh.error);
		if (oh.unique != 230)
			FAIL("combined SETATTR reply unique %llu",
				(unsigned long long)oh.unique);
		r = fuse_drive_test_reply(&rlen);
		if (rlen != sizeof oh + sizeof ao)
			FAIL("combined SETATTR reply size %zu (not one attr_out)",
				rlen);
		memcpy(&ao, r + sizeof oh, sizeof ao);
		if (ao.attr.size != 1234)
			FAIL("combined SETATTR reply size %llu != 1234",
				(unsigned long long)ao.attr.size);
		if (ao.attr.mtime != MTIME_UNIX_SEC)
			FAIL("combined SETATTR reply mtime %llu != %llu",
				(unsigned long long)ao.attr.mtime,
				(unsigned long long)MTIME_UNIX_SEC);
	}
	printf("  setattr size+time: EOF set then Basic set, single "
		"attr_out reply (size 1234, mtime) ok\n");
}

/*
 * Bounds: truncated FileStandardInformation (<24) and FileBasicInformation
 * (<36) FSCC buffers, and a FUSE_WRITE claiming more data than present,
 * must not over-read (ASan/UBSan fails the run on any OOB).  The getattr
 * chain must still produce a well-formed reply with the fallback attr.
 */
static void
test_bounds_meta(struct fuse_drive *fd)
{
	uint8_t buf[256];
	struct fuse_out_header oh;
	uint64_t node;
	uint32_t open_req, std_req, basic_req;

	/* LOOKUP a fresh file; drive OPEN then feed SHORT Standard/Basic. */
	fuse_drive_test_reset();
	{
		const char *nm = "short.bin";
		size_t len = build_in(buf, FUSE_LOOKUP, 300, DRIVE_C_NODE,
			nm, strlen(nm) + 1);
		fuse_drive_test_dispatch(fd, buf, len);
	}
	open_req = fuse_drive_test_req_id();
	feed_rsp(fd, open_req, STATUS_SUCCESS, 0x301, 0, NULL, 0);
	if (fuse_drive_test_req_info_class() != IC_FILE_STANDARD)
		FAIL("bounds_meta: OPEN did not emit Standard query");
	std_req = fuse_drive_test_req_id();

	/* Truncated FileStandardInformation: Length claims 24 but only 10
	 * bytes follow.  The decode must clamp and still chain to Basic. */
	{
		uint8_t pl[4 + 10];
		memset(pl, 0xAB, sizeof pl);
		put32le(pl, 24);   /* over-claims the inner buffer */
		feed_rsp(fd, std_req, STATUS_SUCCESS, 0, 0, pl, sizeof pl);
	}
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_info_class() != IC_FILE_BASIC)
		FAIL("bounds_meta: short Standard did not chain to Basic");
	basic_req = fuse_drive_test_req_id();

	/* Truncated FileBasicInformation: Length claims 36 but only 12 bytes
	 * follow.  The decode must clamp and still produce the final reply. */
	{
		uint8_t pl[4 + 12];
		memset(pl, 0xCD, sizeof pl);
		put32le(pl, 36);   /* over-claims the inner buffer */
		feed_rsp(fd, basic_req, STATUS_SUCCESS, 0, 0, pl, sizeof pl);
	}
	get_out(&oh);   /* well-formed entry reply, no crash */
	if (oh.error != 0)
		FAIL("bounds_meta: short Basic reply error %d", oh.error);

	/* Read the assigned nodeid from the entry to drive the over-claimed
	 * write against an open, writable handle. */
	{
		struct fuse_entry_out eo;
		size_t rlen;
		const uint8_t *r = fuse_drive_test_reply(&rlen);
		if (rlen != sizeof oh + sizeof eo)
			FAIL("bounds_meta: entry size %zu", rlen);
		memcpy(&eo, r + sizeof oh, sizeof eo);
		node = eo.nodeid;
	}

	/* Upgrade the handle to write access so the write is accepted. */
	{
		struct fuse_open_in oi;
		size_t len;
		uint32_t req;
		memset(&oi, 0, sizeof oi);
		oi.flags = O_WRONLY;
		fuse_drive_test_reset();
		len = build_in(buf, FUSE_OPEN, 310, node, &oi, sizeof oi);
		fuse_drive_test_dispatch(fd, buf, len);
		req = fuse_drive_test_req_id();
		feed_rsp(fd, req, STATUS_SUCCESS, 0x302, 0, NULL, 0);
		get_out(&oh);
	}

	/* FUSE_WRITE whose declared size exceeds the bytes actually present
	 * in the request body.  The handler must clamp size to the available
	 * trailing bytes and never over-read. */
	{
		struct fuse_write_in wi;
		size_t hdr = sizeof(struct fuse_in_header);
		size_t total;
		size_t plen;
		const uint8_t *pl;
		memset(&wi, 0, sizeof wi);
		wi.fh = node;
		wi.offset = 0;
		wi.size = 0x10000;   /* claims 64 KiB */
		(void)build_in(buf, FUSE_WRITE, 320, node, &wi, sizeof wi);
		/* Only 3 real data bytes follow the fuse_write_in. */
		buf[hdr + sizeof wi + 0] = 0x11;
		buf[hdr + sizeof wi + 1] = 0x22;
		buf[hdr + sizeof wi + 2] = 0x33;
		total = hdr + sizeof wi + 3;
		{
			struct fuse_in_header ih;
			memcpy(&ih, buf, sizeof ih);
			ih.len = (uint32_t)total;
			memcpy(buf, &ih, sizeof ih);
		}
		fuse_drive_test_reset();
		fuse_drive_test_dispatch(fd, buf, total);
		if (!fuse_drive_test_have_req()
		    || fuse_drive_test_req_op() != RDP_FS_WRITE)
			FAIL("bounds_meta: over-claimed WRITE no FS_REQ");
		pl = fuse_drive_test_req_payload(&plen);
		if (plen != 3)
			FAIL("bounds_meta: WRITE not clamped to 3 bytes (%zu)",
				plen);
		(void)pl;
	}
	printf("  bounds_meta: short Standard/Basic + over-claimed WRITE "
		"clamped, no over-read ok\n");
}

/*
 * FUSE_CREATE under a drive emits an OPEN with disposition FILE_CREATE and
 * write access; the success completion yields a reply containing
 * fuse_entry_out immediately followed by fuse_open_out (correct total
 * length, fh set to the new node id).
 */
static void
test_create(struct fuse_drive *fd)
{
	uint8_t buf[256];
	struct fuse_create_in ci;
	struct fuse_out_header oh;
	struct fuse_entry_out eo;
	struct fuse_open_out oo;
	const char *name = "new.txt";
	size_t len, plen, hdr;
	const uint8_t *r, *pl;
	uint32_t open_req;
	size_t rlen;

	memset(&ci, 0, sizeof ci);
	ci.flags = O_RDWR;
	ci.mode = S_IFREG | 0644;
	hdr = sizeof(struct fuse_in_header);
	fuse_drive_test_reset();
	(void)build_in(buf, FUSE_CREATE, 500, DRIVE_C_NODE, &ci, sizeof ci);
	memcpy(buf + hdr + sizeof ci, name, strlen(name) + 1);
	{
		struct fuse_in_header ih;
		memcpy(&ih, buf, sizeof ih);
		ih.len = (uint32_t)(hdr + sizeof ci + strlen(name) + 1);
		memcpy(buf, &ih, sizeof ih);
		len = ih.len;
	}
	fuse_drive_test_dispatch(fd, buf, len);

	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_OPEN)
		FAIL("CREATE did not emit an OPEN FS_REQ");
	if (fuse_drive_test_req_disposition() != DISP_FILE_CREATE)
		FAIL("CREATE disposition 0x%x != FILE_CREATE",
			fuse_drive_test_req_disposition());
	if ((fuse_drive_test_req_access() & FILE_WRITE_DATA) == 0)
		FAIL("CREATE access 0x%x lacks FILE_WRITE_DATA",
			fuse_drive_test_req_access());
	if ((fuse_drive_test_req_options() & OPT_NON_DIR_FILE) == 0)
		FAIL("CREATE options 0x%x lacks FILE_NON_DIRECTORY_FILE",
			fuse_drive_test_req_options());
	pl = fuse_drive_test_req_payload(&plen);
	if (plen == 0 || strcmp((const char *)pl, "\\new.txt") != 0)
		FAIL("CREATE path '%.*s'", (int)plen, pl);
	open_req = fuse_drive_test_req_id();

	/* The create OPEN succeeds with a handle. */
	feed_rsp(fd, open_req, STATUS_SUCCESS, 0x600, 0, NULL, 0);
	get_out(&oh);
	if (oh.error != 0)
		FAIL("CREATE reply error %d", oh.error);
	if (oh.unique != 500)
		FAIL("CREATE reply unique %llu", (unsigned long long)oh.unique);
	r = fuse_drive_test_reply(&rlen);
	if (rlen != sizeof oh + sizeof eo + sizeof oo)
		FAIL("CREATE reply size %zu (not entry_out+open_out)", rlen);
	memcpy(&eo, r + sizeof oh, sizeof eo);
	memcpy(&oo, r + sizeof oh + sizeof eo, sizeof oo);
	if (eo.nodeid == 0 || eo.nodeid == FUSE_ROOT_ID)
		FAIL("CREATE child nodeid %llu",
			(unsigned long long)eo.nodeid);
	if ((eo.attr.mode & S_IFMT) != S_IFREG)
		FAIL("CREATE attr not S_IFREG, mode 0%o", eo.attr.mode);
	if (eo.attr.size != 0)
		FAIL("CREATE fresh file size %llu != 0",
			(unsigned long long)eo.attr.size);
	if (oo.fh != eo.nodeid)
		FAIL("CREATE open_out fh %llu != nodeid %llu",
			(unsigned long long)oo.fh,
			(unsigned long long)eo.nodeid);
	printf("  create new.txt: OPEN FILE_CREATE write access, reply "
		"entry_out+open_out fh set ok\n");
}

/*
 * FUSE_MKDIR emits an OPEN with options FILE_DIRECTORY_FILE and disposition
 * FILE_CREATE; the success completion closes the handle and replies
 * fuse_entry_out with an S_IFDIR attr.
 */
static void
test_mkdir(struct fuse_drive *fd)
{
	uint8_t buf[256];
	struct fuse_mkdir_in mi;
	struct fuse_out_header oh;
	struct fuse_entry_out eo;
	const char *name = "newdir";
	size_t len, hdr, rlen;
	const uint8_t *r;
	uint32_t open_req;

	memset(&mi, 0, sizeof mi);
	mi.mode = 0755;
	hdr = sizeof(struct fuse_in_header);
	fuse_drive_test_reset();
	(void)build_in(buf, FUSE_MKDIR, 510, DRIVE_C_NODE, &mi, sizeof mi);
	memcpy(buf + hdr + sizeof mi, name, strlen(name) + 1);
	{
		struct fuse_in_header ih;
		memcpy(&ih, buf, sizeof ih);
		ih.len = (uint32_t)(hdr + sizeof mi + strlen(name) + 1);
		memcpy(buf, &ih, sizeof ih);
		len = ih.len;
	}
	fuse_drive_test_dispatch(fd, buf, len);

	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_OPEN)
		FAIL("MKDIR did not emit an OPEN FS_REQ");
	if (fuse_drive_test_req_disposition() != DISP_FILE_CREATE)
		FAIL("MKDIR disposition 0x%x != FILE_CREATE",
			fuse_drive_test_req_disposition());
	if ((fuse_drive_test_req_options() & OPT_DIRECTORY_FILE) == 0)
		FAIL("MKDIR options 0x%x lacks FILE_DIRECTORY_FILE",
			fuse_drive_test_req_options());
	open_req = fuse_drive_test_req_id();

	/* The mkdir OPEN succeeds with a handle; the completion closes it and
	 * replies the entry.  The CLOSE overwrites the captured FS_REQ. */
	feed_rsp(fd, open_req, STATUS_SUCCESS, 0x610, 0, NULL, 0);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_CLOSE)
		FAIL("MKDIR did not close the create handle");
	get_out(&oh);
	if (oh.error != 0)
		FAIL("MKDIR reply error %d", oh.error);
	r = fuse_drive_test_reply(&rlen);
	if (rlen != sizeof oh + sizeof eo)
		FAIL("MKDIR reply size %zu (not one entry_out)", rlen);
	memcpy(&eo, r + sizeof oh, sizeof eo);
	if ((eo.attr.mode & S_IFMT) != S_IFDIR)
		FAIL("MKDIR attr not S_IFDIR, mode 0%o", eo.attr.mode);
	printf("  mkdir newdir: OPEN FILE_CREATE FILE_DIRECTORY_FILE, close, "
		"entry_out S_IFDIR ok\n");
}

/*
 * FUSE_MKNOD of a regular file emits an OPEN with disposition FILE_CREATE,
 * closes the handle, and replies a single entry_out.  A non-regular mode is
 * rejected with -EPERM and emits no FS_REQ.
 */
static void
test_mknod(struct fuse_drive *fd)
{
	uint8_t buf[256];
	struct fuse_mknod_in mi;
	struct fuse_out_header oh;
	struct fuse_entry_out eo;
	const char *name = "node.bin";
	size_t len, hdr, rlen;
	const uint8_t *r;
	uint32_t open_req;

	/* Non-regular mode (a FIFO) must be refused with EPERM, no FS_REQ. */
	memset(&mi, 0, sizeof mi);
	mi.mode = S_IFIFO | 0644;
	hdr = sizeof(struct fuse_in_header);
	fuse_drive_test_reset();
	(void)build_in(buf, FUSE_MKNOD, 515, DRIVE_C_NODE, &mi, sizeof mi);
	memcpy(buf + hdr + sizeof mi, name, strlen(name) + 1);
	{
		struct fuse_in_header ih;
		memcpy(&ih, buf, sizeof ih);
		ih.len = (uint32_t)(hdr + sizeof mi + strlen(name) + 1);
		memcpy(buf, &ih, sizeof ih);
		len = ih.len;
	}
	fuse_drive_test_dispatch(fd, buf, len);
	if (fuse_drive_test_have_req())
		FAIL("MKNOD of a FIFO emitted an FS_REQ");
	get_out(&oh);
	if (oh.error != -EPERM)
		FAIL("MKNOD non-regular error %d != -EPERM", oh.error);

	/* A regular file is created via OPEN(FILE_CREATE), then closed. */
	memset(&mi, 0, sizeof mi);
	mi.mode = S_IFREG | 0644;
	fuse_drive_test_reset();
	(void)build_in(buf, FUSE_MKNOD, 516, DRIVE_C_NODE, &mi, sizeof mi);
	memcpy(buf + hdr + sizeof mi, name, strlen(name) + 1);
	{
		struct fuse_in_header ih;
		memcpy(&ih, buf, sizeof ih);
		ih.len = (uint32_t)(hdr + sizeof mi + strlen(name) + 1);
		memcpy(buf, &ih, sizeof ih);
		len = ih.len;
	}
	fuse_drive_test_dispatch(fd, buf, len);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_OPEN)
		FAIL("MKNOD regular did not emit an OPEN");
	if (fuse_drive_test_req_disposition() != DISP_FILE_CREATE)
		FAIL("MKNOD disposition 0x%x != FILE_CREATE",
			fuse_drive_test_req_disposition());
	open_req = fuse_drive_test_req_id();
	feed_rsp(fd, open_req, STATUS_SUCCESS, 0x620, 0, NULL, 0);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_CLOSE)
		FAIL("MKNOD did not close the create handle");
	get_out(&oh);
	if (oh.error != 0)
		FAIL("MKNOD reply error %d", oh.error);
	r = fuse_drive_test_reply(&rlen);
	if (rlen != sizeof oh + sizeof eo)
		FAIL("MKNOD reply size %zu (not one entry_out)", rlen);
	memcpy(&eo, r + sizeof oh, sizeof eo);
	if ((eo.attr.mode & S_IFMT) != S_IFREG)
		FAIL("MKNOD attr not S_IFREG, mode 0%o", eo.attr.mode);
	printf("  mknod node.bin: FIFO -> EPERM, regular -> OPEN FILE_CREATE "
		"+ close + entry_out ok\n");
}

/*
 * FUSE_UNLINK emits an OPEN(DELETE, FILE_DELETE_ON_CLOSE) then a
 * SET_INFO(FileDispositionInformation) carrying a 1-byte DeletePending=1
 * SetBuffer, then a CLOSE; the chain replies 0.
 */
static void
test_unlink(struct fuse_drive *fd)
{
	uint8_t buf[256];
	struct fuse_out_header oh;
	const char *name = "del.txt";
	size_t len, plen;
	const uint8_t *pl;
	uint32_t open_req, set_req;

	fuse_drive_test_reset();
	len = build_in(buf, FUSE_UNLINK, 520, DRIVE_C_NODE,
		name, strlen(name) + 1);
	fuse_drive_test_dispatch(fd, buf, len);

	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_OPEN)
		FAIL("UNLINK did not emit an OPEN FS_REQ");
	if ((fuse_drive_test_req_access() & ACC_DELETE) == 0)
		FAIL("UNLINK access 0x%x lacks DELETE",
			fuse_drive_test_req_access());
	if ((fuse_drive_test_req_options() & OPT_DELETE_ON_CLOSE) == 0)
		FAIL("UNLINK options 0x%x lacks FILE_DELETE_ON_CLOSE",
			fuse_drive_test_req_options());
	if ((fuse_drive_test_req_options() & OPT_NON_DIR_FILE) == 0)
		FAIL("UNLINK options 0x%x lacks FILE_NON_DIRECTORY_FILE",
			fuse_drive_test_req_options());
	open_req = fuse_drive_test_req_id();

	/* OPEN(DELETE) succeeds; the completion must emit the disposition set. */
	feed_rsp(fd, open_req, STATUS_SUCCESS, 0x630, 0, NULL, 0);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_SET_INFO)
		FAIL("UNLINK did not emit a SET_INFO after the OPEN");
	if (fuse_drive_test_req_info_class() != IC_FILE_DISP)
		FAIL("UNLINK set info_class 0x%x != FileDispositionInformation",
			fuse_drive_test_req_info_class());
	pl = fuse_drive_test_req_payload(&plen);
	if (plen != 1 || pl[0] != 1)
		FAIL("UNLINK disposition SetBuffer (%zu bytes, DeletePending %u)",
			plen, plen > 0 ? pl[0] : 0);
	set_req = fuse_drive_test_req_id();

	/* The disposition set succeeds; the completion closes (emits CLOSE)
	 * and replies 0. */
	feed_rsp(fd, set_req, STATUS_SUCCESS, 0, 0, NULL, 0);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_CLOSE)
		FAIL("UNLINK did not close the delete handle");
	get_out(&oh);
	if (oh.error != 0)
		FAIL("UNLINK reply error %d != 0", oh.error);
	if (oh.unique != 520)
		FAIL("UNLINK reply unique %llu", (unsigned long long)oh.unique);
	printf("  unlink del.txt: OPEN(DELETE) + SET FileDispositionInformation "
		"(DeletePending=1) + CLOSE, reply 0 ok\n");
}

/*
 * FUSE_RMDIR emits the same chain as UNLINK but with FILE_DIRECTORY_FILE in
 * the open options.
 */
static void
test_rmdir(struct fuse_drive *fd)
{
	uint8_t buf[256];
	struct fuse_out_header oh;
	const char *name = "deldir";
	size_t len;
	uint32_t open_req, set_req;

	fuse_drive_test_reset();
	len = build_in(buf, FUSE_RMDIR, 525, DRIVE_C_NODE,
		name, strlen(name) + 1);
	fuse_drive_test_dispatch(fd, buf, len);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_OPEN)
		FAIL("RMDIR did not emit an OPEN FS_REQ");
	if ((fuse_drive_test_req_options() & OPT_DIRECTORY_FILE) == 0)
		FAIL("RMDIR options 0x%x lacks FILE_DIRECTORY_FILE",
			fuse_drive_test_req_options());
	open_req = fuse_drive_test_req_id();
	feed_rsp(fd, open_req, STATUS_SUCCESS, 0x640, 0, NULL, 0);
	if (fuse_drive_test_req_op() != RDP_FS_SET_INFO
	    || fuse_drive_test_req_info_class() != IC_FILE_DISP)
		FAIL("RMDIR did not emit the disposition set");
	set_req = fuse_drive_test_req_id();
	feed_rsp(fd, set_req, STATUS_SUCCESS, 0, 0, NULL, 0);
	get_out(&oh);
	if (oh.error != 0)
		FAIL("RMDIR reply error %d != 0", oh.error);
	printf("  rmdir deldir: OPEN(DELETE, FILE_DIRECTORY_FILE) chain, "
		"reply 0 ok\n");
}

/*
 * FUSE_RENAME on the same device emits an OPEN(source) then a
 * SET_INFO(FileRenameInformation) whose SetBuffer carries ReplaceIfExists=1,
 * RootDirectory=0, the correct FileNameLength, and the UTF-16LE target path
 * bytes.  The chain replies 0.
 */
static void
test_rename_same_device(struct fuse_drive *fd)
{
	uint8_t buf[256];
	struct fuse_rename_in ri;
	struct fuse_out_header oh;
	const char *oldname = "src.txt";
	const char *newname = "dst.txt";
	const char *expect = "\\dst.txt";   /* dest is the drive root */
	size_t len, hdr, plen, i;
	const uint8_t *pl;
	uint32_t open_req, set_req, name_bytes;

	memset(&ri, 0, sizeof ri);
	ri.newdir = DRIVE_C_NODE;   /* same drive root as the source parent */
	hdr = sizeof(struct fuse_in_header);
	fuse_drive_test_reset();
	(void)build_in(buf, FUSE_RENAME, 530, DRIVE_C_NODE, &ri, sizeof ri);
	memcpy(buf + hdr + sizeof ri, oldname, strlen(oldname) + 1);
	memcpy(buf + hdr + sizeof ri + strlen(oldname) + 1,
		newname, strlen(newname) + 1);
	{
		struct fuse_in_header ih;
		size_t total = hdr + sizeof ri + strlen(oldname) + 1
			+ strlen(newname) + 1;
		memcpy(&ih, buf, sizeof ih);
		ih.len = (uint32_t)total;
		memcpy(buf, &ih, sizeof ih);
		len = total;
	}
	fuse_drive_test_dispatch(fd, buf, len);

	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_OPEN)
		FAIL("RENAME did not emit an OPEN FS_REQ");
	if ((fuse_drive_test_req_access() & ACC_DELETE) == 0)
		FAIL("RENAME access 0x%x lacks DELETE",
			fuse_drive_test_req_access());
	pl = fuse_drive_test_req_payload(&plen);
	if (plen == 0 || strcmp((const char *)pl, "\\src.txt") != 0)
		FAIL("RENAME source path '%.*s'", (int)plen, pl);
	open_req = fuse_drive_test_req_id();

	/* OPEN(source) succeeds; the completion must emit the rename set. */
	feed_rsp(fd, open_req, STATUS_SUCCESS, 0x650, 0, NULL, 0);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_SET_INFO)
		FAIL("RENAME did not emit a SET_INFO after the OPEN");
	if (fuse_drive_test_req_info_class() != IC_FILE_RENAME)
		FAIL("RENAME set info_class 0x%x != FileRenameInformation",
			fuse_drive_test_req_info_class());
	pl = fuse_drive_test_req_payload(&plen);
	name_bytes = (uint32_t)(strlen(expect) * 2);
	if (plen != 6 + name_bytes)
		FAIL("RENAME SetBuffer %zu != %u", plen, 6 + name_bytes);
	if (pl[0] != 1)
		FAIL("RENAME ReplaceIfExists %u != 1", pl[0]);
	if (pl[1] != 0)
		FAIL("RENAME RootDirectory %u != 0", pl[1]);
	{
		uint32_t flen = pl[2] | ((uint32_t)pl[3] << 8)
			| ((uint32_t)pl[4] << 16) | ((uint32_t)pl[5] << 24);
		if (flen != name_bytes)
			FAIL("RENAME FileNameLength %u != %u", flen, name_bytes);
	}
	for (i = 0; i < strlen(expect); i++) {
		if (pl[6 + i * 2] != (uint8_t)expect[i] || pl[6 + i * 2 + 1] != 0)
			FAIL("RENAME UTF-16LE target mismatch at char %zu", i);
	}
	set_req = fuse_drive_test_req_id();

	/* The rename set succeeds; the completion closes and replies 0. */
	feed_rsp(fd, set_req, STATUS_SUCCESS, 0, 0, NULL, 0);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_CLOSE)
		FAIL("RENAME did not close the source handle");
	get_out(&oh);
	if (oh.error != 0)
		FAIL("RENAME reply error %d != 0", oh.error);
	if (oh.unique != 530)
		FAIL("RENAME reply unique %llu", (unsigned long long)oh.unique);
	printf("  rename src.txt -> dst.txt (same device): OPEN + SET "
		"FileRenameInformation (replace=1, root=0, UTF-16LE target), "
		"reply 0 ok\n");
}

/*
 * A cross-device FUSE_RENAME (source under drive C, destination under drive
 * DOCS) must reply -EXDEV without emitting any FS_REQ.
 */
static void
test_rename_cross_device(struct fuse_drive *fd)
{
	uint8_t buf[256];
	struct fuse_rename_in ri;
	struct fuse_out_header oh;
	const char *oldname = "a.txt";
	const char *newname = "b.txt";
	size_t hdr, total;

	memset(&ri, 0, sizeof ri);
	ri.newdir = 3;   /* DOCS drive root: a different device than C */
	hdr = sizeof(struct fuse_in_header);
	fuse_drive_test_reset();
	(void)build_in(buf, FUSE_RENAME, 540, DRIVE_C_NODE, &ri, sizeof ri);
	memcpy(buf + hdr + sizeof ri, oldname, strlen(oldname) + 1);
	memcpy(buf + hdr + sizeof ri + strlen(oldname) + 1,
		newname, strlen(newname) + 1);
	total = hdr + sizeof ri + strlen(oldname) + 1 + strlen(newname) + 1;
	{
		struct fuse_in_header ih;
		memcpy(&ih, buf, sizeof ih);
		ih.len = (uint32_t)total;
		memcpy(buf, &ih, sizeof ih);
	}
	fuse_drive_test_dispatch(fd, buf, total);

	if (fuse_drive_test_have_req())
		FAIL("cross-device RENAME emitted an FS_REQ");
	get_out(&oh);
	if (oh.error != -EXDEV)
		FAIL("cross-device RENAME error %d != -EXDEV", oh.error);
	printf("  rename cross-device: -EXDEV, no FS_REQ ok\n");
}

/*
 * Bounds: an over-long create name is rejected safely, and a truncated
 * RENAME body (the second name missing its terminator) replies -EINVAL with
 * no over-read (ASan/UBSan fails the run on any OOB).
 */
static void
test_namespace_bounds(struct fuse_drive *fd)
{
	uint8_t buf[1024];
	struct fuse_out_header oh;
	size_t hdr = sizeof(struct fuse_in_header);

	/* Over-long create name (> FD_NAME_MAX = 255).  The name field has no
	 * NUL within the first 255 bytes plus more, so it is rejected. */
	{
		struct fuse_create_in ci;
		size_t nlen = 400, total;
		memset(&ci, 0, sizeof ci);
		ci.flags = O_RDWR;
		ci.mode = S_IFREG | 0644;
		fuse_drive_test_reset();
		(void)build_in(buf, FUSE_CREATE, 550, DRIVE_C_NODE,
			&ci, sizeof ci);
		memset(buf + hdr + sizeof ci, 'x', nlen);
		buf[hdr + sizeof ci + nlen] = '\0';
		total = hdr + sizeof ci + nlen + 1;
		{
			struct fuse_in_header ih;
			memcpy(&ih, buf, sizeof ih);
			ih.len = (uint32_t)total;
			memcpy(buf, &ih, sizeof ih);
		}
		fuse_drive_test_dispatch(fd, buf, total);
		if (fuse_drive_test_have_req())
			FAIL("over-long CREATE name emitted an FS_REQ");
		get_out(&oh);
		if (oh.error != -EINVAL)
			FAIL("over-long CREATE name error %d != -EINVAL", oh.error);
	}

	/* Truncated RENAME: a first name but the second name runs to the end of
	 * the body with no terminating NUL.  fd_name_field must detect the
	 * missing NUL and the op must reply -EINVAL without reading past the
	 * body. */
	{
		struct fuse_rename_in ri;
		const char *oldname = "one";
		size_t off, total;
		memset(&ri, 0, sizeof ri);
		ri.newdir = DRIVE_C_NODE;
		fuse_drive_test_reset();
		(void)build_in(buf, FUSE_RENAME, 551, DRIVE_C_NODE,
			&ri, sizeof ri);
		off = hdr + sizeof ri;
		memcpy(buf + off, oldname, strlen(oldname) + 1);
		off += strlen(oldname) + 1;
		/* Second name with no terminating NUL: fill 4 non-NUL bytes. */
		memset(buf + off, 'y', 4);
		off += 4;
		total = off;
		{
			struct fuse_in_header ih;
			memcpy(&ih, buf, sizeof ih);
			ih.len = (uint32_t)total;
			memcpy(buf, &ih, sizeof ih);
		}
		fuse_drive_test_dispatch(fd, buf, total);
		if (fuse_drive_test_have_req())
			FAIL("truncated RENAME body emitted an FS_REQ");
		get_out(&oh);
		if (oh.error != -EINVAL)
			FAIL("truncated RENAME error %d != -EINVAL", oh.error);
	}

	printf("  namespace bounds: over-long CREATE name + truncated RENAME "
		"body -> EINVAL, no over-read ok\n");
}

/*
 * Regression: renaming a file into a SUBDIRECTORY must re-parent the local
 * node.  A slot-aliasing bug zeroed the saved destination parent after the
 * follow-up SET_INFO reused and memset the freed inflight slot, so the node
 * kept its old parent while the kernel saw the rename succeed.
 */
static void
test_rename_reparent(struct fuse_drive *fd)
{
	uint8_t buf[256];
	struct fuse_mkdir_in mi;
	struct fuse_rename_in ri;
	struct fuse_out_header oh;
	struct fuse_entry_out eo;
	const char *sub = "sub";
	const char *oldname = "src.txt";
	const char *newname = "moved.txt";
	size_t hdr = sizeof(struct fuse_in_header);
	size_t len, rlen;
	const uint8_t *r;
	uint64_t sub_node;
	uint32_t open_req, set_req;

	/* Create the destination subdirectory under drive C. */
	memset(&mi, 0, sizeof mi);
	mi.mode = 0755;
	fuse_drive_test_reset();
	(void)build_in(buf, FUSE_MKDIR, 600, DRIVE_C_NODE, &mi, sizeof mi);
	memcpy(buf + hdr + sizeof mi, sub, strlen(sub) + 1);
	{
		struct fuse_in_header ih;
		memcpy(&ih, buf, sizeof ih);
		ih.len = (uint32_t)(hdr + sizeof mi + strlen(sub) + 1);
		memcpy(buf, &ih, sizeof ih);
		len = ih.len;
	}
	fuse_drive_test_dispatch(fd, buf, len);
	open_req = fuse_drive_test_req_id();
	feed_rsp(fd, open_req, STATUS_SUCCESS, 0x620, 0, NULL, 0);
	get_out(&oh);
	r = fuse_drive_test_reply(&rlen);
	if (rlen != sizeof oh + sizeof eo)
		FAIL("reparent: mkdir reply size %zu", rlen);
	memcpy(&eo, r + sizeof oh, sizeof eo);
	sub_node = eo.nodeid;
	if (sub_node == 0)
		FAIL("reparent: subdir nodeid is 0");

	/* Rename src.txt (drive root) into the subdir as moved.txt. */
	memset(&ri, 0, sizeof ri);
	ri.newdir = sub_node;
	fuse_drive_test_reset();
	(void)build_in(buf, FUSE_RENAME, 601, DRIVE_C_NODE, &ri, sizeof ri);
	memcpy(buf + hdr + sizeof ri, oldname, strlen(oldname) + 1);
	memcpy(buf + hdr + sizeof ri + strlen(oldname) + 1,
		newname, strlen(newname) + 1);
	{
		struct fuse_in_header ih;
		memcpy(&ih, buf, sizeof ih);
		ih.len = (uint32_t)(hdr + sizeof ri + strlen(oldname) + 1
			+ strlen(newname) + 1);
		memcpy(buf, &ih, sizeof ih);
		len = ih.len;
	}
	fuse_drive_test_dispatch(fd, buf, len);

	open_req = fuse_drive_test_req_id();
	feed_rsp(fd, open_req, STATUS_SUCCESS, 0x650, 0, NULL, 0);
	if (fuse_drive_test_req_op() != RDP_FS_SET_INFO)
		FAIL("reparent: no SET_INFO after the source OPEN");
	set_req = fuse_drive_test_req_id();
	feed_rsp(fd, set_req, STATUS_SUCCESS, 0, 0, NULL, 0);
	get_out(&oh);
	if (oh.error != 0)
		FAIL("reparent: rename reply error %d", oh.error);

	/* The renamed node must now live under the destination subdir as
	 * moved.txt.  The slot-aliasing bug left it under the old parent, so
	 * the destination lookup would miss. */
	if (fuse_drive_test_find_child(fd, sub_node, newname) == 0)
		FAIL("reparent: renamed node not under the destination subdir "
			"(rename did not re-parent)");
	printf("  rename into subdir: node re-parented to the destination "
		"dir ok\n");
}

/*
 * Regression: a root READDIR whose dirent batch exceeds 128 bytes (five
 * or more drives) must return the whole batch.  The fixed-size reply
 * buffer used to reject anything over 128 bytes with EIO, breaking the
 * listing of any real directory.  Announce six more drives and confirm
 * the full batch comes back.
 */
static void
test_readdir_root_many(struct fuse_drive *fd)
{
	uint8_t buf[256];
	struct fuse_read_in ri;
	struct fuse_out_header oh;
	size_t len, rlen, off;
	const uint8_t *r, *p;
	int i, found = 0;
	static const char *names[6] = { "M0", "M1", "M2", "M3", "M4", "M5" };
	char dn[9];

	for (i = 0; i < 6; i++) {
		memset(dn, ' ', 8);
		dn[8] = '\0';
		dn[0] = names[i][0];
		dn[1] = names[i][1];
		fuse_drive_add_device(fd, 200 + i, RDPDR_DTYP_FILESYSTEM, dn, 1);
	}

	memset(&ri, 0, sizeof ri);
	ri.size = 4096;
	fuse_drive_test_reset();
	len = build_in(buf, FUSE_READDIR, 4, FUSE_ROOT_ID, &ri, sizeof ri);
	fuse_drive_test_dispatch(fd, buf, len);

	get_out(&oh);
	if (oh.error != 0)
		FAIL("root READDIR (many) error %d (the over-128-byte EIO bug)",
			oh.error);
	r = fuse_drive_test_reply(&rlen);
	if (rlen - sizeof oh <= 128)
		FAIL("root readdir batch %zu not over 128 (test ineffective)",
			rlen - sizeof oh);
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
		for (i = 0; i < 6; i++)
			if (strcmp(nm, names[i]) == 0)
				found++;
		off += reclen;
	}
	if (found != 6)
		FAIL("root readdir (many) found %d of 6 new drives", found);
	printf("  readdir root (8 drives, batch over 128 bytes): full batch "
		"returned ok\n");
}

int
main(void)
{
	struct fuse_drive *fd = fuse_drive_test_new();
	uint64_t child, wnode, rnode;
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

	/* Stage 4: real metadata getattr chain (covered above via the LOOKUP
	 * tests), plus the write path and setattr. */
	wnode = lookup_open_file(fd, "w.bin", 0x100, 90);
	test_open_wronly(fd, wnode, 0x101);
	test_write(fd, wnode, 0x101);
	test_setattr_truncate(fd, wnode);
	test_setattr_size_and_time(fd, wnode);
	test_bounds_meta(fd);

	/* Open refcount: a dedicated node opened twice via the reuse
	 * fast-path (read-only handle held from the LOOKUP getattr chain). */
	rnode = lookup_open_file(fd, "shared.bin", 0x200, 91);
	test_open_refcount(fd, rnode, 0x200);

	/* Stage 5: namespace ops (create, mknod, mkdir, unlink/rmdir, rename). */
	test_create(fd);
	test_mkdir(fd);
	test_mknod(fd);
	test_unlink(fd);
	test_rmdir(fd);
	test_rename_same_device(fd);
	test_rename_cross_device(fd);
	test_rename_reparent(fd);
	test_namespace_bounds(fd);
	test_readdir_root_many(fd);

	fuse_drive_free(fd);
	printf("fuse_drive_test: all ok\n");
	return 0;
}
