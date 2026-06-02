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
 * fuse_drive_obsd_test.c -- OpenBSD fusebuf read-path checks for the RDPDR
 * drive presentation.  Drives fuse_drive.c on in-memory fusebuf requests (no
 * real fd) via its RDP_FUSE_TEST hooks, feeds canned RDP_BE_FS_RSP replies,
 * and asserts both the emitted FS_REQ and the fusebuf reply bytes (struct
 * stat fields, native dirent records, fb_uuid echo).  This is the OpenBSD
 * mirror of regress/wire/fuse_drive_test.c.
 */

#include "../../src/session/fuse_drive.h"
#include "../../src/backend/proto.h"
#include "../../src/channels/rdpdr.h"   /* FileBothDirectoryInformation */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/dirent.h>
#include <sys/fusebuf.h>

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
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

/* FSCC info-class and FileAttributes constants used by the metadata tests. */
#define IC_FILE_BASIC      0x00000004u
#define IC_FILE_STANDARD   0x00000005u
#define IC_FILE_RENAME     0x0000000Au
#define IC_FILE_DISP       0x0000000Du
#define IC_FILE_EOF        0x00000014u
#define FATTR_DIRECTORY    0x00000010u

/* CreateDisposition / CreateOptions / DesiredAccess mirrored from rdpdr.h for
 * the namespace-op assertions. */
#define DISP_FILE_CREATE    0x00000002u
#define OPT_DIRECTORY_FILE  0x00000001u
#define OPT_NON_DIR_FILE    0x00000040u
#define OPT_DELETE_ON_CLOSE 0x00001000u
#define ACC_DELETE          0x00010000u

#define FD_ROOTINO         ((uint64_t)1)

/* The fixed hdr+FD region of a struct fusebuf (everything before fb_dat). */
#define FB_HDRLEN          (offsetof(struct fusebuf, fb_dat))

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

/*
 * Build one fusebuf request frame into buf: the FB_HDRLEN header region
 * (built through the host struct so the layout is exact) followed by an
 * optional fb_dat blob.  fb_len counts the data bytes.  io_off/io_len/io_fd
 * are written into the FD union's fb_io fields for the io ops.  Returns the
 * total length (header region + data).
 */
static size_t
build_fb(uint8_t *buf, int type, uint64_t uuid, uint64_t ino,
		uint64_t io_fd, uint64_t io_off, uint64_t io_len,
		const void *data, size_t data_len)
{
	struct fusebuf fb;

	memset(&fb, 0, sizeof fb);
	fb.fb_type = type;
	fb.fb_uuid = uuid;
	fb.fb_ino = (ino_t)ino;
	fb.fb_len = data_len;
	fb.fb_io_fd = io_fd;
	fb.fb_io_off = (off_t)io_off;
	fb.fb_io_len = io_len;
	memcpy(buf, &fb, FB_HDRLEN);
	if (data_len > 0)
		memcpy(buf + FB_HDRLEN, data, data_len);
	return FB_HDRLEN + data_len;
}

/*
 * Build a MKDIR/MKNOD request: fb_ino is the parent, the FD union's fb_io_mode
 * carries the mode, and fb_dat is the NUL terminated child name.  Returns the
 * total length.
 */
static size_t
build_fb_mknod(uint8_t *buf, int type, uint64_t uuid, uint64_t parent,
		mode_t mode, const char *name)
{
	struct fusebuf fb;
	size_t namelen = strlen(name) + 1;   /* include the NUL */

	memset(&fb, 0, sizeof fb);
	fb.fb_type = type;
	fb.fb_uuid = uuid;
	fb.fb_ino = (ino_t)parent;
	fb.fb_len = namelen;
	fb.fb_io_mode = mode;
	memcpy(buf, &fb, FB_HDRLEN);
	memcpy(buf + FB_HDRLEN, name, namelen);
	return FB_HDRLEN + namelen;
}

/*
 * Build a SETATTR request: fb_ino is the inode, the FD union's fb_attr (struct
 * stat) carries the new size/atime/mtime, and fb_dat is a struct fb_io whose
 * fi_flags is the FUSE_FATTR_* valid mask.  Returns the total length.
 */
static size_t
build_fb_setattr(uint8_t *buf, uint64_t uuid, uint64_t ino, uint32_t valid,
		uint64_t size, uint64_t atime, uint64_t mtime)
{
	struct fusebuf fb;
	struct fb_io io;

	memset(&fb, 0, sizeof fb);
	fb.fb_type = FBT_SETATTR;
	fb.fb_uuid = uuid;
	fb.fb_ino = (ino_t)ino;
	fb.fb_len = sizeof io;
	fb.fb_attr.st_size = (off_t)size;
	fb.fb_attr.st_atim.tv_sec = (time_t)atime;
	fb.fb_attr.st_mtim.tv_sec = (time_t)mtime;
	memcpy(buf, &fb, FB_HDRLEN);

	memset(&io, 0, sizeof io);
	io.fi_flags = valid;
	memcpy(buf + FB_HDRLEN, &io, sizeof io);
	return FB_HDRLEN + sizeof io;
}

/*
 * Build a RENAME request: fb_ino is the source parent, the FD union's
 * fb_io_ino is the destination parent, and fb_dat is oldname '\0' newname
 * '\0'.  When trailing_nul is 0 the second name's NUL is omitted so the
 * bounds path can be exercised.  Returns the total length.
 */
static size_t
build_fb_rename(uint8_t *buf, uint64_t uuid, uint64_t src_parent,
		uint64_t dst_parent, const char *oldname, const char *newname,
		int trailing_nul)
{
	struct fusebuf fb;
	size_t oldn = strlen(oldname);
	size_t newn = strlen(newname);
	size_t dlen = oldn + 1 + newn + (trailing_nul ? 1 : 0);
	uint8_t *d = buf + FB_HDRLEN;

	memset(&fb, 0, sizeof fb);
	fb.fb_type = FBT_RENAME;
	fb.fb_uuid = uuid;
	fb.fb_ino = (ino_t)src_parent;
	fb.fb_len = dlen;
	fb.fb_io_ino = (ino_t)dst_parent;
	memcpy(buf, &fb, FB_HDRLEN);

	memcpy(d, oldname, oldn);
	d[oldn] = '\0';
	memcpy(d + oldn + 1, newname, newn);
	if (trailing_nul)
		d[oldn + 1 + newn] = '\0';
	return FB_HDRLEN + dlen;
}

/* Read the reply header region into *fb and return the data pointer/len. */
static const uint8_t *
get_reply(struct fusebuf *fb, size_t *data_len)
{
	size_t len;
	const uint8_t *r = fuse_drive_test_reply(&len);
	if (len < FB_HDRLEN)
		FAIL("reply shorter than header region (%zu)", len);
	memcpy(fb, r, FB_HDRLEN);
	if (data_len != NULL)
		*data_len = len - FB_HDRLEN;
	return r + FB_HDRLEN;
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

/* --- INIT: replies success, no body, fb_uuid echoed --- */
static void
test_init(struct fuse_drive *fd)
{
	uint8_t buf[FB_HDRLEN + 16];
	struct fusebuf fb;
	size_t len, dlen;

	fuse_drive_test_reset();
	len = build_fb(buf, FBT_INIT, 0x1001, 0, 0, 0, 0, NULL, 0);
	fuse_drive_test_dispatch(fd, buf, len);

	(void)get_reply(&fb, &dlen);
	if (fb.fb_err != 0)
		FAIL("INIT err %d", fb.fb_err);
	if (fb.fb_uuid != 0x1001)
		FAIL("INIT uuid %llu", (unsigned long long)fb.fb_uuid);
	if (fb.fb_len != 0 || dlen != 0)
		FAIL("INIT carried a body (%zu)", dlen);
	printf("  init: success, no body, uuid echoed ok\n");
}

/* --- GETATTR on root: struct stat with S_IFDIR, st_ino == 1 --- */
static void
test_getattr_root(struct fuse_drive *fd)
{
	uint8_t buf[FB_HDRLEN];
	struct fusebuf fb;
	size_t len, dlen;

	fuse_drive_test_reset();
	len = build_fb(buf, FBT_GETATTR, 0x1002, FD_ROOTINO, 0, 0, 0, NULL, 0);
	fuse_drive_test_dispatch(fd, buf, len);

	(void)get_reply(&fb, &dlen);
	if (fb.fb_err != 0)
		FAIL("root GETATTR err %d", fb.fb_err);
	if (fb.fb_uuid != 0x1002)
		FAIL("root GETATTR uuid %llu", (unsigned long long)fb.fb_uuid);
	if (dlen != 0)
		FAIL("root GETATTR carried a body (%zu)", dlen);
	if ((fb.fb_attr.st_mode & S_IFMT) != S_IFDIR)
		FAIL("root not a dir, mode 0%o", (unsigned)fb.fb_attr.st_mode);
	if ((uint64_t)fb.fb_attr.st_ino != FD_ROOTINO)
		FAIL("root st_ino %llu",
			(unsigned long long)fb.fb_attr.st_ino);
	if (fb.fb_attr.st_nlink < 2)
		FAIL("root st_nlink %u", (unsigned)fb.fb_attr.st_nlink);
	printf("  getattr root: S_IFDIR st_ino 1 st_nlink %u ok\n",
		(unsigned)fb.fb_attr.st_nlink);
}

/* Drive C is node 2 (first announced after root id 1). */
#define DRIVE_C_NODE 2u

/* --- READDIR on root with two announced drives: native dirents --- */
static void
test_readdir_root(struct fuse_drive *fd)
{
	uint8_t buf[FB_HDRLEN];
	struct fusebuf fb;
	const uint8_t *p;
	size_t len, dlen, off;
	int saw_c = 0, saw_d = 0, count = 0;

	fuse_drive_add_device(fd, 100, RDPDR_DTYP_FILESYSTEM, "C       ", 1);
	fuse_drive_add_device(fd, 101, RDPDR_DTYP_FILESYSTEM, "DOCS    ", 1);

	fuse_drive_test_reset();
	len = build_fb(buf, FBT_READDIR, 0x1003, FD_ROOTINO, 0, 0, 4096,
		NULL, 0);
	fuse_drive_test_dispatch(fd, buf, len);

	p = get_reply(&fb, &dlen);
	if (fb.fb_err != 0)
		FAIL("root READDIR err %d", fb.fb_err);
	if (fb.fb_len != dlen)
		FAIL("root READDIR fb_len %zu != data %zu",
			(size_t)fb.fb_len, dlen);
	/* The kernel requires the whole reply in one write; a data-bearing
	 * reply split into two writes is rejected. */
	if (dlen > 0 && fuse_drive_test_reply_writes() != 1)
		FAIL("READDIR reply used %d writes (must be 1)",
			fuse_drive_test_reply_writes());
	off = 0;
	while (off + offsetof(struct dirent, d_name) <= dlen) {
		struct dirent de;
		char nm[MAXNAMLEN + 1];
		memcpy(&de, p + off, offsetof(struct dirent, d_name));
		if (de.d_reclen <= offsetof(struct dirent, d_name))
			FAIL("dirent d_reclen %u too small", de.d_reclen);
		if (de.d_reclen % 8 != 0)
			FAIL("dirent d_reclen %u not 8-aligned", de.d_reclen);
		if (off + de.d_reclen > dlen)
			FAIL("dirent overruns reply");
		if ((size_t)de.d_namlen
		    + offsetof(struct dirent, d_name) >= de.d_reclen)
			FAIL("dirent d_namlen %u overruns record", de.d_namlen);
		memcpy(nm, p + off + offsetof(struct dirent, d_name),
			de.d_namlen);
		nm[de.d_namlen] = '\0';
		if (de.d_type != DT_DIR)
			FAIL("drive dirent '%s' not DT_DIR (%u)", nm, de.d_type);
		if (de.d_fileno == 0)
			FAIL("drive dirent '%s' d_fileno 0", nm);
		if (strcmp(nm, "C") == 0) saw_c = 1;
		if (strcmp(nm, "DOCS") == 0) saw_d = 1;
		count++;
		off += de.d_reclen;
	}
	if (off != dlen)
		FAIL("dirent buffer not exactly consumed (%zu of %zu)",
			off, dlen);
	if (!saw_c || !saw_d || count != 2)
		FAIL("root readdir missing drives (c=%d d=%d n=%d)",
			saw_c, saw_d, count);

	/* A second READDIR at a non-zero offset must report EOF (empty). */
	fuse_drive_test_reset();
	len = build_fb(buf, FBT_READDIR, 0x1004, FD_ROOTINO, 0, 4096, 4096,
		NULL, 0);
	fuse_drive_test_dispatch(fd, buf, len);
	(void)get_reply(&fb, &dlen);
	if (fb.fb_err != 0 || fb.fb_len != 0 || dlen != 0)
		FAIL("root READDIR EOF not empty (err=%d len=%zu)",
			fb.fb_err, dlen);
	printf("  readdir root: 2 aligned DT_DIR drive dirents + EOF ok\n");
}

/* --- LOOKUP under a drive emits an OPEN FS_REQ --- */
static uint32_t
test_lookup_emits_open(struct fuse_drive *fd)
{
	uint8_t buf[FB_HDRLEN + 32];
	const char *name = "file.txt";
	size_t len, plen;
	const uint8_t *pl;

	fuse_drive_test_reset();
	len = build_fb(buf, FBT_LOOKUP, 0x2000, DRIVE_C_NODE, 0, 0, 0,
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
 * Drive the getattr chain a LOOKUP/GETATTR starts: OPEN success (with
 * file_id), then the FileStandardInformation reply, then the
 * FileBasicInformation reply, asserting the query at each step.  The final
 * fusebuf reply is left in the capture for the caller.
 */
static void
drive_getattr_chain(struct fuse_drive *fd, uint32_t open_req,
		uint32_t file_id, uint64_t size, int directory)
{
	uint32_t std_req, basic_req;
	uint8_t std[4 + 24];
	uint8_t basic[4 + 36];

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

	memset(std, 0, sizeof std);
	put32le(std, 24);
	put64le(std + 4 + 8, size);                 /* EndOfFile */
	std[4 + 21] = (uint8_t)(directory ? 1 : 0); /* Directory (+21) */

	feed_rsp(fd, std_req, STATUS_SUCCESS, 0, 0, std, sizeof std);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_QUERY_INFO)
		FAIL("getattr chain: Standard reply did not emit a QUERY_INFO");
	if (fuse_drive_test_req_info_class() != IC_FILE_BASIC)
		FAIL("getattr chain: second query class 0x%x not Basic",
			fuse_drive_test_req_info_class());
	basic_req = fuse_drive_test_req_id();

	memset(basic, 0, sizeof basic);
	put32le(basic, 36);
	put64le(basic + 4 + 16, MTIME_FILETIME);    /* LastWriteTime */
	put32le(basic + 4 + 32, directory ? FATTR_DIRECTORY : 0);

	feed_rsp(fd, basic_req, STATUS_SUCCESS, 0, 0, basic, sizeof basic);
}

/*
 * Feed the OPEN success and drive the getattr chain the LOOKUP started, then
 * check the resulting reply carries the child inode, S_IFREG, the real size,
 * and the converted mtime.  Returns the assigned child inode.
 */
static uint64_t
test_lookup_open_reply(struct fuse_drive *fd, uint32_t req_id)
{
	struct fusebuf fb;
	size_t dlen;

	drive_getattr_chain(fd, req_id, 0x4242, 12345, 0);

	(void)get_reply(&fb, &dlen);
	if (fb.fb_err != 0)
		FAIL("LOOKUP reply err %d", fb.fb_err);
	if (fb.fb_uuid != 0x2000)
		FAIL("LOOKUP reply uuid %llu", (unsigned long long)fb.fb_uuid);
	if (dlen != 0)
		FAIL("LOOKUP reply carried a body (%zu)", dlen);
	if ((uint64_t)fb.fb_ino == 0 || (uint64_t)fb.fb_ino == FD_ROOTINO)
		FAIL("LOOKUP child ino %llu", (unsigned long long)fb.fb_ino);
	if ((uint64_t)fb.fb_attr.st_ino != (uint64_t)fb.fb_ino)
		FAIL("LOOKUP stat st_ino %llu != fb_ino %llu",
			(unsigned long long)fb.fb_attr.st_ino,
			(unsigned long long)fb.fb_ino);
	if ((fb.fb_attr.st_mode & S_IFMT) != S_IFREG)
		FAIL("LOOKUP attr not S_IFREG, mode 0%o",
			(unsigned)fb.fb_attr.st_mode);
	if ((uint64_t)fb.fb_attr.st_size != 12345)
		FAIL("LOOKUP attr st_size %llu != 12345",
			(unsigned long long)fb.fb_attr.st_size);
	if ((uint64_t)fb.fb_attr.st_mtim.tv_sec != MTIME_UNIX_SEC)
		FAIL("LOOKUP attr mtime %llu != %llu",
			(unsigned long long)fb.fb_attr.st_mtim.tv_sec,
			(unsigned long long)MTIME_UNIX_SEC);
	printf("  lookup reply: child ino %llu size 12345 S_IFREG mtime ok\n",
		(unsigned long long)fb.fb_ino);
	return (uint64_t)fb.fb_ino;
}

/* --- OPEN of the looked-up file: cached handle reused, fb_io_fd set --- */
static void
test_open_node(struct fuse_drive *fd, uint64_t child_node)
{
	uint8_t buf[FB_HDRLEN];
	struct fusebuf fb;
	size_t len, dlen;

	fuse_drive_test_reset();
	len = build_fb(buf, FBT_OPEN, 0x2100, child_node, 0, 0, 0, NULL, 0);
	fuse_drive_test_dispatch(fd, buf, len);

	/* The LOOKUP already opened the handle, so OPEN replies immediately
	 * with the cached handle and emits no new FS_REQ. */
	if (fuse_drive_test_have_req())
		FAIL("OPEN re-issued an FS_REQ for an already-open node");
	(void)get_reply(&fb, &dlen);
	if (fb.fb_err != 0)
		FAIL("OPEN err %d", fb.fb_err);
	if ((uint64_t)fb.fb_io_fd != child_node)
		FAIL("OPEN fb_io_fd %llu != node %llu",
			(unsigned long long)fb.fb_io_fd,
			(unsigned long long)child_node);
	printf("  open file: cached handle reused, fb_io_fd set ok\n");
}

/* --- READ emits an FS_REQ READ, reply returns the data in fb_dat --- */
static void
test_read(struct fuse_drive *fd, uint64_t child_node)
{
	uint8_t buf[FB_HDRLEN];
	struct fusebuf fb;
	size_t len, dlen;
	uint32_t req_id;
	const char data[8] = { 'a','b','c','d','e','f','g','h' };
	uint8_t pl[4 + 8];
	const uint8_t *rd;
	struct rdp_be_fs_rsp rsp;

	fuse_drive_test_reset();
	len = build_fb(buf, FBT_READ, 0x2200, child_node, child_node, 16, 8,
		NULL, 0);
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
	put32le(pl, 8);
	memcpy(pl + 4, data, 8);
	memset(&rsp, 0, sizeof rsp);
	rsp.req_id = req_id;
	rsp.status = STATUS_SUCCESS;
	rsp.length = 8;
	fuse_drive_test_reset();
	fuse_drive_handle_fs_rsp(fd, &rsp, pl, sizeof pl);

	rd = get_reply(&fb, &dlen);
	if (fb.fb_err != 0)
		FAIL("READ reply err %d", fb.fb_err);
	if (fb.fb_uuid != 0x2200)
		FAIL("READ uuid %llu", (unsigned long long)fb.fb_uuid);
	if (fb.fb_len != 8 || dlen != 8)
		FAIL("READ fb_len %zu != 8", (size_t)fb.fb_len);
	if (memcmp(rd, data, 8) != 0)
		FAIL("READ data mismatch");
	if (fuse_drive_test_reply_writes() != 1)
		FAIL("READ reply used %d writes (must be 1)",
			fuse_drive_test_reply_writes());
	printf("  read: FS_REQ READ + reply 8 bytes in fb_dat ok\n");
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

/* --- READDIR on a drive: OPENDIR, LIST FS_REQ, FSCC -> native dirents --- */
static void
test_readdir_drive(struct fuse_drive *fd)
{
	uint8_t buf[FB_HDRLEN + 64];
	struct fusebuf fb;
	size_t len, dlen, off, total, doff;
	uint32_t open_req, list_req;
	uint8_t fscc[512];
	uint8_t pl[516];
	const uint8_t *p;
	int saw_sub = 0, saw_file = 0, count = 0;
	struct rdp_be_fs_rsp rsp;

	/* OPENDIR the drive root to get a real handle. */
	fuse_drive_test_reset();
	len = build_fb(buf, FBT_OPENDIR, 0x3000, DRIVE_C_NODE, 0, 0, 0,
		NULL, 0);
	fuse_drive_test_dispatch(fd, buf, len);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_OPEN)
		FAIL("OPENDIR did not emit an OPEN FS_REQ");
	open_req = fuse_drive_test_req_id();
	feed_rsp(fd, open_req, STATUS_SUCCESS, 0x9001, 0, NULL, 0);
	(void)get_reply(&fb, &dlen);
	if (fb.fb_err != 0)
		FAIL("OPENDIR reply err %d", fb.fb_err);

	/* READDIR now emits a LIST. */
	fuse_drive_test_reset();
	len = build_fb(buf, FBT_READDIR, 0x3001, DRIVE_C_NODE, 0x9001, 0, 4096,
		NULL, 0);
	fuse_drive_test_dispatch(fd, buf, len);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_LIST)
		FAIL("drive READDIR did not emit a LIST FS_REQ");
	list_req = fuse_drive_test_req_id();

	/* Canned LIST reply: Length(u32) + "." + ".." (dropped) + a dir + a
	 * file. */
	off = 0;
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

	p = get_reply(&fb, &dlen);
	if (fb.fb_err != 0)
		FAIL("drive READDIR reply err %d", fb.fb_err);
	if (fb.fb_len != dlen)
		FAIL("drive READDIR fb_len %zu != data %zu",
			(size_t)fb.fb_len, dlen);
	doff = 0;
	while (doff + offsetof(struct dirent, d_name) <= dlen) {
		struct dirent de;
		char nm[MAXNAMLEN + 1];
		memcpy(&de, p + doff, offsetof(struct dirent, d_name));
		if (de.d_reclen <= offsetof(struct dirent, d_name)
		    || de.d_reclen % 8 != 0)
			FAIL("drive dirent bad d_reclen %u", de.d_reclen);
		if (doff + de.d_reclen > dlen)
			FAIL("drive dirent overruns reply");
		memcpy(nm, p + doff + offsetof(struct dirent, d_name),
			de.d_namlen);
		nm[de.d_namlen] = '\0';
		if (strcmp(nm, "sub") == 0) {
			saw_sub = 1;
			if (de.d_type != DT_DIR)
				FAIL("'sub' not DT_DIR");
		}
		if (strcmp(nm, "a.txt") == 0) {
			saw_file = 1;
			if (de.d_type != DT_REG)
				FAIL("'a.txt' not DT_REG");
		}
		count++;
		doff += de.d_reclen;
	}
	if (!saw_sub || !saw_file || count != 2)
		FAIL("drive readdir decode (sub=%d file=%d n=%d)",
			saw_sub, saw_file, count);
	printf("  readdir drive: decoded 'sub' (dir) + 'a.txt' (file), "
		"skipped . / .. ok\n");
}

/*
 * Bounds: a truncated fusebuf request and an over-claimed READ reply must not
 * over-read.  Without ASan on OpenBSD we assert the module produces a
 * well-formed clamped reply and never reads past the data we provided.
 */
static void
test_bounds(struct fuse_drive *fd)
{
	uint8_t buf[FB_HDRLEN + 16];
	struct fusebuf fb;
	size_t len, dlen;
	uint32_t open_req, rreq;
	uint64_t xnode;
	uint8_t pl[4 + 2];
	struct rdp_be_fs_rsp rsp;

	/* A LOOKUP whose name has no terminating NUL must be rejected. */
	fuse_drive_test_reset();
	{
		uint8_t bad[4] = { 'a', 'b', 'c', 'd' };   /* no NUL */
		len = build_fb(buf, FBT_LOOKUP, 0x4000, DRIVE_C_NODE, 0, 0, 0,
			bad, sizeof bad);
	}
	fuse_drive_test_dispatch(fd, buf, len);
	if (fuse_drive_test_have_req())
		FAIL("unterminated LOOKUP name was dispatched");
	(void)get_reply(&fb, &dlen);
	if (fb.fb_err == 0)
		FAIL("unterminated LOOKUP name not rejected");

	/* A request shorter than the header region must be ignored as a runt
	 * (no crash, no reply). */
	fuse_drive_test_reset();
	fuse_drive_test_dispatch(fd, buf, FB_HDRLEN - 1);
	{
		size_t rlen;
		(void)fuse_drive_test_reply(&rlen);
		if (rlen != 0)
			FAIL("runt request produced a reply (%zu)", rlen);
	}

	/* Open a real file under DOCS (node 3) and drive its getattr chain so
	 * a READ has a live handle. */
	fuse_drive_test_reset();
	len = build_fb(buf, FBT_LOOKUP, 0x4001, 3, 0, 0, 0, "x",
		strlen("x") + 1);
	fuse_drive_test_dispatch(fd, buf, len);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_OPEN)
		FAIL("bounds LOOKUP did not emit an OPEN");
	open_req = fuse_drive_test_req_id();
	drive_getattr_chain(fd, open_req, 0x55, 0, 0);
	(void)get_reply(&fb, &dlen);
	xnode = (uint64_t)fb.fb_ino;

	fuse_drive_test_reset();
	len = build_fb(buf, FBT_READ, 0x4002, xnode, xnode, 0, 4096, NULL, 0);
	fuse_drive_test_dispatch(fd, buf, len);
	if (!fuse_drive_test_have_req())
		FAIL("bounds READ no FS_REQ");
	rreq = fuse_drive_test_req_id();

	/* READ reply claims 64 KiB but only 2 bytes are present: must clamp. */
	put32le(pl, 0x10000u);
	pl[4] = 0xAA;
	pl[5] = 0xBB;
	memset(&rsp, 0, sizeof rsp);
	rsp.req_id = rreq;
	rsp.status = STATUS_SUCCESS;
	fuse_drive_test_reset();
	fuse_drive_handle_fs_rsp(fd, &rsp, pl, sizeof pl);
	(void)get_reply(&fb, &dlen);
	if (fb.fb_err != 0)
		FAIL("bounds READ reply err %d", fb.fb_err);
	if (fb.fb_len != 2 || dlen != 2)
		FAIL("bounds READ not clamped to 2 (fb_len %zu)",
			(size_t)fb.fb_len);
	printf("  bounds: bad name + runt + over-claimed READ clamped, "
		"no over-read ok\n");
}

/*
 * Open the looked-up file O_WRONLY so the node carries a write handle, then
 * FBT_WRITE: assert the FS_REQ is RDP_FS_WRITE with the file_id/offset and the
 * data payload, feed a canned write completion (Length = N), and assert the
 * reply puts the count in fb_io_len (not fb_len), with fb_len 0 and exactly
 * one write_reply call (header-only, no fb_dat).
 */
static void
test_write(struct fuse_drive *fd, uint64_t child_node)
{
	uint8_t buf[FB_HDRLEN + 32];
	struct fusebuf fb;
	const uint8_t data[5] = { 'h', 'e', 'l', 'l', 'o' };
	uint8_t pl[4 + 1];
	size_t len, dlen, plen;
	const uint8_t *rqpl;
	uint32_t open_req, write_req;
	struct rdp_be_fs_rsp rsp;

	/* Upgrade the read-only handle to a write handle (O_WRONLY open).  The
	 * open flags travel in fb_io_flags, which build_fb does not set, so put
	 * them in directly through the host struct. */
	fuse_drive_test_reset();
	len = build_fb(buf, FBT_OPEN, 0x5000, child_node, 0, 0, 0, NULL, 0);
	{
		struct fusebuf t;
		memcpy(&t, buf, FB_HDRLEN);
		t.fb_io_flags = O_WRONLY;
		memcpy(buf, &t, FB_HDRLEN);
	}
	fuse_drive_test_dispatch(fd, buf, len);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_OPEN)
		FAIL("O_WRONLY open did not emit an OPEN FS_REQ");
	open_req = fuse_drive_test_req_id();
	feed_rsp(fd, open_req, STATUS_SUCCESS, 0x7777, 0, NULL, 0);
	(void)get_reply(&fb, &dlen);
	if (fb.fb_err != 0)
		FAIL("O_WRONLY open reply err %d", fb.fb_err);

	/* FBT_WRITE: handle in fb_io_fd, offset in fb_io_off, length in
	 * fb_io_len, the data in fb_dat. */
	fuse_drive_test_reset();
	len = build_fb(buf, FBT_WRITE, 0x5001, child_node, child_node, 100,
		sizeof data, data, sizeof data);
	fuse_drive_test_dispatch(fd, buf, len);

	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_WRITE)
		FAIL("FBT_WRITE did not emit an RDP_FS_WRITE");
	if (fuse_drive_test_req_file_id() != 0x7777)
		FAIL("WRITE file_id 0x%x != 0x7777",
			fuse_drive_test_req_file_id());
	if (fuse_drive_test_req_offset() != 100)
		FAIL("WRITE offset %llu != 100",
			(unsigned long long)fuse_drive_test_req_offset());
	rqpl = fuse_drive_test_req_payload(&plen);
	if (plen != sizeof data || memcmp(rqpl, data, sizeof data) != 0)
		FAIL("WRITE payload (%zu bytes) mismatch", plen);
	write_req = fuse_drive_test_req_id();

	/* Canned write completion: FSCC Length(u32) = 5, then a Padding byte. */
	put32le(pl, 5);
	pl[4] = 0;
	memset(&rsp, 0, sizeof rsp);
	rsp.req_id = write_req;
	rsp.status = STATUS_SUCCESS;
	rsp.length = 5;
	fuse_drive_test_reset();
	fuse_drive_handle_fs_rsp(fd, &rsp, pl, sizeof pl);

	(void)get_reply(&fb, &dlen);
	if (fb.fb_err != 0)
		FAIL("WRITE reply err %d", fb.fb_err);
	if (fb.fb_uuid != 0x5001)
		FAIL("WRITE uuid %llu", (unsigned long long)fb.fb_uuid);
	if ((uint64_t)fb.fb_io_len != 5)
		FAIL("WRITE count in fb_io_len %llu != 5",
			(unsigned long long)fb.fb_io_len);
	if (fb.fb_len != 0 || dlen != 0)
		FAIL("WRITE reply carried a body (fb_len %zu)", (size_t)fb.fb_len);
	if (fuse_drive_test_reply_writes() != 1)
		FAIL("WRITE reply used %d writes (must be 1)",
			fuse_drive_test_reply_writes());
	printf("  write: RDP_FS_WRITE offset 100 + 5-byte payload, "
		"count in fb_io_len==5, single header-only reply ok\n");
}

/*
 * FBT_SETATTR with FUSE_FATTR_SIZE emits a FileEndOfFileInformation set with
 * the requested size; a success completion (then the re-query chain) yields an
 * attr reply.  The node must be write-open, which test_write left it.
 */
static void
test_setattr_truncate(struct fuse_drive *fd, uint64_t child_node)
{
	uint8_t buf[FB_HDRLEN + 64];
	struct fusebuf fb;
	size_t len, dlen;
	uint32_t set_req;
	const uint8_t *pl;
	size_t plen;

	fuse_drive_test_reset();
	len = build_fb_setattr(buf, 0x5100, child_node, FUSE_FATTR_SIZE,
		4096, 0, 0);
	fuse_drive_test_dispatch(fd, buf, len);

	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_SET_INFO)
		FAIL("SETATTR size did not emit an RDP_FS_SET_INFO");
	if (fuse_drive_test_req_info_class() != IC_FILE_EOF)
		FAIL("SETATTR info_class 0x%x != FileEndOfFileInformation",
			fuse_drive_test_req_info_class());
	pl = fuse_drive_test_req_payload(&plen);
	if (plen != 8)
		FAIL("SETATTR EOF SetBuffer %zu != 8", plen);
	{
		uint64_t eof = 0;
		int i;
		for (i = 0; i < 8; i++)
			eof |= (uint64_t)pl[i] << (i * 8);
		if (eof != 4096)
			FAIL("SETATTR EndOfFile %llu != 4096",
				(unsigned long long)eof);
	}
	set_req = fuse_drive_test_req_id();

	/* The EOF set completion runs a single FileStandardInformation re-query;
	 * answer it, then the FileBasicInformation one, to land the attr reply. */
	feed_rsp(fd, set_req, STATUS_SUCCESS, 0, 0, NULL, 0);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_QUERY_INFO
	    || fuse_drive_test_req_info_class() != IC_FILE_STANDARD)
		FAIL("SETATTR did not re-query Standard after the EOF set");
	{
		uint32_t std_req = fuse_drive_test_req_id();
		uint8_t std[4 + 24];
		uint32_t basic_req;
		uint8_t basic[4 + 36];
		memset(std, 0, sizeof std);
		put32le(std, 24);
		put64le(std + 4 + 8, 4096);   /* EndOfFile reflects the truncate */
		feed_rsp(fd, std_req, STATUS_SUCCESS, 0, 0, std, sizeof std);
		if (!fuse_drive_test_have_req()
		    || fuse_drive_test_req_info_class() != IC_FILE_BASIC)
			FAIL("SETATTR did not re-query Basic");
		basic_req = fuse_drive_test_req_id();
		memset(basic, 0, sizeof basic);
		put32le(basic, 36);
		feed_rsp(fd, basic_req, STATUS_SUCCESS, 0, 0, basic, sizeof basic);
	}

	(void)get_reply(&fb, &dlen);
	if (fb.fb_err != 0)
		FAIL("SETATTR reply err %d", fb.fb_err);
	if (fb.fb_uuid != 0x5100)
		FAIL("SETATTR uuid %llu", (unsigned long long)fb.fb_uuid);
	if (dlen != 0)
		FAIL("SETATTR reply carried a body (%zu)", dlen);
	if ((uint64_t)fb.fb_attr.st_size != 4096)
		FAIL("SETATTR reply st_size %llu != 4096",
			(unsigned long long)fb.fb_attr.st_size);
	printf("  setattr truncate: RDP_FS_SET_INFO FileEndOfFileInformation "
		"EndOfFile==4096, attr reply st_size 4096 ok\n");
}

/*
 * FBT_MKDIR emits an OPEN with disposition FILE_CREATE and options
 * FILE_DIRECTORY_FILE; the success completion closes the handle and replies an
 * entry with S_IFDIR and the new child inode in fb_ino.
 */
static void
test_mkdir(struct fuse_drive *fd)
{
	uint8_t buf[FB_HDRLEN + 32];
	struct fusebuf fb;
	size_t len, dlen;
	uint32_t open_req;

	fuse_drive_test_reset();
	len = build_fb_mknod(buf, FBT_MKDIR, 0x5200, DRIVE_C_NODE,
		S_IFDIR | 0755, "newdir");
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

	/* OPEN(FILE_CREATE) succeeds; the completion closes and replies entry. */
	feed_rsp(fd, open_req, STATUS_SUCCESS, 0x660, 0, NULL, 0);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_CLOSE)
		FAIL("MKDIR did not close the create handle");

	(void)get_reply(&fb, &dlen);
	if (fb.fb_err != 0)
		FAIL("MKDIR reply err %d", fb.fb_err);
	if (fb.fb_uuid != 0x5200)
		FAIL("MKDIR uuid %llu", (unsigned long long)fb.fb_uuid);
	if ((uint64_t)fb.fb_ino == 0 || (uint64_t)fb.fb_ino == FD_ROOTINO)
		FAIL("MKDIR child ino %llu", (unsigned long long)fb.fb_ino);
	if ((fb.fb_attr.st_mode & S_IFMT) != S_IFDIR)
		FAIL("MKDIR attr not S_IFDIR, mode 0%o",
			(unsigned)fb.fb_attr.st_mode);
	if ((uint64_t)fb.fb_attr.st_ino != (uint64_t)fb.fb_ino)
		FAIL("MKDIR stat st_ino %llu != fb_ino %llu",
			(unsigned long long)fb.fb_attr.st_ino,
			(unsigned long long)fb.fb_ino);
	printf("  mkdir newdir: OPEN FILE_CREATE FILE_DIRECTORY_FILE, close, "
		"reply child ino %llu S_IFDIR ok\n",
		(unsigned long long)fb.fb_ino);
}

/*
 * FBT_UNLINK emits an OPEN(DELETE, FILE_DELETE_ON_CLOSE) then a
 * SET_INFO(FileDispositionInformation) carrying DeletePending=1, then a CLOSE;
 * the chain replies fb_err 0.
 */
static void
test_unlink(struct fuse_drive *fd)
{
	uint8_t buf[FB_HDRLEN + 32];
	struct fusebuf fb;
	size_t len, dlen, plen;
	const uint8_t *pl;
	uint32_t open_req, set_req;

	fuse_drive_test_reset();
	len = build_fb_mknod(buf, FBT_UNLINK, 0x5300, DRIVE_C_NODE, 0,
		"del.txt");
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

	feed_rsp(fd, open_req, STATUS_SUCCESS, 0x670, 0, NULL, 0);
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

	feed_rsp(fd, set_req, STATUS_SUCCESS, 0, 0, NULL, 0);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_CLOSE)
		FAIL("UNLINK did not close the delete handle");
	(void)get_reply(&fb, &dlen);
	if (fb.fb_err != 0)
		FAIL("UNLINK reply err %d != 0", fb.fb_err);
	if (fb.fb_uuid != 0x5300)
		FAIL("UNLINK uuid %llu", (unsigned long long)fb.fb_uuid);
	if (dlen != 0)
		FAIL("UNLINK reply carried a body (%zu)", dlen);
	printf("  unlink del.txt: OPEN(DELETE) + SET FileDispositionInformation "
		"(DeletePending=1) + CLOSE, fb_err 0 ok\n");
}

/*
 * FBT_RENAME on the same device emits an OPEN(source) then a
 * SET_INFO(FileRenameInformation) whose SetBuffer carries ReplaceIfExists=1,
 * RootDirectory=0, the correct FileNameLength, and the UTF-16LE target path;
 * the chain closes and replies fb_err 0.  The destination parent travels in
 * the request's fb_io_ino.
 */
static void
test_rename_same_device(struct fuse_drive *fd)
{
	uint8_t buf[FB_HDRLEN + 64];
	struct fusebuf fb;
	const char *expect = "\\dst.txt";   /* dest is the drive root */
	size_t len, dlen, plen, i;
	const uint8_t *pl;
	uint32_t open_req, set_req, name_bytes;

	fuse_drive_test_reset();
	len = build_fb_rename(buf, 0x5400, DRIVE_C_NODE, DRIVE_C_NODE,
		"src.txt", "dst.txt", 1);
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

	feed_rsp(fd, open_req, STATUS_SUCCESS, 0x680, 0, NULL, 0);
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

	feed_rsp(fd, set_req, STATUS_SUCCESS, 0, 0, NULL, 0);
	if (!fuse_drive_test_have_req()
	    || fuse_drive_test_req_op() != RDP_FS_CLOSE)
		FAIL("RENAME did not close the source handle");
	(void)get_reply(&fb, &dlen);
	if (fb.fb_err != 0)
		FAIL("RENAME reply err %d != 0", fb.fb_err);
	if (fb.fb_uuid != 0x5400)
		FAIL("RENAME uuid %llu", (unsigned long long)fb.fb_uuid);
	printf("  rename src.txt -> dst.txt (same device): OPEN + SET "
		"FileRenameInformation (replace=1, root=0, UTF-16LE target), "
		"fb_err 0 ok\n");
}

/*
 * A cross-device FBT_RENAME (source under drive C, destination under drive
 * DOCS, node 3) must reply fb_err EXDEV without emitting any FS_REQ.
 */
static void
test_rename_cross_device(struct fuse_drive *fd)
{
	uint8_t buf[FB_HDRLEN + 64];
	struct fusebuf fb;
	size_t len, dlen;

	fuse_drive_test_reset();
	len = build_fb_rename(buf, 0x5500, DRIVE_C_NODE, 3,
		"a.txt", "b.txt", 1);
	fuse_drive_test_dispatch(fd, buf, len);

	if (fuse_drive_test_have_req())
		FAIL("cross-device RENAME emitted an FS_REQ");
	(void)get_reply(&fb, &dlen);
	if (fb.fb_err != EXDEV)
		FAIL("cross-device RENAME fb_err %d != EXDEV", fb.fb_err);
	printf("  rename cross-device: fb_err EXDEV, no FS_REQ ok\n");
}

/*
 * Namespace bounds: a RENAME whose second name has no terminating NUL, and an
 * over-long MKDIR name, must be rejected (fb_err EINVAL) with no FS_REQ and no
 * over-read past the fb_dat we provided.
 */
static void
test_namespace_bounds(struct fuse_drive *fd)
{
	uint8_t buf[FB_HDRLEN + 512];
	struct fusebuf fb;
	size_t len, dlen;

	/* RENAME missing the second name's NUL: build_fb_rename(..., 0). */
	fuse_drive_test_reset();
	len = build_fb_rename(buf, 0x5600, DRIVE_C_NODE, DRIVE_C_NODE,
		"one", "two", 0);
	fuse_drive_test_dispatch(fd, buf, len);
	if (fuse_drive_test_have_req())
		FAIL("unterminated RENAME name was dispatched");
	(void)get_reply(&fb, &dlen);
	if (fb.fb_err == 0)
		FAIL("unterminated RENAME name not rejected");

	/* Over-long MKDIR name (> FD_NAME_MAX = 255), NUL terminated but too
	 * long: the name field rejects it. */
	{
		struct fusebuf t;
		size_t nlen = 400;
		memset(&t, 0, sizeof t);
		t.fb_type = FBT_MKDIR;
		t.fb_uuid = 0x5601;
		t.fb_ino = (ino_t)DRIVE_C_NODE;
		t.fb_len = nlen + 1;
		t.fb_io_mode = S_IFDIR | 0755;
		memcpy(buf, &t, FB_HDRLEN);
		memset(buf + FB_HDRLEN, 'x', nlen);
		buf[FB_HDRLEN + nlen] = '\0';
		len = FB_HDRLEN + nlen + 1;
		fuse_drive_test_reset();
		fuse_drive_test_dispatch(fd, buf, len);
		if (fuse_drive_test_have_req())
			FAIL("over-long MKDIR name emitted an FS_REQ");
		(void)get_reply(&fb, &dlen);
		if (fb.fb_err == 0)
			FAIL("over-long MKDIR name not rejected");
	}
	printf("  namespace bounds: unterminated RENAME + over-long MKDIR "
		"rejected, no over-read ok\n");
}

int
main(void)
{
	struct fuse_drive *fd = fuse_drive_test_new();
	uint32_t lookup_req;
	uint64_t child;

	if (fd == NULL)
		FAIL("fuse_drive_test_new");

	printf("fuse_drive_obsd_test:\n");
	test_init(fd);
	test_getattr_root(fd);
	test_readdir_root(fd);
	lookup_req = test_lookup_emits_open(fd);
	child = test_lookup_open_reply(fd, lookup_req);
	test_open_node(fd, child);
	test_read(fd, child);
	test_readdir_drive(fd);
	test_bounds(fd);

	/* write + namespace ops (stage 6c) */
	test_write(fd, child);
	test_setattr_truncate(fd, child);
	test_mkdir(fd);
	test_unlink(fd);
	test_rename_same_device(fd);
	test_rename_cross_device(fd);
	test_namespace_bounds(fd);

	fuse_drive_free(fd);
	printf("fuse_drive_obsd_test: all ok\n");
	return 0;
}
