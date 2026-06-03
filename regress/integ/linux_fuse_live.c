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
 * linux_fuse_live.c -- live validation of the Linux raw /dev/fuse drive
 * backend against the REAL kernel.  NOT part of the default regress: it
 * needs root (mount(2)) and a working /dev/fuse, so it is built and run by
 * hand.  Build and run on a Linux host:
 *
 *   make regress/integ/linux_fuse_live
 *   sudo ./regress/integ/linux_fuse_live
 *
 * What it does.  It links the protocol-agnostic drive core (fuse_drive.c)
 * and the Linux raw /dev/fuse backend (fuse_drive_linux.c) and drives them
 * on a REAL /dev/fuse fd mounted at a temp mountpoint, so the local kernel
 * actually exercises the backend's INIT/GETATTR/LOOKUP/READDIR/OPEN/READ/
 * WRITE/CREATE/MKDIR/UNLINK replies (the thing the in-memory unit test
 * cannot confirm).  The RDPDR side is a tiny in-memory mock FS: a drive "C"
 * containing the file "hello.txt" (contents below) and the directory "sub".
 * The mock answers each FS_REQ the core emits with a canned RDPDR FS_RSP,
 * reusing the same FSCC encoders the unit test uses.
 *
 * This is the Linux analogue of regress/integ/obsd_fuse_live.c; it mirrors
 * that file's structure (mock FS, deferred FS_REQ queue, forked child doing
 * real syscalls, parent service loop) but uses the Linux mount/poll/unmount
 * primitives instead of the OpenBSD fusebuf ones:
 *
 *   - mount: open /dev/fuse, then mount("rdpdrive", mnt, "fuse", ...) with
 *     the same optstring sessionmgr.c's fuse_mount_setup builds.
 *   - service loop: poll(POLLIN) on the (non-blocking) fuse fd plus the
 *     child result pipe; the standard fuse_drive_process() drains it.
 *   - teardown: umount2(MNT_DETACH) (lazy) so nothing wedges.
 *
 * Reentrancy.  An FS_REQ is QUEUED when the core emits it during dispatch
 * and answered only after fuse_drive_process() returns, so the FS_RSP
 * completion (which may emit more FS_REQs, e.g. the getattr chain) never
 * runs nested inside dispatch.
 */

#include "../../src/session/fuse_drive.h"
#include "../../src/session/fuse_drive_internal.h"
#include "../../src/backend/proto.h"
#include "../../src/channels/rdpdr.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/wait.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define HELLO_CONTENTS "hello from linux\n"

/* ---- little-endian FSCC encoders (mirrors the unit test) ---- */

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

/* A FILETIME for 2020-06-01 00:00:00 UTC, used as every file's mtime. */
#define MTIME_FILETIME  132356160000000000ull

/* ---- the in-memory mock filesystem ---- */

/*
 * The mock knows three device-relative paths under drive C: the drive root
 * "\", the file "\hello.txt", and the directory "\sub".  An OPEN of a path
 * assigns a file_id; a later QUERY_INFO/READ/WRITE/LIST arrives by file_id,
 * so the mock maps file_id -> path entry.
 */
struct mock_entry {
	const char *path;     /* device-relative, backslash form */
	int         is_dir;
	const char *contents; /* files only; NULL for dirs */
};

static struct mock_entry mock_fs[] = {
	{ "\\",          1, NULL },
	{ "\\hello.txt", 0, HELLO_CONTENTS },
	{ "\\sub",       1, NULL },
};
#define MOCK_FS_N (sizeof mock_fs / sizeof mock_fs[0])

/* file_id -> mock_entry index, assigned on OPEN. */
#define MOCK_FH_MAX 64
static struct {
	int        in_use;
	uint32_t   file_id;
	int        ent;       /* index into mock_fs, or -1 */
} mock_fh[MOCK_FH_MAX];
static uint32_t mock_next_fid = 0x1000;

/*
 * Created-on-demand entries the test wires up: a write target
 * "\wtest.txt" and a new directory "\newdir".  The write target keeps a
 * small in-memory buffer; the new directory is only a name the mock learns
 * to recognise (so a following LIST/QUERY of it succeeds).
 */
static char    wtest_buf[256];
static size_t  wtest_len;
static int     wtest_exists;
static int     newdir_exists;

static int
mock_lookup_path(const char *path)
{
	size_t i;
	if (path == NULL)
		return -1;
	for (i = 0; i < MOCK_FS_N; i++)
		if (strcmp(mock_fs[i].path, path) == 0)
			return (int)i;
	return -1;
}

/* ---- the deferred FS_REQ queue (filled by send, drained after process) ---- */

struct mock_req {
	int                  in_use;
	struct rdp_be_fs_req req;
	uint8_t              payload[4096];
	size_t               payload_len;
};
#define MOCK_REQ_MAX 64
static struct mock_req mock_q[MOCK_REQ_MAX];

static int
mock_send_fs_req(struct fuse_drive *fd, const struct rdp_be_fs_req *req,
		const void *payload, size_t payload_len)
{
	int i;
	(void)fd;
	for (i = 0; i < MOCK_REQ_MAX; i++) {
		if (!mock_q[i].in_use) {
			mock_q[i].in_use = 1;
			mock_q[i].req = *req;
			mock_q[i].payload_len = payload_len < sizeof mock_q[i].payload
				? payload_len : sizeof mock_q[i].payload;
			if (mock_q[i].payload_len > 0)
				memcpy(mock_q[i].payload, payload,
					mock_q[i].payload_len);
			return 0;
		}
	}
	(void)fprintf(stderr, "mock: FS_REQ queue full\n");
	return -1;
}

/* Assign (or reuse) a file_id for a mock entry; return it via *fid. */
static int
mock_open_entry(int ent, uint32_t *fid)
{
	int i;
	for (i = 0; i < MOCK_FH_MAX; i++) {
		if (!mock_fh[i].in_use) {
			mock_fh[i].in_use = 1;
			mock_fh[i].file_id = mock_next_fid++;
			mock_fh[i].ent = ent;
			*fid = mock_fh[i].file_id;
			return 0;
		}
	}
	return -1;
}

static int
mock_fh_find(uint32_t file_id)
{
	int i;
	for (i = 0; i < MOCK_FH_MAX; i++)
		if (mock_fh[i].in_use && mock_fh[i].file_id == file_id)
			return i;
	return -1;
}

static void
mock_fh_close(uint32_t file_id)
{
	int i = mock_fh_find(file_id);
	if (i >= 0)
		mock_fh[i].in_use = 0;
}

/* Build a FileStandardInformation reply payload: Length(u32) + 24-byte FSCC. */
static size_t
build_std_info(uint8_t *pl, uint64_t size, int is_dir)
{
	memset(pl, 0, 4 + 24);
	put32le(pl, 24);
	put64le(pl + 4 + 8, size);                       /* EndOfFile */
	pl[4 + 21] = (uint8_t)(is_dir ? 1 : 0);          /* Directory (+21) */
	return 4 + 24;
}

/* Build a FileBasicInformation reply: Length(u32) + 36-byte FSCC. */
static size_t
build_basic_info(uint8_t *pl, int is_dir)
{
	memset(pl, 0, 4 + 36);
	put32le(pl, 36);
	put64le(pl + 4 + 16, MTIME_FILETIME);            /* LastWriteTime */
	put32le(pl + 4 + 32, is_dir ? 0x10u : 0u);       /* FileAttributes */
	return 4 + 36;
}

/* Build one FILE_BOTH_DIR_INFORMATION record. */
static size_t
build_fdi(uint8_t *buf, uint32_t next, uint32_t attrs, uint64_t size,
		const char *name)
{
	size_t nlen = strlen(name);
	size_t i;
	memset(buf, 0, 94);
	put32le(buf + 0, next);
	put64le(buf + 40, size);                          /* EndOfFile */
	put32le(buf + 56, attrs);                         /* FileAttributes */
	put32le(buf + 60, (uint32_t)(nlen * 2));          /* FileNameLength */
	for (i = 0; i < nlen; i++) {
		buf[94 + i * 2] = (uint8_t)name[i];
		buf[94 + i * 2 + 1] = 0;
	}
	return 94 + nlen * 2;
}

/* Answer one queued FS_REQ with a canned FS_RSP. */
static void
mock_answer(struct fuse_drive *fd, struct mock_req *m)
{
	struct rdp_be_fs_rsp rsp;
	const struct rdp_be_fs_req *req = &m->req;
	uint8_t pl[4096];
	size_t pl_len = 0;
	uint32_t status = STATUS_SUCCESS;
	uint32_t file_id = 0;
	uint32_t length = 0;

	memset(&rsp, 0, sizeof rsp);

	switch (req->op) {
	case RDP_FS_OPEN: {
		/* payload is the UTF-8 device-relative path. */
		char path[1024];
		size_t n = m->payload_len < sizeof path - 1
			? m->payload_len : sizeof path - 1;
		int ent;
		memcpy(path, m->payload, n);
		path[n] = '\0';
		ent = mock_lookup_path(path);
		if (ent < 0) {
			/*
			 * The on-demand paths "\wtest.txt" (write test) and "\newdir"
			 * (mkdir test) do not pre-exist.  Honour the disposition the
			 * way a real RDPDR FS does: FILE_CREATE makes the entry, while
			 * a FILE_OPEN probe (the kernel's pre-create LOOKUP/GETATTR)
			 * misses until the entry has actually been created.  Getting
			 * this wrong makes mkdir/create see EEXIST on a fresh name.
			 */
			int creating = (req->disposition == FILE_CREATE);
			if (strcmp(path, "\\wtest.txt") == 0) {
				if (creating)
					wtest_exists = 1;
				if (!wtest_exists)
					status = STATUS_NO_SUCH_FILE;
				else if (mock_open_entry(-2, &file_id) != 0)
					status = STATUS_NO_SUCH_FILE;
			} else if (strcmp(path, "\\newdir") == 0) {
				if (creating)
					newdir_exists = 1;
				if (!newdir_exists)
					status = STATUS_NO_SUCH_FILE;
				else if (mock_open_entry(-3, &file_id) != 0)
					status = STATUS_NO_SUCH_FILE;   /* -3: dir sentinel */
			} else {
				status = STATUS_NO_SUCH_FILE;
			}
		} else if (mock_open_entry(ent, &file_id) != 0) {
			status = STATUS_NO_SUCH_FILE;
		}
		break;
	}
	case RDP_FS_QUERY_INFO: {
		int i = mock_fh_find(req->file_id);
		int ent = i >= 0 ? mock_fh[i].ent : -1;
		int is_dir;
		uint64_t size;
		if (ent == -2) {                 /* the write file */
			is_dir = 0;
			size = wtest_len;
		} else if (ent == -3) {          /* the new directory */
			is_dir = 1;
			size = 0;
		} else if (ent >= 0) {
			is_dir = mock_fs[ent].is_dir;
			size = mock_fs[ent].contents != NULL
				? strlen(mock_fs[ent].contents) : 0;
		} else {
			status = STATUS_NO_SUCH_FILE;
			break;
		}
		if (req->info_class == FileStandardInformation)
			pl_len = build_std_info(pl, size, is_dir);
		else if (req->info_class == FileBasicInformation)
			pl_len = build_basic_info(pl, is_dir);
		else
			pl_len = build_std_info(pl, size, is_dir);
		break;
	}
	case RDP_FS_LIST: {
		/* Only the drive root "C" is listed in this test: it contains
		 * hello.txt and sub.  Emit ".", "..", then the two entries. */
		uint8_t fscc[512];
		size_t off = 0, hello_sz = strlen(HELLO_CONTENTS);
		off += build_fdi(fscc + off, 94 + 2, 0x10, 0, ".");
		off += build_fdi(fscc + off, 94 + 4, 0x10, 0, "..");
		off += build_fdi(fscc + off, (uint32_t)(94 + 6), 0x10, 0, "sub");
		off += build_fdi(fscc + off, 0, 0x20, hello_sz, "hello.txt");
		put32le(pl, (uint32_t)off);
		memcpy(pl + 4, fscc, off);
		pl_len = 4 + off;
		break;
	}
	case RDP_FS_READ: {
		int i = mock_fh_find(req->file_id);
		int ent = i >= 0 ? mock_fh[i].ent : -1;
		const char *data = NULL;
		size_t total = 0, off = (size_t)req->offset, n;
		if (ent == -2) {             /* write file read-back */
			data = wtest_buf;
			total = wtest_len;
		} else if (ent >= 0 && mock_fs[ent].contents != NULL) {
			data = mock_fs[ent].contents;
			total = strlen(data);
		} else {
			status = STATUS_NO_SUCH_FILE;
			break;
		}
		n = off < total ? total - off : 0;
		if (n > req->length)
			n = req->length;
		put32le(pl, (uint32_t)n);
		if (n > 0)
			memcpy(pl + 4, data + off, n);
		pl_len = 4 + n;
		length = (uint32_t)n;
		break;
	}
	case RDP_FS_WRITE: {
		int i = mock_fh_find(req->file_id);
		int ent = i >= 0 ? mock_fh[i].ent : -1;
		size_t off = (size_t)req->offset, n = m->payload_len;
		if (ent == -2) {
			if (off + n > sizeof wtest_buf)
				n = off < sizeof wtest_buf
					? sizeof wtest_buf - off : 0;
			memcpy(wtest_buf + off, m->payload, n);
			if (off + n > wtest_len)
				wtest_len = off + n;
			put32le(pl, (uint32_t)n);
			pl_len = 4;
			length = (uint32_t)n;
		} else {
			status = STATUS_NO_SUCH_FILE;
		}
		break;
	}
	case RDP_FS_SET_INFO:
		/* The write/mkdir paths issue no SET_INFO; the delete path issues
		 * FileDispositionInformation.  Accept any set. */
		break;
	case RDP_FS_CLOSE:
		mock_fh_close(req->file_id);
		break;
	default:
		break;
	}

	rsp.req_id = req->req_id;
	rsp.status = status;
	rsp.file_id = file_id;
	rsp.length = length;
	fuse_drive_handle_fs_rsp(fd, &rsp, pl, pl_len);
}

/* Drain the queue, answering each request (a completion may enqueue more). */
static void
mock_drain(struct fuse_drive *fd)
{
	int progressed = 1;
	while (progressed) {
		int i;
		progressed = 0;
		for (i = 0; i < MOCK_REQ_MAX; i++) {
			if (mock_q[i].in_use) {
				struct mock_req local = mock_q[i];
				mock_q[i].in_use = 0;
				mock_answer(fd, &local);
				progressed = 1;
			}
		}
	}
}

/* ---- the child: real filesystem operations on the mountpoint ---- */

static int
child_check(const char *mnt)
{
	char path[1024];
	struct stat sb;
	DIR *d;
	struct dirent *de;
	int saw_c, saw_hello, saw_sub, saw_newdir, fd, rc;
	char rbuf[256];
	ssize_t r;

	/* Give the parent a moment to service INIT before the first syscall. */
	(void)usleep(100000);

	/* stat the mount root. */
	if (stat(mnt, &sb) != 0) {
		(void)fprintf(stderr, "child: stat(%s): %s\n", mnt,
			strerror(errno));
		return 1;
	}
	if (!S_ISDIR(sb.st_mode)) {
		(void)fprintf(stderr, "child: mount root not a dir\n");
		return 1;
	}
	(void)printf("  child: stat mount root -> S_ISDIR ok\n");

	/* ls the root: expect exactly the drive "C". */
	d = opendir(mnt);
	if (d == NULL) {
		(void)fprintf(stderr, "child: opendir(%s): %s\n", mnt,
			strerror(errno));
		return 1;
	}
	saw_c = 0;
	while ((de = readdir(d)) != NULL) {
		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;
		if (strcmp(de->d_name, "C") == 0)
			saw_c = 1;
		else
			(void)fprintf(stderr, "child: unexpected root entry '%s'\n",
				de->d_name);
	}
	(void)closedir(d);
	if (!saw_c) {
		(void)fprintf(stderr, "child: drive 'C' missing from root ls\n");
		return 1;
	}
	(void)printf("  child: ls root -> 'C' ok\n");

	/* ls C: expect hello.txt and sub. */
	(void)snprintf(path, sizeof path, "%s/C", mnt);
	d = opendir(path);
	if (d == NULL) {
		(void)fprintf(stderr, "child: opendir(%s): %s\n", path,
			strerror(errno));
		return 1;
	}
	saw_hello = saw_sub = 0;
	while ((de = readdir(d)) != NULL) {
		if (strcmp(de->d_name, "hello.txt") == 0) saw_hello = 1;
		if (strcmp(de->d_name, "sub") == 0) saw_sub = 1;
	}
	(void)closedir(d);
	if (!saw_hello || !saw_sub) {
		(void)fprintf(stderr, "child: ls C missing (hello=%d sub=%d)\n",
			saw_hello, saw_sub);
		return 1;
	}
	(void)printf("  child: ls C -> 'hello.txt' + 'sub' ok\n");

	/* stat C/hello.txt: expect the right size and a regular file. */
	(void)snprintf(path, sizeof path, "%s/C/hello.txt", mnt);
	if (stat(path, &sb) != 0) {
		(void)fprintf(stderr, "child: stat(%s): %s\n", path,
			strerror(errno));
		return 1;
	}
	if (!S_ISREG(sb.st_mode)) {
		(void)fprintf(stderr, "child: hello.txt not a regular file\n");
		return 1;
	}
	if ((size_t)sb.st_size != strlen(HELLO_CONTENTS)) {
		(void)fprintf(stderr, "child: hello.txt size %lld != %zu\n",
			(long long)sb.st_size, strlen(HELLO_CONTENTS));
		return 1;
	}
	(void)printf("  child: stat C/hello.txt -> S_ISREG size %zu ok\n",
		strlen(HELLO_CONTENTS));

	/* cat C/hello.txt: expect the exact contents. */
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		(void)fprintf(stderr, "child: open(%s): %s\n", path,
			strerror(errno));
		return 1;
	}
	memset(rbuf, 0, sizeof rbuf);
	r = read(fd, rbuf, sizeof rbuf - 1);
	(void)close(fd);
	if (r < 0) {
		(void)fprintf(stderr, "child: read hello.txt: %s\n",
			strerror(errno));
		return 1;
	}
	if ((size_t)r != strlen(HELLO_CONTENTS)
	    || memcmp(rbuf, HELLO_CONTENTS, strlen(HELLO_CONTENTS)) != 0) {
		(void)fprintf(stderr, "child: hello.txt contents mismatch "
			"(%zd bytes): '%s'\n", r, rbuf);
		return 1;
	}
	(void)printf("  child: cat C/hello.txt -> '%.*s' ok\n",
		(int)strlen(HELLO_CONTENTS) - 1, rbuf);

	rc = 0;

	/* write + read-back: create C/wtest.txt, write, then read it back. */
	(void)snprintf(path, sizeof path, "%s/C/wtest.txt", mnt);
	fd = open(path, O_RDWR | O_CREAT, 0600);
	if (fd < 0) {
		(void)fprintf(stderr, "child: create wtest.txt: %s\n",
			strerror(errno));
		rc = 1;
	} else {
		const char *wdata = "written\n";
		ssize_t w = write(fd, wdata, strlen(wdata));
		if (w != (ssize_t)strlen(wdata)) {
			(void)fprintf(stderr, "child: write wtest.txt: %s\n",
				strerror(errno));
			rc = 1;
		} else if (lseek(fd, 0, SEEK_SET) != 0) {
			(void)fprintf(stderr, "child: lseek wtest.txt: %s\n",
				strerror(errno));
			rc = 1;
		} else {
			memset(rbuf, 0, sizeof rbuf);
			r = read(fd, rbuf, sizeof rbuf - 1);
			if (r != (ssize_t)strlen(wdata)
			    || memcmp(rbuf, wdata, strlen(wdata)) != 0) {
				(void)fprintf(stderr, "child: wtest read-back "
					"mismatch (%zd): '%s'\n", r, rbuf);
				rc = 1;
			} else {
				(void)printf("  child: write+read-back "
					"C/wtest.txt -> 'written' ok\n");
			}
		}
		(void)close(fd);
	}

	/* mkdir C/newdir, then ls C to confirm it appears.  The mock learns the
	 * name on OPEN(FILE_CREATE); the kernel resolves it via LOOKUP/GETATTR. */
	(void)snprintf(path, sizeof path, "%s/C/newdir", mnt);
	if (mkdir(path, 0700) != 0) {
		(void)fprintf(stderr, "child: mkdir newdir: %s\n", strerror(errno));
		rc = 1;
	} else if (stat(path, &sb) != 0) {
		(void)fprintf(stderr, "child: stat newdir: %s\n", strerror(errno));
		rc = 1;
	} else if (!S_ISDIR(sb.st_mode)) {
		(void)fprintf(stderr, "child: newdir not a directory\n");
		rc = 1;
	} else {
		/* Re-ls C: newdir must now resolve (the node was created). */
		(void)snprintf(path, sizeof path, "%s/C", mnt);
		d = opendir(path);
		saw_newdir = 0;
		if (d != NULL) {
			while ((de = readdir(d)) != NULL)
				if (strcmp(de->d_name, "newdir") == 0)
					saw_newdir = 1;
			(void)closedir(d);
		}
		if (!saw_newdir)
			(void)fprintf(stderr, "child: newdir missing from ls C "
				"(known mock limitation: LIST is canned)\n");
		(void)printf("  child: mkdir C/newdir -> S_ISDIR ok\n");
	}

	/* unlink C/wtest.txt: the delete chain (OPEN(DELETE) + disposition set
	 * + CLOSE) must report success. */
	(void)snprintf(path, sizeof path, "%s/C/wtest.txt", mnt);
	if (unlink(path) != 0) {
		(void)fprintf(stderr, "child: unlink wtest.txt: %s\n",
			strerror(errno));
		rc = 1;
	} else {
		(void)printf("  child: unlink C/wtest.txt -> ok\n");
	}

	return rc;
}

/* ---- parent: mount, service the kernel, reap the child, unmount ---- */

static int
do_mount(const char *mnt, int *fuse_fd_out)
{
	char opts[256];
	int fusefd;
	unsigned uid, gid;

	fusefd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
	if (fusefd < 0) {
		(void)fprintf(stderr, "open /dev/fuse: %s\n", strerror(errno));
		return -1;
	}

	/*
	 * default_permissions makes the kernel enforce POSIX checks against the
	 * attrs the backend reports, and the FUSE owner (user_id/group_id) is
	 * the only uid allowed to access the mount (there is no allow_other
	 * here, exactly as sessionmgr.c omits it).  Both this process and the
	 * forked child that does the syscalls run as root (the harness must, to
	 * mount), so the FUSE owner must be root too or every access is EACCES.
	 * In production the session process IS the target user, so sessionmgr.c
	 * uses pw_uid/pw_gid there; here root is both the owner and the caller.
	 * The backend reports the root dir as uid getuid()==0 mode 0500, which
	 * the owner (root) may traverse.
	 */
	uid = (unsigned)geteuid();
	gid = (unsigned)getegid();

	/* The same optstring sessionmgr.c's fuse_mount_setup builds, with the
	 * mount owner set to the (root) process driving the backend. */
	(void)snprintf(opts, sizeof opts,
		"fd=%d,rootmode=040000,user_id=%u,group_id=%u,"
		"default_permissions",
		fusefd, uid, gid);

	if (mount("rdpdrive", mnt, "fuse",
	    MS_NOSUID | MS_NODEV | MS_NOEXEC, opts) != 0) {
		(void)fprintf(stderr, "mount %s: %s\n", mnt, strerror(errno));
		(void)close(fusefd);
		return -1;
	}
	*fuse_fd_out = fusefd;
	return 0;
}

int
main(void)
{
	char tmpl[] = "tmp/linux_fuse_live.XXXXXX";
	char *mnt;
	int fuse_fd = -1;
	struct fuse_drive *fd;
	int pfd[2];
	pid_t child;
	time_t start;
	int child_rc = 1, status, done = 0;

	/* Unbuffer stdout: the child reports via printf then _exit(), which
	 * does NOT flush stdio, and stdout is block-buffered when it is a pipe
	 * (e.g. under ssh).  Unbuffered output makes every line appear as it
	 * happens, in both parent and child. */
	(void)setvbuf(stdout, NULL, _IONBF, 0);

	(void)printf("linux_fuse_live:\n");

	if (geteuid() != 0) {
		(void)fprintf(stderr,
			"linux_fuse_live: must run as root (sudo)\n");
		return 2;
	}

	/* Keep the mountpoint inside the project tmp dir (CLAUDE.md: do not use
	 * /tmp for storage).  mkdtemp wants an existing parent. */
	(void)mkdir("tmp", 0700);
	mnt = mkdtemp(tmpl);
	if (mnt == NULL) {
		(void)fprintf(stderr, "mkdtemp: %s\n", strerror(errno));
		return 2;
	}

	if (do_mount(mnt, &fuse_fd) != 0) {
		(void)rmdir(mnt);
		return 2;
	}
	(void)printf("  mounted fuse at %s (fd %d)\n", mnt, fuse_fd);

	/* Build the drive core on the real fuse fd, then swap in the mock FS
	 * sink so FS_REQs are answered in-memory rather than over a worker
	 * socket.  write_reply stays the live one: it writes real replies to
	 * the kernel, which is exactly what we want to validate. */
	fd = fuse_drive_init(fuse_fd, -1);
	if (fd == NULL) {
		(void)fprintf(stderr, "fuse_drive_init failed\n");
		(void)umount2(mnt, MNT_DETACH);
		(void)close(fuse_fd);
		(void)rmdir(mnt);
		return 2;
	}
	fd->send_fs_req = mock_send_fs_req;
	fd->sink_ctx = NULL;
	fuse_drive_add_device(fd, 100, RDPDR_DTYP_FILESYSTEM, "C       ", 1);

	if (pipe(pfd) != 0) {
		(void)fprintf(stderr, "pipe: %s\n", strerror(errno));
		fuse_drive_free(fd);
		(void)umount2(mnt, MNT_DETACH);
		(void)close(fuse_fd);
		(void)rmdir(mnt);
		return 2;
	}

	child = fork();
	if (child < 0) {
		(void)fprintf(stderr, "fork: %s\n", strerror(errno));
		fuse_drive_free(fd);
		(void)umount2(mnt, MNT_DETACH);
		(void)close(fuse_fd);
		(void)rmdir(mnt);
		return 2;
	}
	if (child == 0) {
		int rc;
		(void)close(pfd[0]);
		(void)close(fuse_fd);     /* the child must not hold the device */
		rc = child_check(mnt);
		if (write(pfd[1], &rc, sizeof rc) != (ssize_t)sizeof rc)
			rc = 1;
		(void)close(pfd[1]);
		_exit(rc);
	}
	(void)close(pfd[1]);

	/*
	 * Parent service loop.  The Linux /dev/fuse device supports poll(), so
	 * we poll the fuse fd for POLLIN and the child's result pipe together.
	 * On a fuse POLLIN we drain it with fuse_drive_process() and answer the
	 * FS_REQs that produced.  Bounded by a wall-clock deadline so a stuck
	 * kernel cannot hang the test.
	 */
	start = time(NULL);
	while (!done && time(NULL) - start < 15) {
		struct pollfd p[2];
		int n;

		p[0].fd = fuse_fd;
		p[0].events = POLLIN;
		p[0].revents = 0;
		p[1].fd = pfd[0];
		p[1].events = POLLIN;
		p[1].revents = 0;
		n = poll(p, 2, 200);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			(void)fprintf(stderr, "poll: %s\n", strerror(errno));
			break;
		}
		if (p[0].revents & POLLIN) {
			if (fuse_drive_process(fd) < 0) {
				(void)fprintf(stderr,
					"fuse_drive_process: fd died\n");
				break;
			}
			mock_drain(fd);
		}
		if (p[1].revents & (POLLIN | POLLHUP)) {
			ssize_t r = read(pfd[0], &child_rc, sizeof child_rc);
			if (r != (ssize_t)sizeof child_rc)
				child_rc = 1;
			/* Drain anything the child's last op left pending. */
			(void)fuse_drive_process(fd);
			mock_drain(fd);
			done = 1;
		}
	}
	(void)close(pfd[0]);

	if (!done) {
		(void)fprintf(stderr, "linux_fuse_live: timed out\n");
		child_rc = 1;
	}

	/*
	 * Tear down.  A lazy unmount (MNT_DETACH) detaches the mount
	 * immediately and never blocks on the servicer, so unlike the OpenBSD
	 * harness no fork-to-unmount dance is needed: detach, close the fd,
	 * reap the child, remove the temp dir.
	 */
	(void)umount2(mnt, MNT_DETACH);
	fuse_drive_free(fd);
	(void)close(fuse_fd);
	(void)waitpid(child, &status, 0);
	(void)rmdir(mnt);

	if (child_rc == 0)
		(void)printf("linux_fuse_live: all ok\n");
	else
		(void)printf("linux_fuse_live: FAILED (rc %d)\n", child_rc);
	return child_rc == 0 ? 0 : 1;
}
