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
 *
 * fuse_drive_obsd.c -- OpenBSD fusebuf wire backend for the RDPDR drive
 * redirection core (read and write paths).
 *
 * This is the only file that includes <sys/fusebuf.h>.  It owns the OpenBSD
 * kernel wire format: recv parses one struct fusebuf (a 56-byte fb_hdr, a
 * 128-byte FD union, then a separate fb_dat blob) into the OS neutral struct
 * fd_request, and the emit_* turn the core's OS neutral replies (struct
 * fd_attr, the dirent batch) into the struct stat / native dirent bytes the
 * kernel expects.  The FBT_INIT handshake is answered here too.
 *
 * Wire framing (verified from the OpenBSD 7.9 kernel and headers):
 *
 *   A request arrives in one readv of two iovecs: iov[0] is the 184-byte
 *   hdr+FD region (offsetof(struct fusebuf, fb_dat)), iov[1] is the fb_dat
 *   data buffer.  The device does not support partial reads, so the read
 *   buffer is one block sized 184 + FUSEBUFMAXSIZE; the data length is
 *   (bytes_read - 184).
 *
 *   A reply leaves in one write of a single contiguous block: the 184-byte
 *   hdr+FD region (the fb_uuid echoed back, fb_err and fb_len updated)
 *   immediately followed by the fb_dat (fb_len bytes).  The kernel reads the
 *   whole reply in one write and rejects a split one, a reply where both
 *   fb_len and fb_err are non-zero, or where fb_len exceeds the request's
 *   fb_io_len.
 *
 * Async carry.  Like the Linux backend, the emit_* run from the RDP_BE_FS_RSP
 * completion, long after recv returned, so the original request header must
 * survive the gap.  The core threads a single uint64_t "unique" from recv to
 * the matching emit, so we carry the fb_uuid in it (it is itself a uint64_t).
 * The reply also needs the fb_type and the request's fb_io_len (for the READ
 * and READDIR length checks); those live in a small fixed in-flight context
 * table keyed by fb_uuid, allocated in recv and freed when the matching emit
 * fires.  Inline replies (INIT, DESTROY, FLUSH, ACCESS, STATFS) never enter
 * the dispatch path, so they reply straight from the parsed header and need
 * no slot.
 */

#include "fuse_drive.h"

#if HAVE_OBSD_FUSE

#include "fuse_drive_internal.h"

#include "../channels/rdpdr.h"   /* FILE_READ_DATA, FILE_WRITE_DATA */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/dirent.h>
#include <sys/fusebuf.h>
#include <sys/uio.h>
#include <sys/event.h>
#include <sys/time.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/*
 * The mount root inode.  The kernel uses FUSE_ROOTINO (defined ((ino_t)1) in
 * the _KERNEL-only miscfs/fuse/fusefs.h), which matches the core's
 * FD_ROOT_ID.  Defined here so we never reach into a kernel-only header.
 */
#define FD_OBSD_ROOTINO   ((ino_t)1)

/*
 * The fixed hdr+FD region of a struct fusebuf, i.e. everything up to the
 * fb_dat pointer.  Computed from the host struct so it is never hardcoded.
 */
#define FD_FB_HDRLEN      (offsetof(struct fusebuf, fb_dat))

/*
 * Cap the data payload at the kernel maximum.  The recv buffer is one block
 * of header region plus this, so the kernel's single non-partial read always
 * fits.  4 MiB matches FUSEBUFMAXSIZE.
 */
#define FD_OBSD_MAXDATA   ((size_t)FUSEBUFMAXSIZE)
#define FD_OBSD_BUFSZ     (FD_FB_HDRLEN + FD_OBSD_MAXDATA)

/*
 * One in-flight request context, keyed by fb_uuid.  Carries the bits of the
 * request header the reply must echo or validate against across the async
 * gap between recv and the emit_* that the FS_RSP completion runs.
 */
struct fd_obsd_slot {
	int      in_use;
	uint64_t uuid;     /* fb_uuid, also the core's "unique" */
	int      type;     /* fb_type, echoed in the reply header */
	uint64_t ino;      /* request fb_ino */
	size_t   io_len;   /* request fb_io_len (READ/READDIR max) */
};

/*
 * The OpenBSD backend context.  It hangs off fuse_drive via a single static
 * instance because the session is single threaded and runs exactly one drive
 * mount.  The recv buffer is large to satisfy the device's no-partial-read
 * rule; keeping it here avoids a multi-megabyte stack frame.
 */
struct fd_obsd_ctx {
	uint8_t buf[FD_OBSD_BUFSZ];
	struct fd_obsd_slot slots[FD_INFLIGHT_MAX];
	int kq;        /* kqueue for the read-readiness probe; -1 until built */
	int kq_fuse;   /* the fuse fd registered on kq, to detect a change */
};

/* kq/kq_fuse start at -1 (no kqueue yet); the buffers and slots zero-init. */
static struct fd_obsd_ctx fd_obsd_ctx = { .kq = -1, .kq_fuse = -1 };

/*
 * Is a fusebuf ready to read on the fuse fd?
 *
 * The OpenBSD fusefs device has no d_poll, so poll()/select() fall back to
 * seltrue and ALWAYS report the fd readable -- a blocking readv on an empty
 * device would then hang the whole single-threaded session loop.  The device
 * does implement an EVFILT_READ kqfilter that fires only when its input queue
 * is non-empty, so gate every read through a non-blocking kevent probe: the
 * readv runs only when exactly one fusebuf is actually queued and thus never
 * blocks.  The kqueue is built once and reused.  Returns 1 if readable, 0 if
 * not, and -1 on a kqueue error (the caller then treats it as not-ready).
 */
static int
fd_obsd_readable(struct fuse_drive *fd)
{
	struct kevent ev;
	struct timespec zero = { 0, 0 };
	int n;

	/* (Re)build the kqueue if it is missing or the fuse fd changed. */
	if (fd_obsd_ctx.kq < 0 || fd_obsd_ctx.kq_fuse != fd->fuse_fd) {
		struct kevent ch;
		if (fd_obsd_ctx.kq >= 0)
			(void)close(fd_obsd_ctx.kq);
		fd_obsd_ctx.kq = kqueue();
		if (fd_obsd_ctx.kq < 0)
			return -1;
		EV_SET(&ch, fd->fuse_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
		if (kevent(fd_obsd_ctx.kq, &ch, 1, NULL, 0, NULL) != 0) {
			(void)close(fd_obsd_ctx.kq);
			fd_obsd_ctx.kq = -1;
			return -1;
		}
		fd_obsd_ctx.kq_fuse = fd->fuse_fd;
	}

	do {
		n = kevent(fd_obsd_ctx.kq, NULL, 0, &ev, 1, &zero);
	} while (n < 0 && errno == EINTR);
	if (n < 0)
		return -1;
	return n > 0 ? 1 : 0;
}

/* slot table */

static struct fd_obsd_slot *
fd_obsd_slot_alloc(uint64_t uuid, int type, uint64_t ino, size_t io_len)
{
	int i;
	for (i = 0; i < FD_INFLIGHT_MAX; i++) {
		struct fd_obsd_slot *s = &fd_obsd_ctx.slots[i];
		if (!s->in_use) {
			s->in_use = 1;
			s->uuid = uuid;
			s->type = type;
			s->ino = ino;
			s->io_len = io_len;
			return s;
		}
	}
	return NULL;
}

static struct fd_obsd_slot *
fd_obsd_slot_find(uint64_t uuid)
{
	int i;
	for (i = 0; i < FD_INFLIGHT_MAX; i++) {
		struct fd_obsd_slot *s = &fd_obsd_ctx.slots[i];
		if (s->in_use && s->uuid == uuid)
			return s;
	}
	return NULL;
}

static void
fd_obsd_slot_free(struct fd_obsd_slot *s)
{
	if (s != NULL)
		s->in_use = 0;
}

/*
 * Write one reply.  The OpenBSD kernel reads the whole reply (the 184-byte
 * hdr+FD region plus the fb_dat data) in a SINGLE write and rejects anything
 * split across writes (fusewrite requires uio_resid == sizeof(FD) + fb_len
 * after consuming the header), so the reply must be one contiguous block.
 * Assemble it in the reply buffer and write it once.  hdr is the FD_FB_HDRLEN
 * header region; data/data_len is the fb_dat blob (empty for attr replies).
 */
static void
fd_obsd_write_reply(struct fuse_drive *fd, const uint8_t *hdr,
		const uint8_t *data, size_t data_len)
{
	if (data_len > FD_OBSD_MAXDATA)
		data_len = FD_OBSD_MAXDATA;
	if (hdr != fd_obsd_ctx.buf)
		memmove(fd_obsd_ctx.buf, hdr, FD_FB_HDRLEN);
	if (data_len > 0 && data != fd_obsd_ctx.buf + FD_FB_HDRLEN)
		memmove(fd_obsd_ctx.buf + FD_FB_HDRLEN, data, data_len);
	(void)fd->write_reply(fd, fd_obsd_ctx.buf, FD_FB_HDRLEN + data_len);
}

/*
 * Build a reply header region into hdr (FD_FB_HDRLEN bytes) for an in-flight
 * request identified by its slot.  fh_next is kernel private and is zeroed.
 * The caller fills the FD union (stat/io) afterwards as the op needs.
 */
static void
fd_obsd_build_hdr(uint8_t *hdr, const struct fd_obsd_slot *s, int err,
		size_t len)
{
	struct fusebuf *fb = (struct fusebuf *)hdr;

	memset(hdr, 0, FD_FB_HDRLEN);
	/* fh_next stays zeroed: the kernel owns that link. */
	fb->fb_uuid = s->uuid;
	fb->fb_type = s->type;
	fb->fb_ino = (ino_t)s->ino;
	fb->fb_err = err;
	fb->fb_len = len;
}

/* Map an OS neutral struct fd_attr into the reply's struct stat (fb_attr).
 * The permission bits pass through unchanged; the FD_S_IF* type bits become
 * S_IFDIR/S_IFREG, and the OpenBSD specific uid/gid/blocks are filled here so
 * the core never has to know about them.  Times are unix seconds. */
static void
fd_obsd_fill_stat(const struct fd_attr *a, struct stat *st)
{
	memset(st, 0, sizeof *st);
	st->st_ino = (ino_t)a->ino;
	st->st_size = (off_t)a->size;
	st->st_nlink = (nlink_t)(a->nlink != 0 ? a->nlink : 1);
	st->st_mode = (mode_t)(a->mode & ~(uint32_t)FD_S_IFMT);
	if ((a->mode & FD_S_IFMT) == FD_S_IFDIR)
		st->st_mode |= S_IFDIR;
	else if ((a->mode & FD_S_IFMT) == FD_S_IFREG)
		st->st_mode |= S_IFREG;
	st->st_uid = getuid();
	st->st_gid = getgid();
	st->st_blksize = 4096;
	st->st_blocks = (blkcnt_t)((a->size + 511) / 512);
	st->st_atim.tv_sec = (time_t)a->atime;
	st->st_atim.tv_nsec = 0;
	st->st_mtim.tv_sec = (time_t)a->mtime;
	st->st_mtim.tv_nsec = 0;
	st->st_ctim.tv_sec = (time_t)a->ctime;
	st->st_ctim.tv_nsec = 0;
}

/* emit_* (run from the FS_RSP completion via the saved slot) */

/*
 * Reply GETATTR / SETATTR.  The struct stat travels in the FD union, not in
 * fb_dat, so fb_len stays 0.
 */
static void
obsd_emit_attr(struct fuse_drive *fd, uint64_t unique, const struct fd_attr *a)
{
	struct fd_obsd_slot *s = fd_obsd_slot_find(unique);
	uint8_t hdr[FD_FB_HDRLEN];
	struct fusebuf *fb = (struct fusebuf *)hdr;

	if (s == NULL)
		return;
	fd_obsd_build_hdr(hdr, s, 0, 0);
	fd_obsd_fill_stat(a, &fb->fb_attr);
	fd_obsd_write_reply(fd, hdr, NULL, 0);
	fd_obsd_slot_free(s);
}

/*
 * Reply LOOKUP.  The kernel learns the child inode from the reply fb_ino and
 * the child attributes from the FD union stat.
 */
static void
obsd_emit_entry(struct fuse_drive *fd, uint64_t unique, uint64_t nodeid,
		const struct fd_attr *a)
{
	struct fd_obsd_slot *s = fd_obsd_slot_find(unique);
	uint8_t hdr[FD_FB_HDRLEN];
	struct fusebuf *fb = (struct fusebuf *)hdr;

	if (s == NULL)
		return;
	fd_obsd_build_hdr(hdr, s, 0, 0);
	fb->fb_ino = (ino_t)nodeid;   /* the looked-up child inode */
	fd_obsd_fill_stat(a, &fb->fb_attr);
	fd_obsd_write_reply(fd, hdr, NULL, 0);
	fd_obsd_slot_free(s);
}

/*
 * Reply OPEN / OPENDIR.  The handle goes in fb_io_fd.  direct_io has no
 * fusebuf equivalent and is ignored.
 */
static void
obsd_emit_open(struct fuse_drive *fd, uint64_t unique, uint64_t fh,
		int direct_io)
{
	struct fd_obsd_slot *s = fd_obsd_slot_find(unique);
	uint8_t hdr[FD_FB_HDRLEN];
	struct fusebuf *fb = (struct fusebuf *)hdr;

	(void)direct_io;
	if (s == NULL)
		return;
	fd_obsd_build_hdr(hdr, s, 0, 0);
	fb->fb_io_fd = fh;
	fd_obsd_write_reply(fd, hdr, NULL, 0);
	fd_obsd_slot_free(s);
}

/*
 * CREATE has no fusebuf opcode: the OpenBSD kernel maps fusefs_create onto
 * FBT_MKNOD, which the core serves through emit_entry, so this emitter is
 * never reached.  Reply ENOSYS defensively in case a future kernel adds one.
 */
static void
obsd_emit_create(struct fuse_drive *fd, uint64_t unique, uint64_t nodeid,
		uint64_t fh, const struct fd_attr *a)
{
	struct fd_obsd_slot *s = fd_obsd_slot_find(unique);

	(void)nodeid;
	(void)fh;
	(void)a;
	if (s == NULL)
		return;
	{
		uint8_t hdr[FD_FB_HDRLEN];
		fd_obsd_build_hdr(hdr, s, ENOSYS, 0);
		fd_obsd_write_reply(fd, hdr, NULL, 0);
	}
	fd_obsd_slot_free(s);
}

/*
 * Reply READ.  The data travels in fb_dat with fb_len set to the byte count.
 * The core has already capped len to the request's fb_io_len (it set
 * f->read_size from the request size), so the kernel's fb_len <= fb_io_len
 * check always holds; clamp again defensively against the saved io_len.
 */
static void
obsd_emit_read(struct fuse_drive *fd, uint64_t unique, const uint8_t *data,
		uint32_t len)
{
	struct fd_obsd_slot *s = fd_obsd_slot_find(unique);
	uint8_t hdr[FD_FB_HDRLEN];
	size_t n = len;

	if (s == NULL)
		return;
	if (n > s->io_len)
		n = s->io_len;
	fd_obsd_build_hdr(hdr, s, 0, n);
	fd_obsd_write_reply(fd, hdr, data, n);
	fd_obsd_slot_free(s);
}

/*
 * Reply WRITE.  The kernel reads the byte count back from the reply's
 * fb_io_len (the FD union), not from fb_len: fusefs_write computes
 * diff = len - fbuf->fb_io_len.  So the count goes in fb_io_len with fb_len 0
 * and fb_err 0, and the reply is a single header-only write (no fb_dat).
 */
static void
obsd_emit_write(struct fuse_drive *fd, uint64_t unique, uint32_t count)
{
	struct fd_obsd_slot *s = fd_obsd_slot_find(unique);
	uint8_t hdr[FD_FB_HDRLEN];
	struct fusebuf *fb = (struct fusebuf *)hdr;

	if (s == NULL)
		return;
	fd_obsd_build_hdr(hdr, s, 0, 0);
	fb->fb_io_len = (size_t)count;   /* bytes written, read via fb_io_len */
	fd_obsd_write_reply(fd, hdr, NULL, 0);
	fd_obsd_slot_free(s);
}

/*
 * Native dirent record size: the fixed header up to d_name, plus the name
 * with its NUL, rounded up to an 8-byte boundary (the kernel's GENERIC_DIRSIZ,
 * which is not exported to userland).  offsetof keeps this arch correct.
 */
static size_t
fd_obsd_dirsiz(size_t namelen)
{
	return offsetof(struct dirent, d_name) + ((namelen + 1 + 7) & ~(size_t)7);
}

/*
 * Pack the decoded dirents into one native struct dirent batch in fb_dat.
 *
 * The core lists a directory in a single batch: the first READDIR (offset 0)
 * gets every entry, and any later READDIR (offset > 0) gets an empty reply,
 * which the kernel reads as EOF.  We mirror that by emitting the whole batch
 * on the first call and an empty fb_len==0 reply otherwise; the offset==0 vs
 * else split is decided by the core (it passes n==0 for the EOF case).
 *
 * Each record is laid out so the kernel validator accepts it: d_reclen is the
 * 8-byte aligned record length (> the d_name offset), d_fileno is the entry
 * inode, d_off is the cursor just past this record, d_type is DT_DIR/DT_REG,
 * d_namlen is the strlen with no NUL, and the name plus its padding are zero
 * filled.  No name may contain '/'.  We stop before any record that would
 * exceed the requested fb_io_len or the data buffer.
 */
static size_t
obsd_emit_dirent_batch(struct fuse_drive *fd, uint64_t unique,
		const struct fd_dirent *ents, size_t n, uint32_t maxbytes)
{
	struct fd_obsd_slot *s = fd_obsd_slot_find(unique);
	uint8_t hdr[FD_FB_HDRLEN];
	uint8_t *out = fd_obsd_ctx.buf + FD_FB_HDRLEN;
	size_t off = 0;
	size_t want;
	size_t i;

	if (s == NULL)
		return 0;

	/* Bound the batch by what the kernel asked, the saved request io_len,
	 * and our data buffer. */
	want = maxbytes;
	if (want > s->io_len)
		want = s->io_len;
	if (want > FD_OBSD_MAXDATA)
		want = FD_OBSD_MAXDATA;

	for (i = 0; i < n; i++) {
		size_t namelen = ents[i].name_len;
		size_t reclen;
		struct dirent de;

		if (namelen == 0 || namelen > MAXNAMLEN)
			continue;   /* the kernel rejects empty / over-long names */
		if (memchr(ents[i].name, '/', namelen) != NULL)
			continue;   /* a slash is illegal in a single component */
		reclen = fd_obsd_dirsiz(namelen);
		if (off + reclen > want)
			break;

		memset(&de, 0, sizeof de);
		de.d_fileno = (ino_t)ents[i].ino;
		de.d_off = (off_t)(off + reclen);   /* cursor past this record */
		de.d_reclen = (uint16_t)reclen;
		de.d_type = ents[i].is_dir ? DT_DIR : DT_REG;
		de.d_namlen = (uint8_t)namelen;

		/* Copy the fixed header (up to d_name) then the name; the d_name
		 * tail and the alignment padding are zeroed in the buffer below. */
		memset(out + off, 0, reclen);
		memcpy(out + off, &de, offsetof(struct dirent, d_name));
		memcpy(out + off + offsetof(struct dirent, d_name),
			ents[i].name, namelen);
		off += reclen;
	}

	fd_obsd_build_hdr(hdr, s, 0, off);
	fd_obsd_write_reply(fd, hdr, fd_obsd_ctx.buf + FD_FB_HDRLEN, off);
	fd_obsd_slot_free(s);
	return off;
}

/* Reply success with no body (RELEASE / RELEASEDIR / FLUSH / ACCESS). */
static void
obsd_emit_ok(struct fuse_drive *fd, uint64_t unique)
{
	struct fd_obsd_slot *s = fd_obsd_slot_find(unique);
	uint8_t hdr[FD_FB_HDRLEN];

	if (s == NULL)
		return;
	fd_obsd_build_hdr(hdr, s, 0, 0);
	fd_obsd_write_reply(fd, hdr, NULL, 0);
	fd_obsd_slot_free(s);
}

/*
 * Reply an error.  The core passes the errno the way the OS expects it; the
 * Linux backend wants a negative value, the OpenBSD kernel wants a positive
 * errno in fb_err, so take the magnitude.  fb_len must be 0 when fb_err is
 * set (the kernel rejects a reply carrying both).
 */
static void
obsd_emit_error(struct fuse_drive *fd, uint64_t unique, int error)
{
	struct fd_obsd_slot *s = fd_obsd_slot_find(unique);
	uint8_t hdr[FD_FB_HDRLEN];
	int err = error < 0 ? -error : error;

	if (s == NULL)
		return;
	fd_obsd_build_hdr(hdr, s, err, 0);
	fd_obsd_write_reply(fd, hdr, NULL, 0);
	fd_obsd_slot_free(s);
}

/* Reply an inline header-only result without going through a slot.  Used for
 * the handshake and the always-allow ops the kernel issues before (or instead
 * of) any node operation. */
static void
fd_obsd_reply_inline(struct fuse_drive *fd, const struct fusebuf *req,
		int err, size_t len)
{
	uint8_t hdr[FD_FB_HDRLEN];
	struct fusebuf *fb = (struct fusebuf *)hdr;

	memset(hdr, 0, FD_FB_HDRLEN);
	fb->fb_uuid = req->fb_uuid;
	fb->fb_type = req->fb_type;
	fb->fb_ino = req->fb_ino;
	fb->fb_err = err;
	fb->fb_len = len;
	fd_obsd_write_reply(fd, hdr, NULL, 0);
}

/* Reply STATFS inline with a sane, valid statvfs in the FD union. */
static void
fd_obsd_reply_statfs(struct fuse_drive *fd, const struct fusebuf *req)
{
	uint8_t hdr[FD_FB_HDRLEN];
	struct fusebuf *fb = (struct fusebuf *)hdr;

	memset(hdr, 0, FD_FB_HDRLEN);
	fb->fb_uuid = req->fb_uuid;
	fb->fb_type = req->fb_type;
	fb->fb_ino = req->fb_ino;
	fb->fb_err = 0;
	fb->fb_len = 0;
	memset(&fb->fb_stat, 0, sizeof fb->fb_stat);
	fb->fb_stat.f_bsize = 4096;
	fb->fb_stat.f_frsize = 4096;
	fb->fb_stat.f_namemax = MAXNAMLEN;
	fd_obsd_write_reply(fd, hdr, NULL, 0);
}

/*
 * Pull one NUL-terminated leaf name out of the fb_dat blob at offset off.
 * The kernel appends a single NUL-terminated component for MKNOD/MKDIR/UNLINK/
 * RMDIR, and two back to back for RENAME, so this is called once per name.
 * Returns a pointer to the name and its length via *name_len, or NULL on a
 * malformed (unterminated or empty/over-long) body.  Every read is bounded
 * against data_len so there is no over-read.
 */
static const char *
fd_obsd_name_field(const uint8_t *data, size_t data_len, size_t off,
		size_t *name_len)
{
	const char *name;
	size_t avail, namelen;

	if (off >= data_len)
		return NULL;
	name = (const char *)(data + off);
	avail = data_len - off;
	namelen = strnlen(name, avail);
	if (namelen == avail)
		return NULL;   /* no terminating NUL inside the body */
	if (namelen == 0 || namelen > FD_NAME_MAX)
		return NULL;
	*name_len = namelen;
	return name;
}

/*
 * Resolve a SETATTR request into the OS neutral fattr_valid mask and the
 * requested size/time fields.  The new values travel in the request's
 * fb_attr (a struct stat in the FD union); fb_dat is a struct fb_io whose
 * fi_flags is the FUSE_FATTR_* mask telling which fields are being set.  The
 * fb_io is read through the host struct so its layout is never hardcoded.
 * Mode/uid/gid changes have no RDPDR representation and are ignored; the
 * core then replies a fresh attr.  Returns 0 on success, or -1 if fb_dat is
 * too short to carry the fb_io mask.
 */
static int
fd_obsd_parse_setattr(const struct fusebuf *fb, const uint8_t *data,
		size_t data_len, struct fd_request *req)
{
	struct fb_io io;

	if (data_len < sizeof io)
		return -1;
	memcpy(&io, data, sizeof io);

	req->fattr_valid = 0;
	if (io.fi_flags & FUSE_FATTR_SIZE) {
		req->fattr_valid |= FD_FATTR_SIZE;
		req->set_size = (uint64_t)fb->fb_attr.st_size;
	}
	if (io.fi_flags & FUSE_FATTR_ATIME) {
		req->fattr_valid |= FD_FATTR_ATIME;
		req->set_atime = (uint64_t)fb->fb_attr.st_atim.tv_sec;
		req->set_atimensec = 0;
	}
	if (io.fi_flags & FUSE_FATTR_MTIME) {
		req->fattr_valid |= FD_FATTR_MTIME;
		req->set_mtime = (uint64_t)fb->fb_attr.st_mtim.tv_sec;
		req->set_mtimensec = 0;
	}
	/* MODE/UID/GID/FH carry no RDPDR meaning; the core replies a fresh
	 * attr for those so the kernel sees current state. */
	return 0;
}

/*
 * Parse one fully framed fusebuf request (raw points at the hdr+FD region,
 * len is the total bytes received, so the data is at raw + FD_FB_HDRLEN with
 * length len - FD_FB_HDRLEN) into *req.  Returns 1 when the core should
 * dispatch *req, or 0 when the backend already handled it (INIT/DESTROY/FLUSH/
 * ACCESS/STATFS replied inline, or a malformed/over-long request was rejected
 * here).  Allocates the carry slot for every op that runs through the core.
 */
static int
obsd_recv(struct fuse_drive *fd, const uint8_t *raw, size_t len,
		struct fd_request *req)
{
	struct fusebuf fb;
	const uint8_t *data;
	size_t data_len;
	struct fd_obsd_slot *s;
	int type;

	/* A short read that does not even carry the header region is a runt;
	 * the caller already rejected len < FD_FB_HDRLEN, but guard anyway. */
	if (len < FD_FB_HDRLEN)
		return 0;
	memcpy(&fb, raw, FD_FB_HDRLEN);   /* hdr + FD union; fb_dat unused here */
	data = raw + FD_FB_HDRLEN;
	data_len = len - FD_FB_HDRLEN;
	type = fb.fb_type;

	/* Inline ops: these never block a VFS syscall on a node operation, so
	 * they reply straight from the parsed header without a carry slot. */
	switch (type) {
	case FBT_INIT:
		/* The kernel sets sess_init from any reply; answer success. */
		fd_obsd_reply_inline(fd, &fb, 0, 0);
		return 0;
	case FBT_DESTROY:
		fd_obsd_reply_inline(fd, &fb, 0, 0);
		return 0;
	case FBT_FLUSH:
	case FBT_FSYNC:
	case FBT_FSYNCDIR:
		fd_obsd_reply_inline(fd, &fb, 0, 0);
		return 0;
	case FBT_ACCESS:
		fd_obsd_reply_inline(fd, &fb, 0, 0);   /* allow */
		return 0;
	case FBT_STATFS:
		fd_obsd_reply_statfs(fd, &fb);
		return 0;
	default:
		break;
	}

	/* Everything below dispatches through the core and replies async, so
	 * allocate the carry slot now.  io_len is meaningful only for READ and
	 * READDIR but is harmless to carry for the rest. */
	s = fd_obsd_slot_alloc(fb.fb_uuid, type, fb.fb_ino,
		(size_t)fb.fb_io_len);
	if (s == NULL) {
		/* No slot: fail this op so the kernel is never left waiting. */
		fd_obsd_reply_inline(fd, &fb, ENOMEM, 0);
		return 0;
	}

	req->unique = fb.fb_uuid;
	req->nodeid = (uint64_t)fb.fb_ino;

	switch (type) {
	case FBT_GETATTR:
		req->op = FD_OP_GETATTR;
		return 1;
	case FBT_LOOKUP:
		/* fb_dat is the NUL-terminated child name; fb_len counts the NUL. */
		if (data_len == 0 || data[data_len - 1] != '\0') {
			obsd_emit_error(fd, fb.fb_uuid, EINVAL);
			return 0;
		}
		req->op = FD_OP_LOOKUP;
		req->name = (const char *)data;
		req->name_len = strnlen(req->name, data_len);
		if (req->name_len == 0 || req->name_len > FD_NAME_MAX) {
			obsd_emit_error(fd, fb.fb_uuid, EINVAL);
			return 0;
		}
		return 1;
	case FBT_OPEN:
		req->op = FD_OP_OPEN;
		req->flags = fb.fb_io_flags;
		return 1;
	case FBT_OPENDIR:
		req->op = FD_OP_OPENDIR;
		req->flags = fb.fb_io_flags;
		return 1;
	case FBT_READ:
		req->op = FD_OP_READ;
		req->fh = fb.fb_io_fd;
		req->offset = (uint64_t)fb.fb_io_off;
		req->size = (uint32_t)fb.fb_io_len;
		return 1;
	case FBT_READDIR:
		req->op = FD_OP_READDIR;
		req->fh = fb.fb_io_fd;
		req->offset = (uint64_t)fb.fb_io_off;
		req->size = (uint32_t)fb.fb_io_len;
		return 1;
	case FBT_RELEASE:
		req->op = FD_OP_RELEASE;
		req->fh = fb.fb_io_fd;
		return 1;
	case FBT_RELEASEDIR:
		req->op = FD_OP_RELEASEDIR;
		req->fh = fb.fb_io_fd;
		return 1;
	case FBT_WRITE:
		/* fb_io carries the handle, offset and length; fb_dat is the
		 * data (fb_len bytes).  Never read past the bytes received. */
		req->op = FD_OP_WRITE;
		req->fh = fb.fb_io_fd;
		req->offset = (uint64_t)fb.fb_io_off;
		req->data = data;
		req->data_len = (uint32_t)data_len;
		return 1;
	case FBT_SETATTR:
		req->op = FD_OP_SETATTR;
		if (fd_obsd_parse_setattr(&fb, data, data_len, req) != 0) {
			obsd_emit_error(fd, fb.fb_uuid, EINVAL);
			return 0;
		}
		return 1;
	case FBT_MKNOD:
	case FBT_MKDIR: {
		/* fb_ino is the parent, fb_io_mode the mode, fb_dat the NUL
		 * terminated child name (fb_len counts the NUL). */
		size_t namelen;
		const char *name = fd_obsd_name_field(data, data_len, 0,
			&namelen);
		if (name == NULL) {
			obsd_emit_error(fd, fb.fb_uuid, EINVAL);
			return 0;
		}
		req->op = type == FBT_MKDIR ? FD_OP_MKDIR : FD_OP_MKNOD;
		req->mode = (uint32_t)fb.fb_io_mode;
		req->name = name;
		req->name_len = namelen;
		return 1;
	}
	case FBT_UNLINK:
	case FBT_RMDIR: {
		/* fb_ino is the parent, fb_dat the NUL terminated name. */
		size_t namelen;
		const char *name = fd_obsd_name_field(data, data_len, 0,
			&namelen);
		if (name == NULL) {
			obsd_emit_error(fd, fb.fb_uuid, EINVAL);
			return 0;
		}
		req->op = type == FBT_RMDIR ? FD_OP_RMDIR : FD_OP_UNLINK;
		req->name = name;
		req->name_len = namelen;
		return 1;
	}
	case FBT_RENAME: {
		/* fb_ino is the source parent; fb_dat is oldname '\0' newname
		 * '\0'; fb_io_ino is the destination parent.  Both names are
		 * bounded against fb_len so a missing second NUL is rejected. */
		size_t oldlen, newlen;
		const char *oldname = fd_obsd_name_field(data, data_len, 0,
			&oldlen);
		const char *newname;
		if (oldname == NULL) {
			obsd_emit_error(fd, fb.fb_uuid, EINVAL);
			return 0;
		}
		newname = fd_obsd_name_field(data, data_len, oldlen + 1,
			&newlen);
		if (newname == NULL) {
			obsd_emit_error(fd, fb.fb_uuid, EINVAL);
			return 0;
		}
		req->op = FD_OP_RENAME;
		req->newdir = (uint64_t)fb.fb_io_ino;
		req->name = oldname;
		req->name_len = oldlen;
		req->name2 = newname;
		req->name2_len = newlen;
		return 1;
	}
	default:
		/* READLINK / SYMLINK / LINK and any unknown op have no RDPDR
		 * representation; reject so the kernel sees a clean error. */
		obsd_emit_error(fd, fb.fb_uuid, ENOSYS);
		return 0;
	}
}

int
fuse_drive_backend_process(struct fuse_drive *fd)
{
	struct iovec iov[2];
	ssize_t r;
	size_t len;
	struct fd_request req;

	/*
	 * The OpenBSD fusefs device cannot be made non-blocking (its cdevsw has
	 * no d_ioctl, so FIONBIO fails) and has no d_poll (so poll() reports it
	 * always-readable via seltrue).  A blocking readv on an empty device
	 * would therefore hang the single-threaded session loop.  Gate the read
	 * on a non-blocking EVFILT_READ kqueue probe, which fires only when a
	 * fusebuf is actually queued; if nothing is ready, return at once.
	 */
	if (fd_obsd_readable(fd) != 1)
		return 0;

	/*
	 * The device delivers exactly ONE fusebuf per read, so read just one
	 * request and return -- a second read with nothing queued would block.
	 * Any further queued requests are picked up on the next loop iteration
	 * (the probe will report them ready), mirroring libfuse's
	 * one-read-per-loop model.  The device does not support partial reads:
	 * one readv into the fixed header region plus the data buffer.
	 */
	iov[0].iov_base = fd_obsd_ctx.buf;
	iov[0].iov_len = FD_FB_HDRLEN;
	iov[1].iov_base = fd_obsd_ctx.buf + FD_FB_HDRLEN;
	iov[1].iov_len = FD_OBSD_MAXDATA;
	do {
		r = readv(fd->fuse_fd, iov, 2);
	} while (r < 0 && errno == EINTR);
	if (r < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		/* ENODEV means the mount was torn down. */
		return -1;
	}
	if (r == 0)
		return -1;
	len = (size_t)r;
	if (len < FD_FB_HDRLEN)
		return 0;   /* runt: ignore */
	memset(&req, 0, sizeof req);
	if (obsd_recv(fd, fd_obsd_ctx.buf, len, &req) == 1)
		fd_dispatch(fd, &req);
	return 0;
}

const struct fd_backend fd_backend_obsd = {
	obsd_recv,
	obsd_emit_attr,
	obsd_emit_entry,
	obsd_emit_open,
	obsd_emit_create,
	obsd_emit_read,
	obsd_emit_write,
	obsd_emit_dirent_batch,
	obsd_emit_ok,
	obsd_emit_error
};

#endif /* HAVE_OBSD_FUSE */
