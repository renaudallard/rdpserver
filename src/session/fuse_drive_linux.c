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
 * fuse_drive_linux.c -- Linux raw /dev/fuse wire backend for the RDPDR
 * drive redirection core.
 *
 * This is the only file that includes <linux/fuse.h>.  It owns the Linux
 * kernel wire format: recv parses a fuse_in_header plus the per-opcode
 * fuse_*_in into the OS neutral struct fd_request, and the emit_* turn the
 * core's OS neutral replies (struct fd_attr, the dirent batch) into
 * fuse_out_header + fuse_attr/entry_out/open_out/dirent bytes on the fuse
 * fd.  The FUSE_INIT handshake is answered here too, since it is purely a
 * wire-format negotiation.
 */

#define _GNU_SOURCE

#include "fuse_drive.h"

#if HAVE_FUSE

#include "fuse_drive_internal.h"

#include "../channels/rdpdr.h"   /* FILE_READ_DATA, FILE_WRITE_DATA */

#include <linux/fuse.h>

#include <sys/stat.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Our supported FUSE protocol.  We answer INIT with major 7 and the
 * smaller of our and the kernel's minor.  7.27 predates every extended
 * input struct we touch, so the fixed sizes we parse are always present. */
#define FD_FUSE_MINOR        27
#define FD_MAX_WRITE         (128u * 1024u)

/* Read buffer: large enough for a 128 KiB write payload plus headers, so
 * one FUSE_WRITE request (fuse_write_in + up to max_write data bytes)
 * fits in a single read. */
#define FD_IN_BUF_SZ         (FD_MAX_WRITE + 4096u)
/* Reply scratch: a READDIR fills at most the requested size, capped. */
#define FD_OUT_BUF_SZ        (128u * 1024u + 4096u)

/* Map an OS neutral struct fd_attr into a fuse_attr.  The permission bits
 * pass through unchanged; the FD_S_IF* type bits become S_IFDIR/S_IFREG,
 * and the Linux-specific uid/gid/block size are filled here so the core
 * never has to know about them. */
static void
ln_fill_fuse_attr(const struct fd_attr *a, struct fuse_attr *fa)
{
	memset(fa, 0, sizeof *fa);
	fa->ino = a->ino;
	fa->size = a->size;
	fa->nlink = a->nlink;
	/* The FD_S_IF* values match the Linux S_IF* values, but translate
	 * explicitly so the core stays free of any OS file-type constant. */
	fa->mode = a->mode & ~(uint32_t)FD_S_IFMT;
	if ((a->mode & FD_S_IFMT) == FD_S_IFDIR)
		fa->mode |= S_IFDIR;
	else if ((a->mode & FD_S_IFMT) == FD_S_IFREG)
		fa->mode |= S_IFREG;
	fa->mtime = a->mtime;
	fa->atime = a->atime;
	fa->ctime = a->ctime;
	fa->uid = (uint32_t)getuid();
	fa->gid = (uint32_t)getgid();
	fa->blksize = 4096;
}

/* Write a fuse_out_header carrying an error (or success with no body). */
static void
ln_emit_error(struct fuse_drive *fd, uint64_t unique, int error)
{
	struct fuse_out_header oh;
	memset(&oh, 0, sizeof oh);
	oh.len = (uint32_t)sizeof oh;
	oh.error = error;
	oh.unique = unique;
	(void)fd->write_reply(fd, &oh, sizeof oh);
}

/* Write a fuse_out_header followed by a fixed-size body. */
static void
ln_reply_ok(struct fuse_drive *fd, uint64_t unique,
		const void *body, size_t body_len)
{
	uint8_t buf[sizeof(struct fuse_out_header)
		+ sizeof(struct fuse_entry_out)];
	struct fuse_out_header oh;

	if (body_len > sizeof buf - sizeof oh) {
		ln_emit_error(fd, unique, -EIO);
		return;
	}
	memset(&oh, 0, sizeof oh);
	oh.len = (uint32_t)(sizeof oh + body_len);
	oh.error = 0;
	oh.unique = unique;
	memcpy(buf, &oh, sizeof oh);
	if (body_len > 0)
		memcpy(buf + sizeof oh, body, body_len);
	(void)fd->write_reply(fd, buf, sizeof oh + body_len);
}

static void
ln_emit_ok(struct fuse_drive *fd, uint64_t unique)
{
	ln_emit_error(fd, unique, 0);   /* success, no body */
}

static void
ln_emit_attr(struct fuse_drive *fd, uint64_t unique, const struct fd_attr *a)
{
	struct fuse_attr_out ao;
	memset(&ao, 0, sizeof ao);
	ao.attr_valid = 1;
	ln_fill_fuse_attr(a, &ao.attr);
	ln_reply_ok(fd, unique, &ao, sizeof ao);
}

static void
ln_emit_entry(struct fuse_drive *fd, uint64_t unique, uint64_t nodeid,
		const struct fd_attr *a)
{
	struct fuse_entry_out eo;
	memset(&eo, 0, sizeof eo);
	eo.nodeid = nodeid;
	eo.entry_valid = 1;
	eo.attr_valid = 1;
	ln_fill_fuse_attr(a, &eo.attr);
	ln_reply_ok(fd, unique, &eo, sizeof eo);
}

static void
ln_emit_open(struct fuse_drive *fd, uint64_t unique, uint64_t fh, int direct_io)
{
	struct fuse_open_out out;
	memset(&out, 0, sizeof out);
	out.fh = fh;
	if (direct_io)
		out.open_flags = FOPEN_DIRECT_IO;
	ln_reply_ok(fd, unique, &out, sizeof out);
}

/*
 * Reply to a FUSE_CREATE: a fuse_out_header followed by fuse_entry_out and
 * then fuse_open_out.
 */
static void
ln_emit_create(struct fuse_drive *fd, uint64_t unique, uint64_t nodeid,
		uint64_t fh, const struct fd_attr *a)
{
	uint8_t buf[sizeof(struct fuse_out_header)
		+ sizeof(struct fuse_entry_out)
		+ sizeof(struct fuse_open_out)];
	struct fuse_out_header oh;
	struct fuse_entry_out eo;
	struct fuse_open_out oo;
	size_t off = 0;

	memset(&eo, 0, sizeof eo);
	eo.nodeid = nodeid;
	eo.entry_valid = 1;
	eo.attr_valid = 1;
	ln_fill_fuse_attr(a, &eo.attr);

	memset(&oo, 0, sizeof oo);
	oo.fh = fh;
	oo.open_flags = FOPEN_DIRECT_IO;

	memset(&oh, 0, sizeof oh);
	oh.len = (uint32_t)(sizeof oh + sizeof eo + sizeof oo);
	oh.error = 0;
	oh.unique = unique;

	memcpy(buf + off, &oh, sizeof oh); off += sizeof oh;
	memcpy(buf + off, &eo, sizeof eo); off += sizeof eo;
	memcpy(buf + off, &oo, sizeof oo); off += sizeof oo;
	(void)fd->write_reply(fd, buf, off);
}

static void
ln_emit_read(struct fuse_drive *fd, uint64_t unique, const uint8_t *data,
		uint32_t len)
{
	struct fuse_out_header oh;
	memset(&oh, 0, sizeof oh);
	oh.len = (uint32_t)(sizeof oh + len);
	oh.error = 0;
	oh.unique = unique;
	(void)fd->write_reply(fd, &oh, sizeof oh);
	if (len > 0)
		(void)fd->write_reply(fd, data, len);
}

static void
ln_emit_write(struct fuse_drive *fd, uint64_t unique, uint32_t count)
{
	struct fuse_write_out out;
	memset(&out, 0, sizeof out);
	out.size = count;
	ln_reply_ok(fd, unique, &out, sizeof out);
}

/*
 * Pack the decoded dirents into one fuse_dirent batch.  The kernel asked
 * for at most maxbytes; we cap that to our scratch buffer and stop once
 * the next aligned record would not fit.  A 0-entry batch yields a
 * body-less success reply (an empty directory or an exhausted offset).
 */
static size_t
ln_emit_dirent_batch(struct fuse_drive *fd, uint64_t unique,
		const struct fd_dirent *ents, size_t n, uint32_t maxbytes)
{
	uint8_t out[FD_OUT_BUF_SZ];
	size_t off = 0;
	size_t want = maxbytes < sizeof out ? maxbytes : sizeof out;
	uint64_t doff = 0;
	size_t i;

	for (i = 0; i < n; i++) {
		struct fuse_dirent de;
		size_t namelen = ents[i].name_len;
		size_t reclen = FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + namelen);
		if (off + reclen > want)
			break;
		doff++;
		memset(&de, 0, sizeof de);
		de.ino = ents[i].ino;
		de.off = doff;
		de.namelen = (uint32_t)namelen;
		de.type = ents[i].is_dir ? (S_IFDIR >> 12) : (S_IFREG >> 12);
		memcpy(out + off, &de, FUSE_NAME_OFFSET);
		memcpy(out + off + FUSE_NAME_OFFSET, ents[i].name, namelen);
		/* Zero the alignment tail so no stack bytes leak. */
		if (reclen > FUSE_NAME_OFFSET + namelen)
			memset(out + off + FUSE_NAME_OFFSET + namelen, 0,
				reclen - (FUSE_NAME_OFFSET + namelen));
		off += reclen;
	}
	/* Write the header and the packed records directly.  ln_reply_ok is
	 * sized for the fixed attr/entry replies and would reject a dirent
	 * batch larger than 128 bytes, so a real directory must not route
	 * through it. */
	{
		struct fuse_out_header oh;
		memset(&oh, 0, sizeof oh);
		oh.len = (uint32_t)(sizeof oh + off);
		oh.error = 0;
		oh.unique = unique;
		(void)fd->write_reply(fd, &oh, sizeof oh);
		if (off > 0)
			(void)fd->write_reply(fd, out, off);
	}
	return off;
}

/* FUSE_INIT handshake: answer with our supported major/minor. */
static void
ln_init_reply(struct fuse_drive *fd, const struct fuse_in_header *ih,
		const uint8_t *body, size_t body_len)
{
	struct fuse_init_in in;
	struct fuse_init_out out;
	uint32_t kmajor, kminor;

	if (body_len < sizeof(uint32_t) * 2) {
		ln_emit_error(fd, ih->unique, -EINVAL);
		return;
	}
	/* Only major/minor are guaranteed present in every INIT version. */
	memset(&in, 0, sizeof in);
	memcpy(&in, body, body_len < sizeof in ? body_len : sizeof in);
	kmajor = in.major;
	kminor = in.minor;

	memset(&out, 0, sizeof out);
	if (kmajor < FUSE_KERNEL_VERSION) {
		/* Older kernel major: echo its major and let it re-INIT. */
		out.major = kmajor;
		out.minor = kminor;
		ln_reply_ok(fd, ih->unique, &out, sizeof out);
		return;
	}
	out.major = FUSE_KERNEL_VERSION;
	out.minor = kminor < FD_FUSE_MINOR ? kminor : FD_FUSE_MINOR;
	out.max_readahead = in.max_readahead;
	out.flags = 0;   /* no optional features: keep the protocol minimal */
	out.max_background = 0;
	out.congestion_threshold = 0;
	out.max_write = FD_MAX_WRITE;
	out.time_gran = 1;
	ln_reply_ok(fd, ih->unique, &out, sizeof out);
}

/*
 * Pull the leaf name out of a FUSE namespace request body.  The kernel
 * appends a single NUL-terminated component after the op's fixed struct
 * (offset off); for the RENAME body two components follow back to back, so
 * this is called once per component.  Returns a pointer to the name and
 * its length via *name_len, or NULL on a malformed (unterminated or
 * empty/over-long) body.  Every read is bounded against body_len.
 */
static const char *
ln_name_field(const uint8_t *body, size_t body_len, size_t off,
		size_t *name_len)
{
	const char *name;
	size_t avail, namelen;

	if (off >= body_len)
		return NULL;
	name = (const char *)(body + off);
	avail = body_len - off;
	namelen = strnlen(name, avail);
	if (namelen == avail)
		return NULL;   /* no terminating NUL inside the body */
	if (namelen == 0 || namelen > FD_NAME_MAX)
		return NULL;
	*name_len = namelen;
	return name;
}

/*
 * Resolve a fuse_setattr_in time field into the request's OS neutral
 * seconds/nsec, turning ATIME_NOW/MTIME_NOW into the current wall-clock
 * time.  The core converts those to FILETIME later.
 */
static void
ln_parse_setattr(const struct fuse_setattr_in *si, struct fd_request *req)
{
	uint64_t now = (uint64_t)time(NULL);

	req->fattr_valid = 0;
	if (si->valid & FATTR_SIZE) {
		req->fattr_valid |= FD_FATTR_SIZE;
		req->set_size = si->size;
	}
	if (si->valid & FATTR_ATIME) {
		req->fattr_valid |= FD_FATTR_ATIME;
		if (si->valid & FATTR_ATIME_NOW) {
			req->set_atime = now;
			req->set_atimensec = 0;
		} else {
			req->set_atime = si->atime;
			req->set_atimensec = si->atimensec;
		}
	}
	if (si->valid & FATTR_MTIME) {
		req->fattr_valid |= FD_FATTR_MTIME;
		if (si->valid & FATTR_MTIME_NOW) {
			req->set_mtime = now;
			req->set_mtimensec = 0;
		} else {
			req->set_mtime = si->mtime;
			req->set_mtimensec = si->mtimensec;
		}
	}
}

/*
 * Parse one fully framed FUSE request (buf points at the fuse_in_header,
 * len is the header length the kernel reported) into *req.  Returns 1 when
 * the core should dispatch *req, or 0 when the backend already handled the
 * request (INIT, FLUSH replied inline, or a malformed body rejected here).
 */
static int
ln_recv(struct fuse_drive *fd, const uint8_t *buf, size_t len,
		struct fd_request *req)
{
	struct fuse_in_header ih;
	const uint8_t *body;
	size_t body_len;

	memcpy(&ih, buf, sizeof ih);
	body = buf + sizeof ih;
	body_len = len - sizeof ih;

	req->unique = ih.unique;
	req->nodeid = ih.nodeid;

	switch (ih.opcode) {
	case FUSE_INIT:
		ln_init_reply(fd, &ih, body, body_len);
		return 0;
	case FUSE_GETATTR:
		req->op = FD_OP_GETATTR;
		return 1;
	case FUSE_SETATTR: {
		struct fuse_setattr_in si;
		if (body_len < sizeof si) {
			ln_emit_error(fd, ih.unique, -EINVAL);
			return 0;
		}
		memcpy(&si, body, sizeof si);
		req->op = FD_OP_SETATTR;
		ln_parse_setattr(&si, req);
		return 1;
	}
	case FUSE_LOOKUP:
		/* The name is a NUL-terminated string filling the request body. */
		if (body_len == 0 || body[body_len - 1] != '\0') {
			ln_emit_error(fd, ih.unique, -EINVAL);
			return 0;
		}
		req->op = FD_OP_LOOKUP;
		req->name = (const char *)body;
		req->name_len = strnlen(req->name, body_len);
		return 1;
	case FUSE_OPENDIR:
		req->op = FD_OP_OPENDIR;
		return 1;
	case FUSE_READDIR: {
		struct fuse_read_in ri;
		if (body_len < sizeof ri) {
			ln_emit_error(fd, ih.unique, -EINVAL);
			return 0;
		}
		memcpy(&ri, body, sizeof ri);
		req->op = FD_OP_READDIR;
		req->offset = ri.offset;
		req->size = ri.size;
		return 1;
	}
	case FUSE_OPEN: {
		struct fuse_open_in oi;
		memset(&oi, 0, sizeof oi);
		if (body_len >= sizeof oi)
			memcpy(&oi, body, sizeof oi);
		req->op = FD_OP_OPEN;
		req->flags = oi.flags;
		return 1;
	}
	case FUSE_READ: {
		struct fuse_read_in ri;
		if (body_len < sizeof ri) {
			ln_emit_error(fd, ih.unique, -EINVAL);
			return 0;
		}
		memcpy(&ri, body, sizeof ri);
		req->op = FD_OP_READ;
		req->fh = ri.fh;
		req->offset = ri.offset;
		req->size = ri.size;
		return 1;
	}
	case FUSE_WRITE: {
		struct fuse_write_in wi;
		uint32_t size;
		if (body_len < sizeof wi) {
			ln_emit_error(fd, ih.unique, -EINVAL);
			return 0;
		}
		memcpy(&wi, body, sizeof wi);
		size = wi.size;
		/* The write data follows the fixed fuse_write_in.  Never read
		 * past the bytes the kernel actually delivered. */
		if (size > body_len - sizeof wi)
			size = (uint32_t)(body_len - sizeof wi);
		req->op = FD_OP_WRITE;
		req->fh = wi.fh;
		req->offset = wi.offset;
		req->data = body + sizeof wi;
		req->data_len = size;
		return 1;
	}
	case FUSE_CREATE: {
		struct fuse_create_in ci;
		size_t namelen;
		const char *name;
		if (body_len < sizeof ci) {
			ln_emit_error(fd, ih.unique, -EINVAL);
			return 0;
		}
		memcpy(&ci, body, sizeof ci);
		name = ln_name_field(body, body_len, sizeof ci, &namelen);
		if (name == NULL) {
			ln_emit_error(fd, ih.unique, -EINVAL);
			return 0;
		}
		req->op = FD_OP_CREATE;
		req->flags = ci.flags;
		req->mode = ci.mode;
		req->name = name;
		req->name_len = namelen;
		return 1;
	}
	case FUSE_MKNOD: {
		struct fuse_mknod_in mi;
		size_t namelen;
		const char *name;
		if (body_len < sizeof mi) {
			ln_emit_error(fd, ih.unique, -EINVAL);
			return 0;
		}
		memcpy(&mi, body, sizeof mi);
		if (!S_ISREG(mi.mode)) {
			/* Devices, FIFOs and sockets have no RDPDR representation. */
			ln_emit_error(fd, ih.unique, -EPERM);
			return 0;
		}
		name = ln_name_field(body, body_len, sizeof mi, &namelen);
		if (name == NULL) {
			ln_emit_error(fd, ih.unique, -EINVAL);
			return 0;
		}
		req->op = FD_OP_MKNOD;
		req->mode = mi.mode;
		req->name = name;
		req->name_len = namelen;
		return 1;
	}
	case FUSE_MKDIR: {
		struct fuse_mkdir_in mi;
		size_t namelen;
		const char *name;
		if (body_len < sizeof mi) {
			ln_emit_error(fd, ih.unique, -EINVAL);
			return 0;
		}
		memcpy(&mi, body, sizeof mi);
		name = ln_name_field(body, body_len, sizeof mi, &namelen);
		if (name == NULL) {
			ln_emit_error(fd, ih.unique, -EINVAL);
			return 0;
		}
		req->op = FD_OP_MKDIR;
		req->mode = mi.mode;
		req->name = name;
		req->name_len = namelen;
		return 1;
	}
	case FUSE_UNLINK:
	case FUSE_RMDIR: {
		size_t namelen;
		const char *name = ln_name_field(body, body_len, 0, &namelen);
		if (name == NULL) {
			ln_emit_error(fd, ih.unique, -EINVAL);
			return 0;
		}
		req->op = ih.opcode == FUSE_RMDIR ? FD_OP_RMDIR : FD_OP_UNLINK;
		req->name = name;
		req->name_len = namelen;
		return 1;
	}
	case FUSE_RENAME:
	case FUSE_RENAME2: {
		const char *oldname, *newname;
		size_t oldlen, newlen, off;
		uint64_t newdir;

		/* Parse the fixed head: newdir nodeid, plus RENAME2 flags. */
		if (ih.opcode == FUSE_RENAME2) {
			struct fuse_rename2_in r2;
			if (body_len < sizeof r2) {
				ln_emit_error(fd, ih.unique, -EINVAL);
				return 0;
			}
			memcpy(&r2, body, sizeof r2);
			newdir = r2.newdir;
			off = sizeof r2;
			if (r2.flags != 0) {
				/* RENAME_NOREPLACE / RENAME_EXCHANGE not supported. */
				ln_emit_error(fd, ih.unique, -EINVAL);
				return 0;
			}
		} else {
			struct fuse_rename_in ri;
			if (body_len < sizeof ri) {
				ln_emit_error(fd, ih.unique, -EINVAL);
				return 0;
			}
			memcpy(&ri, body, sizeof ri);
			newdir = ri.newdir;
			off = sizeof ri;
		}

		/* Two NUL-terminated names follow: oldname then newname. */
		oldname = ln_name_field(body, body_len, off, &oldlen);
		if (oldname == NULL) {
			ln_emit_error(fd, ih.unique, -EINVAL);
			return 0;
		}
		newname = ln_name_field(body, body_len, off + oldlen + 1, &newlen);
		if (newname == NULL) {
			ln_emit_error(fd, ih.unique, -EINVAL);
			return 0;
		}
		req->op = FD_OP_RENAME;
		req->newdir = newdir;
		req->name = oldname;
		req->name_len = oldlen;
		req->name2 = newname;
		req->name2_len = newlen;
		return 1;
	}
	case FUSE_RELEASE:
		req->op = FD_OP_RELEASE;
		return 1;
	case FUSE_RELEASEDIR:
		req->op = FD_OP_RELEASEDIR;
		return 1;
	case FUSE_FLUSH:
		ln_emit_ok(fd, ih.unique);
		return 0;
	case FUSE_FORGET: {
		struct fuse_forget_in in;
		if (body_len < sizeof in)
			return 0;   /* FORGET has no reply regardless */
		memcpy(&in, body, sizeof in);
		req->op = FD_OP_FORGET;
		req->nlookup = in.nlookup;
		return 1;
	}
	case FUSE_BATCH_FORGET: {
		/* BATCH_FORGET carries a count followed by that many
		 * (nodeid, nlookup) records.  It has no reply; dispatch each
		 * record's forget directly here since the core's FD_OP_FORGET
		 * takes one node at a time. */
		struct fuse_batch_forget_in in;
		struct fuse_forget_one one;
		size_t off;
		uint32_t i;
		if (body_len < sizeof in)
			return 0;
		memcpy(&in, body, sizeof in);
		off = sizeof in;
		for (i = 0; i < in.count; i++) {
			struct fd_request fr;
			if (off + sizeof one > body_len)
				break;
			memcpy(&one, body + off, sizeof one);
			off += sizeof one;
			memset(&fr, 0, sizeof fr);
			fr.op = FD_OP_FORGET;
			fr.nodeid = one.nodeid;
			fr.nlookup = one.nlookup;
			fd_dispatch(fd, &fr);
		}
		return 0;
	}
	default:
		ln_emit_error(fd, ih.unique, -ENOSYS);
		return 0;
	}
}

int
fuse_drive_backend_process(struct fuse_drive *fd)
{
	uint8_t buf[FD_IN_BUF_SZ];
	int handled = 0;

	/* Drain a bounded number of requests per call so one busy directory
	 * cannot starve the rest of the session loop. */
	while (handled < 64) {
		ssize_t r;
		struct fuse_in_header ih;
		size_t len;
		struct fd_request req;
		do {
			r = read(fd->fuse_fd, buf, sizeof buf);
		} while (r < 0 && errno == EINTR);
		if (r < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0;
			/* ENODEV means the mount was torn down. */
			return -1;
		}
		if (r == 0)
			return -1;
		if ((size_t)r < sizeof ih)
			return 0;   /* runt: ignore */
		memcpy(&ih, buf, sizeof ih);
		len = ih.len;
		/* The header length must be self-consistent and within the
		 * bytes the kernel actually delivered. */
		if (len < sizeof ih || len > (size_t)r)
			return 0;
		memset(&req, 0, sizeof req);
		if (ln_recv(fd, buf, len, &req) == 1)
			fd_dispatch(fd, &req);
		handled++;
	}
	return 0;
}

const struct fd_backend fd_backend_linux = {
	ln_recv,
	ln_emit_attr,
	ln_emit_entry,
	ln_emit_open,
	ln_emit_create,
	ln_emit_read,
	ln_emit_write,
	ln_emit_dirent_batch,
	ln_emit_ok,
	ln_emit_error
};

#endif /* HAVE_FUSE */
