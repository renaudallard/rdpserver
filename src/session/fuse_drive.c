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
 * fuse_drive.c -- raw /dev/fuse read-path for RDPDR drive redirection.
 *
 * Design.
 *
 *   Node model.  A fixed table of nodes maps a FUSE nodeid (u64) to a
 *   path under one announced drive.  nodeid 1 is the synthetic root of
 *   the mount; its children are one directory node per announced drive
 *   (device_id, name = drive label).  Below a drive, each looked up name
 *   becomes a child node carrying device_id, parent nodeid, the leaf
 *   name, and whether it is a directory.  The full RDPDR path of a node
 *   is rebuilt by walking parents to the drive root.  A node also caches
 *   the open RDPDR handle (file_id) once OPEN/OPENDIR succeeds.
 *
 *   Async model.  FUSE ops that need the client store the kernel's
 *   fuse_unique in an in-flight slot keyed by a freshly allocated backend
 *   req_id, send the FS_REQ, and return WITHOUT writing a FUSE reply.
 *   When the matching RDP_BE_FS_RSP arrives, fuse_drive_handle_fs_rsp
 *   looks the slot up, maps NTSTATUS to errno, decodes the op payload,
 *   and writes the FUSE reply.  The in-flight table is bounded to
 *   FD_INFLIGHT_MAX; if it is full the op is failed immediately with
 *   ENOMEM so the kernel is never left waiting.
 *
 *   GETATTR / LOOKUP KISS approach.  Synthetic directories (root and the
 *   per-drive roots) answer immediately with a fabricated dir attr.  For
 *   any other path the module does a single round trip: it sends an OPEN
 *   (which the worker turns into an RDPDR create) and, on the reply,
 *   derives the attributes from the create status alone.  RDPDR create
 *   does not return size or times, so files report a synthetic size of 0
 *   and zeroed timestamps; only existence and the dir/file split are
 *   authoritative.  A richer attr fetch (QUERY_INFO chaining) is left for
 *   a later stage; this is documented as a known limitation.  The open
 *   handle from the LOOKUP create is reused for a following OPEN/OPENDIR
 *   so a browse does not reopen the same path twice.
 *
 *   Trust.  Everything decoded out of an FS_RSP payload originates with
 *   the RDP client (its file system).  Every parse here is length
 *   bounded against the received payload before any byte is consumed.
 *
 * On hosts without <linux/fuse.h> (OpenBSD, macOS) the file compiles to
 * empty no-op stubs selected by HAVE_FUSE.
 */

#define _GNU_SOURCE

#include "fuse_drive.h"

#if HAVE_FUSE

#include "../include/rdp_log.h"
#include "../common/io.h"
#include "../backend/proto.h"
#include "../backend/proto_api.h"
#include "../channels/rdpdr.h"   /* FileBothDirectoryInformation, NTSTATUS */

#include <linux/fuse.h>

#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Our supported FUSE protocol.  We answer INIT with major 7 and the
 * smaller of our and the kernel's minor.  7.27 predates every extended
 * input struct we touch, so the fixed sizes we parse are always present. */
#define FD_FUSE_MINOR        27
#define FD_MAX_WRITE         (128u * 1024u)
#define FD_MAX_READ          (128u * 1024u)

#define FD_MAX_NODES         512
#define FD_INFLIGHT_MAX      RDPDR_MAX_PENDING   /* 64 */
#define FD_NAME_MAX          255

/* Private in-flight op tags above the wire RDP_FS_* range (1..7) so the
 * completion can tell which FUSE op a backend OPEN was serving.  These
 * never travel the wire: the backend FS_REQ always carries RDP_FS_OPEN. */
#define RDP_FS_OPENDIR_TAG   101u
#define RDP_FS_OPENFILE_TAG  102u   /* direct FUSE_OPEN of a regular file */

/* Read buffer: large enough for a 128 KiB write payload plus headers.
 * We never write, but the kernel can still hand us up to max_write, so
 * keep the headroom. */
#define FD_IN_BUF_SZ         (FD_MAX_WRITE + 4096u)
/* Reply scratch: a READDIR fills at most the requested size, capped. */
#define FD_OUT_BUF_SZ        (128u * 1024u + 4096u)

struct fd_node {
	int      in_use;
	uint64_t nodeid;
	uint64_t parent;       /* parent nodeid; 0 for root */
	uint32_t device_id;    /* owning RDPDR drive; 0 for the synthetic root */
	int      is_drive;     /* a per-drive top-level directory */
	int      is_dir;
	uint32_t file_id;      /* open RDPDR handle, 0 when not open */
	int      have_open;    /* file_id is valid */
	uint64_t nlookup;      /* kernel lookup count, decremented by FORGET */
	char     name[FD_NAME_MAX + 1];
};

struct fd_inflight {
	int      in_use;
	uint32_t req_id;
	uint64_t fuse_unique;
	uint32_t op;           /* RDP_FS_* */
	uint64_t nodeid;       /* node the op concerns */
	uint32_t read_size;    /* READ: bytes the kernel asked for */
};

struct fuse_drive {
	int      fuse_fd;
	int      be_fd;
	uint32_t next_req_id;
	uint64_t next_nodeid;
	struct fd_node nodes[FD_MAX_NODES];
	struct fd_inflight inflight[FD_INFLIGHT_MAX];

	/* Reply / request sinks.  The live session writes to the fds; the
	 * regress harness substitutes in-memory capture sinks. */
	int (*send_fs_req)(struct fuse_drive *, const struct rdp_be_fs_req *,
		const void *payload, size_t payload_len);
	int (*write_reply)(struct fuse_drive *, const void *buf, size_t len);
	void *sink_ctx;
};

/* little-endian helpers (FUSE is host-endian; RDPDR FSCC is LE) */

static uint32_t
fd_ld32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
		| ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* node table */

static struct fd_node *
fd_node_find(struct fuse_drive *fd, uint64_t nodeid)
{
	int i;
	for (i = 0; i < FD_MAX_NODES; i++)
		if (fd->nodes[i].in_use && fd->nodes[i].nodeid == nodeid)
			return &fd->nodes[i];
	return NULL;
}

/* Find an existing child of parent with this name, or NULL. */
static struct fd_node *
fd_child_find(struct fuse_drive *fd, uint64_t parent,
		const char *name, size_t namelen)
{
	int i;
	if (namelen > FD_NAME_MAX)
		return NULL;
	for (i = 0; i < FD_MAX_NODES; i++) {
		struct fd_node *n = &fd->nodes[i];
		if (!n->in_use || n->parent != parent)
			continue;
		if (strlen(n->name) == namelen
		    && memcmp(n->name, name, namelen) == 0)
			return n;
	}
	return NULL;
}

static struct fd_node *
fd_node_alloc(struct fuse_drive *fd)
{
	int i;
	for (i = 0; i < FD_MAX_NODES; i++) {
		if (!fd->nodes[i].in_use) {
			struct fd_node *n = &fd->nodes[i];
			memset(n, 0, sizeof *n);
			n->in_use = 1;
			n->nodeid = fd->next_nodeid++;
			return n;
		}
	}
	return NULL;
}

/* Create-or-find a child node under parent with a copied leaf name. */
static struct fd_node *
fd_child_make(struct fuse_drive *fd, uint64_t parent,
		const char *name, size_t namelen, uint32_t device_id, int is_dir)
{
	struct fd_node *n;
	if (namelen > FD_NAME_MAX)
		return NULL;
	n = fd_child_find(fd, parent, name, namelen);
	if (n != NULL) {
		n->is_dir = is_dir;
		return n;
	}
	n = fd_node_alloc(fd);
	if (n == NULL)
		return NULL;
	n->parent = parent;
	n->device_id = device_id;
	n->is_dir = is_dir;
	memcpy(n->name, name, namelen);
	n->name[namelen] = '\0';
	return n;
}

/*
 * Build the RDPDR path of a node into buf (UTF-8, backslash separated,
 * leading backslash, e.g. "\dir\file.txt"; the drive root is "\").
 * Returns the length, or (size_t)-1 if it does not fit.  Walks parents
 * to the drive root, so it is bounded by the node-table depth.
 */
static size_t
fd_node_path(struct fuse_drive *fd, const struct fd_node *n,
		char *buf, size_t cap)
{
	const char *parts[FD_MAX_NODES];
	int depth = 0;
	size_t i, off = 0;
	const struct fd_node *cur = n;

	/* Collect leaf names from the node up to (not including) the drive
	 * root.  is_drive nodes contribute no path component. */
	while (cur != NULL && !cur->is_drive && cur->nodeid != FUSE_ROOT_ID) {
		if (depth >= FD_MAX_NODES)
			return (size_t)-1;
		parts[depth++] = cur->name;
		cur = fd_node_find(fd, cur->parent);
	}
	if (depth == 0) {
		if (cap < 2)
			return (size_t)-1;
		buf[0] = '\\';
		buf[1] = '\0';
		return 1;
	}
	for (i = (size_t)depth; i > 0; i--) {
		const char *p = parts[i - 1];
		size_t pl = strlen(p);
		if (off + 1 + pl + 1 > cap)
			return (size_t)-1;
		buf[off++] = '\\';
		memcpy(buf + off, p, pl);
		off += pl;
	}
	buf[off] = '\0';
	return off;
}

/* in-flight table */

static struct fd_inflight *
fd_inflight_alloc(struct fuse_drive *fd, uint32_t op, uint64_t fuse_unique,
		uint64_t nodeid, uint32_t *req_id_out)
{
	int i;
	for (i = 0; i < FD_INFLIGHT_MAX; i++) {
		if (!fd->inflight[i].in_use) {
			struct fd_inflight *f = &fd->inflight[i];
			f->in_use = 1;
			f->req_id = fd->next_req_id++;
			f->op = op;
			f->fuse_unique = fuse_unique;
			f->nodeid = nodeid;
			f->read_size = 0;
			*req_id_out = f->req_id;
			return f;
		}
	}
	return NULL;
}

static struct fd_inflight *
fd_inflight_find(struct fuse_drive *fd, uint32_t req_id)
{
	int i;
	for (i = 0; i < FD_INFLIGHT_MAX; i++)
		if (fd->inflight[i].in_use && fd->inflight[i].req_id == req_id)
			return &fd->inflight[i];
	return NULL;
}

/* NTSTATUS to errno */

static int
fd_status_to_errno(uint32_t status)
{
	switch (status) {
	case STATUS_SUCCESS:
		return 0;
	case STATUS_NO_SUCH_FILE:
	case STATUS_OBJECT_NAME_NOT_FOUND:
		return ENOENT;
	case 0xC0000022u:   /* STATUS_ACCESS_DENIED */
		return EACCES;
	default:
		return EIO;
	}
}

/* FUSE reply emit */

/* Write a fuse_out_header carrying an error (or success with no body). */
static void
fd_reply_error(struct fuse_drive *fd, uint64_t unique, int error)
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
fd_reply_ok(struct fuse_drive *fd, uint64_t unique,
		const void *body, size_t body_len)
{
	uint8_t buf[sizeof(struct fuse_out_header)
		+ sizeof(struct fuse_entry_out)];
	struct fuse_out_header oh;

	if (body_len > sizeof buf - sizeof oh) {
		fd_reply_error(fd, unique, -EIO);
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

/* Fill a fuse_attr for a node.  Directories report mode 0500 (browse),
 * files 0400 (read).  Size and times are synthetic for now. */
static void
fd_fill_attr(const struct fd_node *n, struct fuse_attr *a)
{
	memset(a, 0, sizeof *a);
	a->ino = n->nodeid;
	if (n->is_dir) {
		a->mode = S_IFDIR | 0500;
		a->nlink = 2;
		a->size = 0;
	} else {
		a->mode = S_IFREG | 0400;
		a->nlink = 1;
		a->size = 0;
	}
	a->uid = (uint32_t)getuid();
	a->gid = (uint32_t)getgid();
	a->blksize = 4096;
}

static void
fd_reply_attr(struct fuse_drive *fd, uint64_t unique, const struct fd_node *n)
{
	struct fuse_attr_out ao;
	memset(&ao, 0, sizeof ao);
	ao.attr_valid = 1;
	fd_fill_attr(n, &ao.attr);
	fd_reply_ok(fd, unique, &ao, sizeof ao);
}

static void
fd_reply_entry(struct fuse_drive *fd, uint64_t unique, const struct fd_node *n)
{
	struct fuse_entry_out eo;
	memset(&eo, 0, sizeof eo);
	eo.nodeid = n->nodeid;
	eo.entry_valid = 1;
	eo.attr_valid = 1;
	fd_fill_attr(n, &eo.attr);
	fd_reply_ok(fd, unique, &eo, sizeof eo);
}

/* backend FS_REQ senders */

static int
fd_send_open(struct fuse_drive *fd, struct fd_node *n, uint64_t unique,
		uint32_t op_tag)
{
	struct rdp_be_fs_req req;
	struct fd_inflight *f;
	char path[1024];
	size_t plen;

	plen = fd_node_path(fd, n, path, sizeof path);
	if (plen == (size_t)-1)
		return -1;
	f = fd_inflight_alloc(fd, op_tag, unique, n->nodeid, &req.req_id);
	if (f == NULL)
		return -1;
	req.op = RDP_FS_OPEN;
	req.device_id = n->device_id;
	req.file_id = 0;
	req.desired_access = 0;   /* worker substitutes read defaults */
	req.disposition = 0;
	req.options = 0;
	req.info_class = 0;
	req.length = 0;
	req.payload_len = (uint32_t)plen;
	req.offset = 0;
	return fd->send_fs_req(fd, &req, path, plen);
}

static int
fd_send_read(struct fuse_drive *fd, struct fd_node *n, uint64_t unique,
		uint64_t offset, uint32_t size)
{
	struct rdp_be_fs_req req;
	struct fd_inflight *f;

	f = fd_inflight_alloc(fd, RDP_FS_READ, unique, n->nodeid, &req.req_id);
	if (f == NULL)
		return -1;
	f->read_size = size;
	req.op = RDP_FS_READ;
	req.device_id = n->device_id;
	req.file_id = n->file_id;
	req.desired_access = 0;
	req.disposition = 0;
	req.options = 0;
	req.info_class = 0;
	req.length = size;
	req.payload_len = 0;
	req.offset = offset;
	return fd->send_fs_req(fd, &req, NULL, 0);
}

static int
fd_send_list(struct fuse_drive *fd, struct fd_node *n, uint64_t unique)
{
	struct rdp_be_fs_req req;
	struct fd_inflight *f;

	f = fd_inflight_alloc(fd, RDP_FS_LIST, unique, n->nodeid, &req.req_id);
	if (f == NULL)
		return -1;
	req.op = RDP_FS_LIST;
	req.device_id = n->device_id;
	req.file_id = n->file_id;
	req.desired_access = 0;
	req.disposition = 0;
	req.options = 0;
	req.info_class = 0;
	req.length = 0;
	req.payload_len = 0;   /* empty pattern => "*" at the worker */
	req.offset = 0;
	return fd->send_fs_req(fd, &req, NULL, 0);
}

static void
fd_send_close(struct fuse_drive *fd, struct fd_node *n)
{
	struct rdp_be_fs_req req;
	uint32_t req_id;
	struct fd_inflight *f;

	if (!n->have_open)
		return;
	/* CLOSE has no FUSE reply to correlate, but we still allocate a slot
	 * so the worker's FS_RSP for it is consumed cleanly. */
	f = fd_inflight_alloc(fd, RDP_FS_CLOSE, 0, n->nodeid, &req_id);
	if (f == NULL)
		req_id = fd->next_req_id++;   /* fire and forget */
	req.req_id = req_id;
	req.op = RDP_FS_CLOSE;
	req.device_id = n->device_id;
	req.file_id = n->file_id;
	req.desired_access = 0;
	req.disposition = 0;
	req.options = 0;
	req.info_class = 0;
	req.length = 0;
	req.payload_len = 0;
	req.offset = 0;
	(void)fd->send_fs_req(fd, &req, NULL, 0);
	n->have_open = 0;
	n->file_id = 0;
}

/* FUSE opcode handlers */

static void
fd_op_init(struct fuse_drive *fd, const struct fuse_in_header *ih,
		const uint8_t *body, size_t body_len)
{
	struct fuse_init_in in;
	struct fuse_init_out out;
	uint32_t kmajor, kminor;

	if (body_len < sizeof(uint32_t) * 2) {
		fd_reply_error(fd, ih->unique, -EINVAL);
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
		fd_reply_ok(fd, ih->unique, &out, sizeof out);
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
	fd_reply_ok(fd, ih->unique, &out, sizeof out);
}

static void
fd_op_getattr(struct fuse_drive *fd, const struct fuse_in_header *ih)
{
	struct fd_node *n = fd_node_find(fd, ih->nodeid);
	if (n == NULL) {
		fd_reply_error(fd, ih->unique, -ENOENT);
		return;
	}
	/* Synthetic directories answer immediately; real paths would need a
	 * QUERY_INFO round trip.  Since LOOKUP already established existence
	 * and the dir/file split, report the cached attr synchronously.
	 * Known limitation: file size and times are synthetic (0 / now). */
	fd_reply_attr(fd, ih->unique, n);
}

static void
fd_op_lookup(struct fuse_drive *fd, const struct fuse_in_header *ih,
		const uint8_t *body, size_t body_len)
{
	struct fd_node *parent = fd_node_find(fd, ih->nodeid);
	const char *name = (const char *)body;
	size_t namelen;
	struct fd_node *child;

	if (parent == NULL || !parent->is_dir) {
		fd_reply_error(fd, ih->unique, -ENOENT);
		return;
	}
	/* The name is a NUL-terminated string filling the request body. */
	if (body_len == 0 || body[body_len - 1] != '\0') {
		fd_reply_error(fd, ih->unique, -EINVAL);
		return;
	}
	namelen = strnlen(name, body_len);
	if (namelen == 0 || namelen > FD_NAME_MAX) {
		fd_reply_error(fd, ih->unique, -EINVAL);
		return;
	}

	/* Children of the synthetic root are the announced drives only; a
	 * name that is not a known drive cannot exist. */
	if (ih->nodeid == FUSE_ROOT_ID) {
		child = fd_child_find(fd, FUSE_ROOT_ID, name, namelen);
		if (child == NULL)
			fd_reply_error(fd, ih->unique, -ENOENT);
		else
			fd_reply_entry(fd, ih->unique, child);
		return;
	}

	/* Below a drive: create-or-find the child, then probe it with an
	 * OPEN.  The reply handler fills in the dir/file split and replies. */
	child = fd_child_make(fd, parent->nodeid, name, namelen,
		parent->device_id, 0);
	if (child == NULL) {
		fd_reply_error(fd, ih->unique, -ENOMEM);
		return;
	}
	/* The kernel re-LOOKUPs each entry once its validity timeout lapses.
	 * If we already hold an RDPDR handle for this node, reusing it avoids
	 * a second OPEN that would leak the prior client handle. */
	if (child->have_open) {
		child->nlookup++;
		fd_reply_entry(fd, ih->unique, child);
		return;
	}
	if (fd_send_open(fd, child, ih->unique, RDP_FS_OPEN) != 0)
		fd_reply_error(fd, ih->unique, -ENOMEM);
}

static void
fd_op_opendir(struct fuse_drive *fd, const struct fuse_in_header *ih)
{
	struct fd_node *n = fd_node_find(fd, ih->nodeid);
	struct fuse_open_out out;

	if (n == NULL || !n->is_dir) {
		fd_reply_error(fd, ih->unique, -ENOTDIR);
		return;
	}
	/* The synthetic root and per-drive roots are listed without an RDPDR
	 * handle.  A drive root needs a real open handle for READDIR, so open
	 * it lazily; the synthetic root does not. */
	if (ih->nodeid == FUSE_ROOT_ID) {
		memset(&out, 0, sizeof out);
		out.fh = ih->nodeid;
		fd_reply_ok(fd, ih->unique, &out, sizeof out);
		return;
	}
	if (n->have_open) {
		memset(&out, 0, sizeof out);
		out.fh = ih->nodeid;
		fd_reply_ok(fd, ih->unique, &out, sizeof out);
		return;
	}
	if (fd_send_open(fd, n, ih->unique, RDP_FS_OPENDIR_TAG) != 0)
		fd_reply_error(fd, ih->unique, -ENOMEM);
}

static void
fd_op_readdir(struct fuse_drive *fd, const struct fuse_in_header *ih,
		const uint8_t *body, size_t body_len)
{
	struct fuse_read_in ri;
	struct fd_node *n = fd_node_find(fd, ih->nodeid);

	if (n == NULL || !n->is_dir) {
		fd_reply_error(fd, ih->unique, -ENOTDIR);
		return;
	}
	if (body_len < sizeof ri) {
		fd_reply_error(fd, ih->unique, -EINVAL);
		return;
	}
	memcpy(&ri, body, sizeof ri);

	/* Root: synthesize one dirent per announced drive.  A non-zero
	 * offset means the kernel already consumed our single batch. */
	if (ih->nodeid == FUSE_ROOT_ID) {
		uint8_t out[FD_OUT_BUF_SZ];
		size_t off = 0;
		uint64_t doff = 0;
		int i;
		size_t want = ri.size < sizeof out ? ri.size : sizeof out;

		if (ri.offset != 0) {
			fd_reply_ok(fd, ih->unique, NULL, 0);
			return;
		}
		for (i = 0; i < FD_MAX_NODES; i++) {
			struct fd_node *d = &fd->nodes[i];
			struct fuse_dirent de;
			size_t namelen, reclen;
			if (!d->in_use || d->parent != FUSE_ROOT_ID
			    || !d->is_drive)
				continue;
			namelen = strlen(d->name);
			reclen = FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + namelen);
			if (off + reclen > want)
				break;
			doff++;
			memset(&de, 0, sizeof de);
			de.ino = d->nodeid;
			de.off = doff;
			de.namelen = (uint32_t)namelen;
			de.type = S_IFDIR >> 12;   /* DT_DIR */
			memcpy(out + off, &de, FUSE_NAME_OFFSET);
			memcpy(out + off + FUSE_NAME_OFFSET, d->name, namelen);
			/* Zero the alignment tail so no stack bytes leak. */
			if (reclen > FUSE_NAME_OFFSET + namelen)
				memset(out + off + FUSE_NAME_OFFSET + namelen, 0,
					reclen - (FUSE_NAME_OFFSET + namelen));
			off += reclen;
		}
		fd_reply_ok(fd, ih->unique, out, off);
		return;
	}

	/* A real drive directory.  We list it in one shot; a non-zero offset
	 * means the kernel wants more after our single batch, which we do not
	 * paginate yet, so return EOF.  Known limitation: directories whose
	 * full listing exceeds one batch are truncated to the first batch. */
	if (ri.offset != 0) {
		fd_reply_ok(fd, ih->unique, NULL, 0);
		return;
	}
	if (!n->have_open) {
		fd_reply_error(fd, ih->unique, -EBADF);
		return;
	}
	if (fd_send_list(fd, n, ih->unique) != 0)
		fd_reply_error(fd, ih->unique, -ENOMEM);
}

static void
fd_op_open(struct fuse_drive *fd, const struct fuse_in_header *ih)
{
	struct fd_node *n = fd_node_find(fd, ih->nodeid);
	struct fuse_open_out out;

	if (n == NULL) {
		fd_reply_error(fd, ih->unique, -ENOENT);
		return;
	}
	if (n->is_dir) {
		fd_reply_error(fd, ih->unique, -EISDIR);
		return;
	}
	if (n->have_open) {
		memset(&out, 0, sizeof out);
		out.fh = ih->nodeid;
		out.open_flags = FOPEN_DIRECT_IO;
		fd_reply_ok(fd, ih->unique, &out, sizeof out);
		return;
	}
	if (fd_send_open(fd, n, ih->unique, RDP_FS_OPENFILE_TAG) != 0)
		fd_reply_error(fd, ih->unique, -ENOMEM);
}

static void
fd_op_read(struct fuse_drive *fd, const struct fuse_in_header *ih,
		const uint8_t *body, size_t body_len)
{
	struct fuse_read_in ri;
	struct fd_node *n = fd_node_find(fd, ih->nodeid);
	uint32_t size;

	if (n == NULL || n->is_dir || !n->have_open) {
		fd_reply_error(fd, ih->unique, -EBADF);
		return;
	}
	if (body_len < sizeof ri) {
		fd_reply_error(fd, ih->unique, -EINVAL);
		return;
	}
	memcpy(&ri, body, sizeof ri);
	size = ri.size;
	if (size > FD_MAX_READ)
		size = FD_MAX_READ;
	if (fd_send_read(fd, n, ih->unique, ri.offset, size) != 0)
		fd_reply_error(fd, ih->unique, -ENOMEM);
}

static void
fd_op_release(struct fuse_drive *fd, const struct fuse_in_header *ih)
{
	struct fd_node *n = fd_node_find(fd, ih->nodeid);
	if (n != NULL)
		fd_send_close(fd, n);
	fd_reply_error(fd, ih->unique, 0);   /* success, no body */
}

/*
 * Drop nlookup references from a node, freeing it when the count reaches
 * zero (closing any open RDPDR handle first).  Shared by FUSE_FORGET and
 * FUSE_BATCH_FORGET.  The synthetic root and per-drive roots are never
 * forgotten. */
static void
fd_forget_node(struct fuse_drive *fd, uint64_t nodeid, uint64_t nlookup)
{
	struct fd_node *n;

	if (nodeid == FUSE_ROOT_ID)
		return;
	n = fd_node_find(fd, nodeid);
	if (n == NULL || n->is_drive)
		return;
	if (nlookup >= n->nlookup)
		n->nlookup = 0;
	else
		n->nlookup -= nlookup;
	if (n->nlookup == 0) {
		if (n->have_open)
			fd_send_close(fd, n);
		n->in_use = 0;
	}
}

static void
fd_op_forget(struct fuse_drive *fd, const struct fuse_in_header *ih,
		const uint8_t *body, size_t body_len)
{
	struct fuse_forget_in in;

	if (body_len < sizeof in)
		return;   /* FORGET has no reply regardless */
	memcpy(&in, body, sizeof in);
	fd_forget_node(fd, ih->nodeid, in.nlookup);
}

/*
 * BATCH_FORGET carries a count followed by that many (nodeid, nlookup)
 * records.  The kernel uses it by default at minor 27.  Like FORGET it
 * has no reply; each record is bounds checked against the body before it
 * is consumed. */
static void
fd_op_batch_forget(struct fuse_drive *fd, const struct fuse_in_header *ih,
		const uint8_t *body, size_t body_len)
{
	struct fuse_batch_forget_in in;
	struct fuse_forget_one one;
	size_t off;
	uint32_t i;

	(void)ih;
	if (body_len < sizeof in)
		return;   /* BATCH_FORGET has no reply regardless */
	memcpy(&in, body, sizeof in);
	off = sizeof in;
	for (i = 0; i < in.count; i++) {
		if (off + sizeof one > body_len)
			break;
		memcpy(&one, body + off, sizeof one);
		off += sizeof one;
		fd_forget_node(fd, one.nodeid, one.nlookup);
	}
}

/*
 * Dispatch a single fully framed FUSE request.  buf points at the
 * fuse_in_header; len is the byte count the kernel reported in the
 * header and is guaranteed by the caller to be in [sizeof header, avail].
 */
static void
fd_dispatch(struct fuse_drive *fd, const uint8_t *buf, size_t len)
{
	struct fuse_in_header ih;
	const uint8_t *body;
	size_t body_len;

	memcpy(&ih, buf, sizeof ih);
	body = buf + sizeof ih;
	body_len = len - sizeof ih;

	switch (ih.opcode) {
	case FUSE_INIT:
		fd_op_init(fd, &ih, body, body_len);
		break;
	case FUSE_GETATTR:
		fd_op_getattr(fd, &ih);
		break;
	case FUSE_LOOKUP:
		fd_op_lookup(fd, &ih, body, body_len);
		break;
	case FUSE_OPENDIR:
		fd_op_opendir(fd, &ih);
		break;
	case FUSE_READDIR:
		fd_op_readdir(fd, &ih, body, body_len);
		break;
	case FUSE_OPEN:
		fd_op_open(fd, &ih);
		break;
	case FUSE_READ:
		fd_op_read(fd, &ih, body, body_len);
		break;
	case FUSE_RELEASE:
	case FUSE_RELEASEDIR:
		fd_op_release(fd, &ih);
		break;
	case FUSE_FLUSH:
		fd_reply_error(fd, ih.unique, 0);
		break;
	case FUSE_FORGET:
		fd_op_forget(fd, &ih, body, body_len);
		break;   /* no reply */
	case FUSE_BATCH_FORGET:
		fd_op_batch_forget(fd, &ih, body, body_len);
		break;   /* no reply */
	default:
		fd_reply_error(fd, ih.unique, -ENOSYS);
		break;
	}
}

/* FS_RSP completion */

/*
 * Parse one FileBothDirectoryInformation record at fdi[0..avail) and emit
 * a fuse_dirent into out at *off (bounded by out_cap).  Returns the
 * number of FSCC bytes consumed (the record's NextEntryOffset, or the
 * remaining bytes for the last record), or 0 to stop.  Every field is
 * bounds checked against avail before use.
 *
 * FILE_BOTH_DIR_INFORMATION layout (MS-FSCC 2.4.8):
 *   0  NextEntryOffset  u32
 *   4  FileIndex        u32
 *   8  CreationTime     u64
 *   16 LastAccessTime   u64
 *   24 LastWriteTime    u64
 *   32 ChangeTime       u64
 *   40 EndOfFile        u64
 *   48 AllocationSize   u64
 *   56 FileAttributes   u32
 *   60 FileNameLength   u32   (bytes, UTF-16LE)
 *   64 EaSize           u32
 *   68 ShortNameLength  u8
 *   69 Reserved         u8
 *   70 ShortName        24 bytes
 *   94 FileName         FileNameLength bytes
 */
#define FDI_FIXED 94u
#define FILE_ATTRIBUTE_DIRECTORY 0x00000010u

static size_t
fd_emit_one_dirent(struct fuse_drive *fd, const uint8_t *fdi, size_t avail,
		uint8_t *out, size_t *off, size_t out_cap,
		uint32_t device_id, uint64_t parent, uint64_t *doff)
{
	uint32_t next, name_bytes, attrs;
	size_t name_chars, i, reclen;
	struct fuse_dirent de;
	char name[FD_NAME_MAX + 1];
	struct fd_node *child;
	int is_dir;

	if (avail < FDI_FIXED)
		return 0;
	next = fd_ld32(fdi + 0);
	attrs = fd_ld32(fdi + 56);
	name_bytes = fd_ld32(fdi + 60);
	/* The name must fit inside this record's bytes. */
	if (name_bytes > avail - FDI_FIXED)
		return 0;
	name_chars = name_bytes / 2;   /* UTF-16LE; we keep the low byte */
	if (name_chars > FD_NAME_MAX)
		name_chars = FD_NAME_MAX;
	for (i = 0; i < name_chars; i++)
		name[i] = (char)fdi[FDI_FIXED + i * 2];
	name[name_chars] = '\0';

	/* Skip the "." and ".." pseudo-entries; the kernel synthesizes them. */
	if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
		goto advance;
	if (name_chars == 0)
		goto advance;

	is_dir = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
	child = fd_child_make(fd, parent, name, name_chars, device_id, is_dir);
	reclen = FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + name_chars);
	if (*off + reclen > out_cap)
		return 0;   /* buffer full: stop without overflowing */
	(*doff)++;
	memset(&de, 0, sizeof de);
	de.ino = child != NULL ? child->nodeid : 0;
	de.off = *doff;
	de.namelen = (uint32_t)name_chars;
	de.type = is_dir ? (S_IFDIR >> 12) : (S_IFREG >> 12);
	memcpy(out + *off, &de, FUSE_NAME_OFFSET);
	memcpy(out + *off + FUSE_NAME_OFFSET, name, name_chars);
	if (reclen > FUSE_NAME_OFFSET + name_chars)
		memset(out + *off + FUSE_NAME_OFFSET + name_chars, 0,
			reclen - (FUSE_NAME_OFFSET + name_chars));
	*off += reclen;

advance:
	/* NextEntryOffset of 0 marks the final record. */
	if (next == 0)
		return avail;
	if (next < FDI_FIXED || next > avail)
		return 0;
	return next;
}

static void
fd_complete_list(struct fuse_drive *fd, struct fd_inflight *f, uint32_t status,
		const uint8_t *payload, size_t payload_len)
{
	struct fd_node *n = fd_node_find(fd, f->nodeid);
	uint8_t out[FD_OUT_BUF_SZ];
	size_t outoff = 0;
	uint64_t doff = 0;
	const uint8_t *fdi;
	size_t avail;
	uint32_t fscc_len;

	if (n == NULL) {
		fd_reply_error(fd, f->fuse_unique, -ENOENT);
		return;
	}
	if (status != STATUS_SUCCESS) {
		/* No-more-files on the very first query is an empty dir. */
		if (status == STATUS_NO_MORE_FILES)
			fd_reply_ok(fd, f->fuse_unique, NULL, 0);
		else
			fd_reply_error(fd, f->fuse_unique,
				-fd_status_to_errno(status));
		return;
	}
	/* The LIST payload is Length(u32) + FileBothDirectoryInformation
	 * buffer (the worker forwards the DR_DRIVE_QUERY_DIRECTORY_RSP body
	 * verbatim).  Bound the inner length against what we actually got. */
	if (payload_len < 4) {
		fd_reply_ok(fd, f->fuse_unique, NULL, 0);
		return;
	}
	fscc_len = fd_ld32(payload);
	fdi = payload + 4;
	avail = payload_len - 4;
	if (fscc_len < avail)
		avail = fscc_len;

	while (avail >= FDI_FIXED && outoff < sizeof out) {
		size_t used = fd_emit_one_dirent(fd, fdi, avail,
			out, &outoff, sizeof out, n->device_id, n->nodeid,
			&doff);
		if (used == 0 || used > avail)
			break;
		fdi += used;
		avail -= used;
	}
	fd_reply_ok(fd, f->fuse_unique, out, outoff);
}

static void
fd_complete_read(struct fuse_drive *fd, struct fd_inflight *f, uint32_t status,
		const uint8_t *payload, size_t payload_len)
{
	uint32_t data_len;
	const uint8_t *data;

	if (status != STATUS_SUCCESS) {
		fd_reply_error(fd, f->fuse_unique, -fd_status_to_errno(status));
		return;
	}
	/* READ payload is FSCC Length(u32) + ReadData.  Bound the declared
	 * length against the bytes received and the size the kernel asked. */
	if (payload_len < 4) {
		fd_reply_ok(fd, f->fuse_unique, NULL, 0);
		return;
	}
	data_len = fd_ld32(payload);
	data = payload + 4;
	if (data_len > payload_len - 4)
		data_len = (uint32_t)(payload_len - 4);
	if (data_len > f->read_size)
		data_len = f->read_size;

	{
		struct fuse_out_header oh;
		memset(&oh, 0, sizeof oh);
		oh.len = (uint32_t)(sizeof oh + data_len);
		oh.error = 0;
		oh.unique = f->fuse_unique;
		(void)fd->write_reply(fd, &oh, sizeof oh);
		if (data_len > 0)
			(void)fd->write_reply(fd, data, data_len);
	}
}

/* OPEN completion serving a LOOKUP, OPEN, or OPENDIR.  file_id was
 * pre-extracted by the worker into rsp->file_id. */
static void
fd_complete_open(struct fuse_drive *fd, struct fd_inflight *f, uint32_t status,
		uint32_t file_id)
{
	struct fd_node *n = fd_node_find(fd, f->nodeid);
	struct fuse_open_out out;

	if (n == NULL) {
		fd_reply_error(fd, f->fuse_unique, -ENOENT);
		return;
	}
	if (status != STATUS_SUCCESS) {
		/* A failed probe drops the speculative LOOKUP node. */
		if (f->op == RDP_FS_OPEN && !n->is_drive && n->nlookup == 0)
			n->in_use = 0;
		fd_reply_error(fd, f->fuse_unique, -fd_status_to_errno(status));
		return;
	}
	n->file_id = file_id;
	n->have_open = 1;

	switch (f->op) {
	case RDP_FS_OPEN:
		/* Came from LOOKUP: report the entry.  We could not learn the
		 * dir/file split from create alone, so keep whatever LOOKUP
		 * guessed (file by default); a later QUERY_INFO stage will
		 * refine this.  The handle stays open for a following OPEN. */
		n->nlookup++;
		fd_reply_entry(fd, f->fuse_unique, n);
		break;
	case RDP_FS_OPENFILE_TAG:   /* a direct FUSE_OPEN of a regular file */
		memset(&out, 0, sizeof out);
		out.fh = n->nodeid;
		out.open_flags = FOPEN_DIRECT_IO;
		fd_reply_ok(fd, f->fuse_unique, &out, sizeof out);
		break;
	case RDP_FS_OPENDIR_TAG:
		memset(&out, 0, sizeof out);
		out.fh = n->nodeid;
		fd_reply_ok(fd, f->fuse_unique, &out, sizeof out);
		break;
	default:
		fd_reply_error(fd, f->fuse_unique, -EIO);
		break;
	}
}

void
fuse_drive_handle_fs_rsp(struct fuse_drive *fd, const void *rsp_v,
		const uint8_t *payload, size_t payload_len)
{
	const struct rdp_be_fs_rsp *rsp = rsp_v;
	struct fd_inflight *f;
	uint32_t op;

	if (fd == NULL || rsp == NULL)
		return;
	f = fd_inflight_find(fd, rsp->req_id);
	if (f == NULL)
		return;   /* stale or CLOSE we already forgot */
	op = f->op;
	f->in_use = 0;

	if (op == RDP_FS_CLOSE)
		return;   /* nothing to reply */

	switch (op) {
	case RDP_FS_OPEN:
	case RDP_FS_OPENFILE_TAG:
	case RDP_FS_OPENDIR_TAG:
		fd_complete_open(fd, f, rsp->status, rsp->file_id);
		break;
	case RDP_FS_READ:
		fd_complete_read(fd, f, rsp->status, payload, payload_len);
		break;
	case RDP_FS_LIST:
		fd_complete_list(fd, f, rsp->status, payload, payload_len);
		break;
	default:
		fd_reply_error(fd, f->fuse_unique, -EIO);
		break;
	}
}

/* live fd sinks */

static int
fd_live_send_fs_req(struct fuse_drive *fd, const struct rdp_be_fs_req *req,
		const void *payload, size_t payload_len)
{
	uint32_t hdr[2];
	uint32_t frame_len = (uint32_t)(sizeof *req + payload_len);

	/* Frame: type(u32) + length(u32) + body.  rdp_be_send cannot carry
	 * two buffers, so emit the framed bytes directly. */
	hdr[0] = RDP_BE_FS_REQ;
	hdr[1] = frame_len;
	if (rdp_write_full(fd->be_fd, hdr, sizeof hdr) != (ssize_t)sizeof hdr)
		return -1;
	if (rdp_write_full(fd->be_fd, req, sizeof *req)
	    != (ssize_t)sizeof *req)
		return -1;
	if (payload_len > 0
	    && rdp_write_full(fd->be_fd, payload, payload_len)
	    != (ssize_t)payload_len)
		return -1;
	return 0;
}

static int
fd_live_write_reply(struct fuse_drive *fd, const void *buf, size_t len)
{
	ssize_t w;
	do {
		w = write(fd->fuse_fd, buf, len);
	} while (w < 0 && errno == EINTR);
	/* ENOENT here means the kernel already cancelled the request
	 * (interrupt/abort); that is not fatal to the channel. */
	return w == (ssize_t)len ? 0 : -1;
}

/* public API */

static void
fd_common_init(struct fuse_drive *fd)
{
	struct fd_node *root;
	fd->next_req_id = 1;
	fd->next_nodeid = FUSE_ROOT_ID + 1;
	root = &fd->nodes[0];
	memset(root, 0, sizeof *root);
	root->in_use = 1;
	root->nodeid = FUSE_ROOT_ID;
	root->parent = 0;
	root->is_dir = 1;
}

struct fuse_drive *
fuse_drive_init(int fuse_fd, int be_fd)
{
	struct fuse_drive *fd;
	struct stat sb;

	if (fuse_fd < 0)
		return NULL;
	/* fd 4 is only a fuse fd when sessionmgr mounted one.  A character
	 * device is the cheap, safe probe; anything else means no drive. */
	if (fstat(fuse_fd, &sb) != 0 || !S_ISCHR(sb.st_mode))
		return NULL;

	/* The fd we inherit is blocking.  fuse_drive_process drains several
	 * requests per call and relies on read() returning EAGAIN to stop;
	 * on a blocking fd the second read would stall the single-threaded
	 * session loop, so switch to non-blocking. */
	{
		int fl = fcntl(fuse_fd, F_GETFL, 0);
		if (fl < 0 || fcntl(fuse_fd, F_SETFL, fl | O_NONBLOCK) < 0) {
			rdp_warn("fuse drive: cannot set O_NONBLOCK on fd %d: %s",
				fuse_fd, strerror(errno));
			return NULL;
		}
	}

	fd = calloc(1, sizeof *fd);
	if (fd == NULL)
		return NULL;
	fd->fuse_fd = fuse_fd;
	fd->be_fd = be_fd;
	fd->send_fs_req = fd_live_send_fs_req;
	fd->write_reply = fd_live_write_reply;
	fd_common_init(fd);
	rdp_info("fuse drive: read-path active on fd %d", fuse_fd);
	return fd;
}

void
fuse_drive_free(struct fuse_drive *fd)
{
	free(fd);
}

int
fuse_drive_fd(const struct fuse_drive *fd)
{
	return fd != NULL ? fd->fuse_fd : -1;
}

void
fuse_drive_add_device(struct fuse_drive *fd, uint32_t device_id,
		uint32_t device_type, const char *name, int added)
{
	struct fd_node *n;
	char label[FD_NAME_MAX + 1];
	size_t i, ln;

	if (fd == NULL || name == NULL)
		return;
	(void)device_type;

	/* Sanitise the 8-byte client label into a single safe path
	 * component: trim trailing spaces/NULs and drop slashes. */
	ln = 0;
	for (i = 0; i < 8 && name[i] != '\0'; i++) {
		char c = name[i];
		if (c == '/' || c == '\\')
			c = '_';
		label[ln++] = c;
	}
	while (ln > 0 && (label[ln - 1] == ' ' || label[ln - 1] == '\t'))
		ln--;
	if (ln == 0) {
		(void)snprintf(label, sizeof label, "drive%u",
			(unsigned)device_id);
		ln = strlen(label);
	} else {
		label[ln] = '\0';
	}

	if (!added) {
		int j;
		for (j = 0; j < FD_MAX_NODES; j++) {
			n = &fd->nodes[j];
			if (n->in_use && n->is_drive && n->device_id == device_id)
				n->in_use = 0;
		}
		return;
	}

	/* Idempotent announce. */
	n = fd_child_find(fd, FUSE_ROOT_ID, label, ln);
	if (n != NULL && n->is_drive)
		return;
	n = fd_child_make(fd, FUSE_ROOT_ID, label, ln, device_id, 1);
	if (n == NULL) {
		rdp_warn("fuse drive: node table full, dropping drive '%s'",
			label);
		return;
	}
	n->is_drive = 1;
	rdp_info("fuse drive: announced '%s' (device %u) as node %llu",
		label, (unsigned)device_id, (unsigned long long)n->nodeid);
}

int
fuse_drive_process(struct fuse_drive *fd)
{
	uint8_t buf[FD_IN_BUF_SZ];
	int handled = 0;

	if (fd == NULL)
		return 0;
	/* Drain a bounded number of requests per call so one busy directory
	 * cannot starve the rest of the session loop. */
	while (handled < 64) {
		ssize_t r;
		struct fuse_in_header ih;
		size_t len;
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
		fd_dispatch(fd, buf, len);
		handled++;
	}
	return 0;
}

#ifdef RDP_FUSE_TEST
/*
 * Test harness hooks.  Compiled only into the regress binary
 * (-DRDP_FUSE_TEST).  They let the test drive fd_dispatch and the FS_RSP
 * path on in-memory buffers and inspect the captured FS_REQ frame and
 * FUSE reply bytes through accessors, so the test never needs the layout
 * of the private capture struct.
 */

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

struct fd_test_capture {
	int      have_req;
	struct rdp_be_fs_req req;
	uint8_t  req_payload[2048];
	size_t   req_payload_len;
	uint8_t  reply[FD_OUT_BUF_SZ];
	size_t   reply_len;
};

static struct fd_test_capture fd_test_cap;

static int
fd_test_send_fs_req(struct fuse_drive *fd, const struct rdp_be_fs_req *req,
		const void *payload, size_t payload_len)
{
	struct fd_test_capture *c = fd->sink_ctx;
	(void)fd;
	c->have_req = 1;
	c->req = *req;
	c->req_payload_len = payload_len < sizeof c->req_payload
		? payload_len : sizeof c->req_payload;
	if (c->req_payload_len > 0)
		memcpy(c->req_payload, payload, c->req_payload_len);
	return 0;
}

static int
fd_test_write_reply(struct fuse_drive *fd, const void *buf, size_t len)
{
	struct fd_test_capture *c = fd->sink_ctx;
	(void)fd;
	if (c->reply_len + len > sizeof c->reply)
		return -1;
	memcpy(c->reply + c->reply_len, buf, len);
	c->reply_len += len;
	return 0;
}

struct fuse_drive *
fuse_drive_test_new(void)
{
	struct fuse_drive *fd = calloc(1, sizeof *fd);
	if (fd == NULL)
		return NULL;
	fd->fuse_fd = -1;
	fd->be_fd = -1;
	fd->sink_ctx = &fd_test_cap;
	fd->send_fs_req = fd_test_send_fs_req;
	fd->write_reply = fd_test_write_reply;
	fd_common_init(fd);
	return fd;
}

/* Reset both captures before driving an op. */
void
fuse_drive_test_reset(void)
{
	memset(&fd_test_cap, 0, sizeof fd_test_cap);
}

void
fuse_drive_test_dispatch(struct fuse_drive *fd, const uint8_t *buf, size_t len)
{
	fd_dispatch(fd, buf, len);
}

/* Accessors for the captured FS_REQ. */
int      fuse_drive_test_have_req(void) { return fd_test_cap.have_req; }
uint32_t fuse_drive_test_req_op(void) { return fd_test_cap.req.op; }
uint32_t fuse_drive_test_req_id(void) { return fd_test_cap.req.req_id; }
uint32_t fuse_drive_test_req_device(void)
	{ return fd_test_cap.req.device_id; }
uint32_t fuse_drive_test_req_file_id(void)
	{ return fd_test_cap.req.file_id; }
uint32_t fuse_drive_test_req_length(void) { return fd_test_cap.req.length; }
uint64_t fuse_drive_test_req_offset(void) { return fd_test_cap.req.offset; }

const uint8_t *
fuse_drive_test_req_payload(size_t *len_out)
{
	if (len_out != NULL)
		*len_out = fd_test_cap.req_payload_len;
	return fd_test_cap.req_payload;
}

/* Accessors for the captured FUSE reply. */
const uint8_t *
fuse_drive_test_reply(size_t *len_out)
{
	if (len_out != NULL)
		*len_out = fd_test_cap.reply_len;
	return fd_test_cap.reply;
}
#endif /* RDP_FUSE_TEST */

#else /* !HAVE_FUSE: no-op stubs */

struct fuse_drive *
fuse_drive_init(int fuse_fd, int be_fd)
{
	(void)fuse_fd;
	(void)be_fd;
	return NULL;
}

void fuse_drive_free(struct fuse_drive *fd) { (void)fd; }
int  fuse_drive_process(struct fuse_drive *fd) { (void)fd; return 0; }
int  fuse_drive_fd(const struct fuse_drive *fd) { (void)fd; return -1; }

void
fuse_drive_add_device(struct fuse_drive *fd, uint32_t device_id,
		uint32_t device_type, const char *name, int added)
{
	(void)fd; (void)device_id; (void)device_type; (void)name; (void)added;
}

void
fuse_drive_handle_fs_rsp(struct fuse_drive *fd, const void *rsp,
		const uint8_t *payload, size_t payload_len)
{
	(void)fd; (void)rsp; (void)payload; (void)payload_len;
}

#endif /* HAVE_FUSE */
