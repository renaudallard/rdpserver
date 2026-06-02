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
 * fuse_drive.c -- raw /dev/fuse read-write path for RDPDR drive
 * redirection.
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
 *   GETATTR / LOOKUP metadata chain.  Synthetic directories (root and the
 *   per-drive roots) answer immediately with a fabricated dir attr.  Any
 *   other path runs a two-step QUERY_INFO chain on the node's open handle
 *   (opening it read-access first if no handle is held, and keeping it
 *   open as the read path does): FileStandardInformation yields the size
 *   and the dir/file split, then FileBasicInformation yields the
 *   timestamps and attributes.  The decoded attr is reported in the
 *   fuse_entry_out (LOOKUP) or fuse_attr_out (GETATTR/SETATTR).  Every
 *   FSCC field is bounds checked before use; on any query failure the
 *   chain falls back to a synthetic attr (size 0, zeroed times) and still
 *   replies so the kernel is never left waiting.  The open handle from the
 *   chain is reused for a following OPEN/OPENDIR so a browse does not
 *   reopen the same path twice.
 *
 *   Write path.  FUSE_OPEN maps the open(2) access mode to an RDPDR
 *   DesiredAccess (read, write, or both); a held read-only handle is
 *   upgraded by closing and reopening with the union of the old and new
 *   access (one handle per node, KISS).  FUSE_WRITE forwards the data with
 *   an RDP_FS_WRITE and reports the bytes the client acknowledges.
 *   FUSE_SETATTR turns a size change into a FileEndOfFileInformation
 *   SetInformation (truncate or extend, including save-with-truncate) and
 *   a time change into a FileBasicInformation SetInformation, then
 *   re-queries for the post-set attr.
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
#include <time.h>
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
#define RDP_FS_GETATTR_TAG   103u   /* OPEN issued to drive a getattr chain */
#define RDP_FS_SETATTR_TAG   104u   /* SET_INFO whose reply ends a setattr */

/* Read buffer: large enough for a 128 KiB write payload plus headers, so
 * one FUSE_WRITE request (fuse_write_in + up to max_write data bytes)
 * fits in a single read. */
#define FD_IN_BUF_SZ         (FD_MAX_WRITE + 4096u)
/* Reply scratch: a READDIR fills at most the requested size, capped. */
#define FD_OUT_BUF_SZ        (128u * 1024u + 4096u)

/*
 * Multi-step phase for an in-flight getattr/setattr chain.  A GETATTR or
 * LOOKUP on a real node walks PHASE_GETATTR_STD then PHASE_GETATTR_BASIC,
 * accumulating the decoded attributes between steps.  PHASE_NONE is a
 * single-step op (OPEN/READ/LIST/WRITE/CLOSE/SET_INFO).
 */
enum fd_phase {
	PHASE_NONE = 0,
	PHASE_GETATTR_STD,    /* awaiting FileStandardInformation reply */
	PHASE_GETATTR_BASIC,  /* awaiting FileBasicInformation reply */
	PHASE_GETATTR_OPEN,   /* awaiting an OPEN before the query chain */
	PHASE_SETATTR_EOF_THEN_TIME /* EOF set done -> issue the time set next */
};

/* Pending FileBasicInformation set carried across an EOF set completion for
 * a combined size+time SETATTR.  The times are already resolved to FILETIME
 * (ATIME_NOW/MTIME_NOW turned into a real wall-clock time). */
struct fd_time_set {
	int      set_atime, set_mtime;
	uint64_t atime_ft, mtime_ft;
};

/* Decoded attributes accumulated across the getattr chain.  Unix times
 * are seconds since the epoch; 0 means "no value" (FILETIME was 0). */
struct fd_attr_acc {
	uint64_t size;
	uint64_t mtime, atime, ctime;
	int      is_dir;
	int      readonly;
};

struct fd_node {
	int      in_use;
	uint64_t nodeid;
	uint64_t parent;       /* parent nodeid; 0 for root */
	uint32_t device_id;    /* owning RDPDR drive; 0 for the synthetic root */
	int      is_drive;     /* a per-drive top-level directory */
	int      is_dir;
	uint32_t file_id;      /* open RDPDR handle, 0 when not open */
	int      have_open;    /* file_id is valid */
	unsigned open_refs;    /* kernel fds sharing this handle (open/release) */
	uint32_t access;       /* DesiredAccess granted on the open handle */
	uint64_t nlookup;      /* kernel lookup count, decremented by FORGET */
	char     name[FD_NAME_MAX + 1];
};

struct fd_inflight {
	int      in_use;
	uint32_t req_id;
	uint64_t fuse_unique;
	uint32_t op;           /* RDP_FS_* (or a private *_TAG) */
	uint64_t nodeid;       /* node the op concerns */
	uint32_t read_size;    /* READ/WRITE: bytes the kernel asked for */
	uint32_t req_access;   /* OPEN: DesiredAccess requested (0 = default) */
	uint32_t reply_op;     /* getattr chain: FUSE_LOOKUP -> entry, else attr */
	enum fd_phase phase;   /* getattr/setattr chain step */
	struct fd_attr_acc acc;/* accumulated attrs for the getattr chain */
	struct fd_time_set time_set; /* pending time set for combined SETATTR */
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

static uint64_t
fd_ld64(const uint8_t *p)
{
	return (uint64_t)fd_ld32(p) | ((uint64_t)fd_ld32(p + 4) << 32);
}

static void
fd_st64(uint8_t *p, uint64_t v)
{
	int i;
	for (i = 0; i < 8; i++)
		p[i] = (uint8_t)(v >> (i * 8));
}

/*
 * FILETIME (100ns ticks since 1601) to unix seconds + nsec.  A zero
 * FILETIME means "no value"; we report unix 0 so the attr shows the
 * epoch rather than a bogus 1601 date.  All math is unsigned and bounded:
 * ft / 10000000 cannot exceed the input, and the 11644473600 epoch shift
 * is only applied when it would not underflow.
 */
static void
fd_filetime_to_unix(uint64_t ft, uint64_t *sec_out, uint32_t *nsec_out)
{
	uint64_t whole, rem;
	*sec_out = 0;
	*nsec_out = 0;
	if (ft == 0)
		return;
	whole = ft / 10000000u;
	rem = ft % 10000000u;
	if (whole < 11644473600u)
		return;   /* pre-1970; clamp to the epoch */
	*sec_out = whole - 11644473600u;
	*nsec_out = (uint32_t)(rem * 100u);
}

/* unix seconds + nsec to FILETIME (100ns ticks since 1601). */
static uint64_t
fd_unix_to_filetime(uint64_t sec, uint32_t nsec)
{
	return (sec + 11644473600u) * 10000000u + (uint64_t)(nsec / 100u);
}

/* MS-FSCC FileAttributes bits we honour. */
#define FILE_ATTRIBUTE_READONLY  0x00000001u
/* FILE_ATTRIBUTE_DIRECTORY (0x10) is defined alongside the dirent decoder. */

/* Minimum lengths of the FSCC structures we decode/encode. */
#define FSCC_STD_INFO_LEN    24u   /* FileStandardInformation */
#define FSCC_BASIC_INFO_LEN  36u   /* FileBasicInformation (fixed prefix) */
#define FSCC_EOF_INFO_LEN     8u   /* FileEndOfFileInformation */

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
			memset(f, 0, sizeof *f);
			f->in_use = 1;
			f->req_id = fd->next_req_id++;
			f->op = op;
			f->fuse_unique = fuse_unique;
			f->nodeid = nodeid;
			f->read_size = 0;
			f->phase = PHASE_NONE;
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
 * files 0400 (read), 0600 when write access has been granted.  When acc
 * is non-NULL the size and times come from a QUERY_INFO chain; otherwise
 * they are synthetic (size 0, zeroed times). */
static void
fd_fill_attr(const struct fd_node *n, struct fuse_attr *a,
		const struct fd_attr_acc *acc)
{
	int is_dir = n->is_dir;

	memset(a, 0, sizeof *a);
	a->ino = n->nodeid;
	if (acc != NULL)
		is_dir = acc->is_dir;
	if (is_dir) {
		a->mode = S_IFDIR | 0500;
		a->nlink = 2;
		a->size = acc != NULL ? acc->size : 0;
	} else {
		a->mode = S_IFREG | 0400;
		a->nlink = 1;
		a->size = acc != NULL ? acc->size : 0;
		/* Reflect a writable handle, unless the file is read-only. */
		if (n->have_open && (n->access & FILE_WRITE_DATA)
		    && (acc == NULL || !acc->readonly))
			a->mode |= 0200;
	}
	if (acc != NULL) {
		a->mtime = acc->mtime;
		a->atime = acc->atime;
		a->ctime = acc->ctime;
	}
	a->uid = (uint32_t)getuid();
	a->gid = (uint32_t)getgid();
	a->blksize = 4096;
}

static void
fd_reply_attr_acc(struct fuse_drive *fd, uint64_t unique,
		const struct fd_node *n, const struct fd_attr_acc *acc)
{
	struct fuse_attr_out ao;
	memset(&ao, 0, sizeof ao);
	ao.attr_valid = 1;
	fd_fill_attr(n, &ao.attr, acc);
	fd_reply_ok(fd, unique, &ao, sizeof ao);
}

static void
fd_reply_attr(struct fuse_drive *fd, uint64_t unique, const struct fd_node *n)
{
	fd_reply_attr_acc(fd, unique, n, NULL);
}

static void
fd_reply_entry_acc(struct fuse_drive *fd, uint64_t unique,
		const struct fd_node *n, const struct fd_attr_acc *acc)
{
	struct fuse_entry_out eo;
	memset(&eo, 0, sizeof eo);
	eo.nodeid = n->nodeid;
	eo.entry_valid = 1;
	eo.attr_valid = 1;
	fd_fill_attr(n, &eo.attr, acc);
	fd_reply_ok(fd, unique, &eo, sizeof eo);
}

static void
fd_reply_entry(struct fuse_drive *fd, uint64_t unique, const struct fd_node *n)
{
	fd_reply_entry_acc(fd, unique, n, NULL);
}

/* backend FS_REQ senders */

/*
 * Send an OPEN (RDPDR create) for node n.  desired_access of 0 lets the
 * worker substitute its read defaults; a non-zero value (FILE_READ_DATA
 * and/or FILE_WRITE_DATA) requests that access explicitly.  op_tag tells
 * the completion which FUSE op the open was serving.  Returns the new
 * in-flight slot via *f_out (never NULL on success) so a caller driving a
 * multi-step chain can stash phase/accumulator state on it.
 */
static int
fd_send_open_ex(struct fuse_drive *fd, struct fd_node *n, uint64_t unique,
		uint32_t op_tag, uint32_t desired_access,
		struct fd_inflight **f_out)
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
	f->req_access = desired_access;   /* recorded on the node when granted */
	req.op = RDP_FS_OPEN;
	req.device_id = n->device_id;
	req.file_id = 0;
	req.desired_access = desired_access;   /* 0 = worker read defaults */
	req.disposition = FILE_OPEN;
	req.options = 0;
	req.info_class = 0;
	req.length = 0;
	req.payload_len = (uint32_t)plen;
	req.offset = 0;
	if (f_out != NULL)
		*f_out = f;
	return fd->send_fs_req(fd, &req, path, plen);
}

static int
fd_send_open(struct fuse_drive *fd, struct fd_node *n, uint64_t unique,
		uint32_t op_tag)
{
	return fd_send_open_ex(fd, n, unique, op_tag, 0, NULL);
}

/*
 * Send a QUERY_INFO for one FileInformation class on the node's open
 * handle.  Carries the chain phase and the accumulator so the completion
 * can decode into it and advance the chain.
 */
static int
fd_send_query(struct fuse_drive *fd, struct fd_node *n, uint64_t unique,
		uint32_t info_class, enum fd_phase phase,
		const struct fd_attr_acc *acc, uint32_t reply_op)
{
	struct rdp_be_fs_req req;
	struct fd_inflight *f;
	struct fd_attr_acc snap;

	if (!n->have_open)
		return -1;
	/* Snapshot the incoming accumulator first: the caller often passes
	 * &slot->acc of the slot it just freed, which fd_inflight_alloc may
	 * reuse and memset, so reading it after the alloc would lose data. */
	if (acc != NULL)
		snap = *acc;
	else
		memset(&snap, 0, sizeof snap);
	f = fd_inflight_alloc(fd, RDP_FS_QUERY_INFO, unique, n->nodeid,
		&req.req_id);
	if (f == NULL)
		return -1;
	f->phase = phase;
	f->reply_op = reply_op;
	f->acc = snap;
	req.op = RDP_FS_QUERY_INFO;
	req.device_id = n->device_id;
	req.file_id = n->file_id;
	req.desired_access = 0;
	req.disposition = 0;
	req.options = 0;
	req.info_class = info_class;
	req.length = 0;
	req.payload_len = 0;
	req.offset = 0;
	return fd->send_fs_req(fd, &req, NULL, 0);
}

/*
 * Send a SET_INFO with a verbatim FSCC SetBuffer on the node's open
 * handle.  op_tag is the private tag identifying the FUSE op being
 * served (RDP_FS_SET_INFO when fire-and-forget, RDP_FS_SETATTR_TAG when
 * its reply must finish a setattr).  The new in-flight slot is returned
 * via *f_out (never NULL on success) so a caller chaining a combined
 * size+time setattr can stash phase/time_set state on it.
 */
static int
fd_send_set_info(struct fuse_drive *fd, struct fd_node *n, uint64_t unique,
		uint32_t info_class, uint32_t op_tag,
		const uint8_t *buf, size_t buf_len, struct fd_inflight **f_out)
{
	struct rdp_be_fs_req req;
	struct fd_inflight *f;

	if (!n->have_open)
		return -1;
	f = fd_inflight_alloc(fd, op_tag, unique, n->nodeid, &req.req_id);
	if (f == NULL)
		return -1;
	if (f_out != NULL)
		*f_out = f;
	req.op = RDP_FS_SET_INFO;
	req.device_id = n->device_id;
	req.file_id = n->file_id;
	req.desired_access = 0;
	req.disposition = 0;
	req.options = 0;
	req.info_class = info_class;
	req.length = 0;
	req.payload_len = (uint32_t)buf_len;
	req.offset = 0;
	return fd->send_fs_req(fd, &req, buf, buf_len);
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

/*
 * Send a WRITE of `size` bytes from data at the given offset on the
 * node's open handle.  The number of bytes requested is stashed in
 * read_size so the completion can report a short write honestly.
 */
static int
fd_send_write(struct fuse_drive *fd, struct fd_node *n, uint64_t unique,
		uint64_t offset, const uint8_t *data, uint32_t size)
{
	struct rdp_be_fs_req req;
	struct fd_inflight *f;

	if (!n->have_open)
		return -1;
	f = fd_inflight_alloc(fd, RDP_FS_WRITE, unique, n->nodeid, &req.req_id);
	if (f == NULL)
		return -1;
	f->read_size = size;
	req.op = RDP_FS_WRITE;
	req.device_id = n->device_id;
	req.file_id = n->file_id;
	req.desired_access = 0;
	req.disposition = 0;
	req.options = 0;
	req.info_class = 0;
	req.length = size;
	req.payload_len = size;
	req.offset = offset;
	return fd->send_fs_req(fd, &req, data, size);
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
	n->access = 0;
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

/*
 * A node is synthetic when it has no RDPDR path to query: the mount root
 * and the per-drive top-level directories.  Those answer attr requests
 * with a fabricated dir attr; everything else is a real client path.
 */
static int
fd_node_synthetic(const struct fd_node *n)
{
	return n->nodeid == FUSE_ROOT_ID || n->is_drive;
}

/*
 * Start (or continue) the real-metadata getattr chain for a node.  The
 * chain is: optionally OPEN the node read-access if no handle is held,
 * then QUERY_INFO(FileStandardInformation), then
 * QUERY_INFO(FileBasicInformation), then reply with the decoded attr.
 * reply_op selects the final reply form: FUSE_LOOKUP yields a
 * fuse_entry_out, anything else a fuse_attr_out.  Returns 0 if the chain
 * was started (no FUSE reply written yet), or non-zero on a setup failure
 * (the caller then replies, typically with a synthetic fallback attr).
 */
static int
fd_start_getattr(struct fuse_drive *fd, struct fd_node *n, uint64_t unique,
		uint32_t reply_op)
{
	struct fd_attr_acc acc;

	memset(&acc, 0, sizeof acc);
	acc.is_dir = n->is_dir;
	if (!n->have_open) {
		/* Open read-access first; the OPEN completion starts the query
		 * chain.  The reply form and accumulator ride on the slot. */
		struct fd_inflight *f = NULL;
		if (fd_send_open_ex(fd, n, unique, RDP_FS_GETATTR_TAG,
		    FILE_READ_DATA, &f) != 0 || f == NULL)
			return -1;
		f->phase = PHASE_GETATTR_OPEN;
		f->reply_op = reply_op;
		f->acc = acc;
		return 0;
	}
	return fd_send_query(fd, n, unique, FileStandardInformation,
		PHASE_GETATTR_STD, &acc, reply_op) == 0 ? 0 : -1;
}

static void
fd_op_getattr(struct fuse_drive *fd, const struct fuse_in_header *ih)
{
	struct fd_node *n = fd_node_find(fd, ih->nodeid);
	if (n == NULL) {
		fd_reply_error(fd, ih->unique, -ENOENT);
		return;
	}
	/* Synthetic directories (root, per-drive roots) answer immediately
	 * with a fabricated dir attr.  A real path runs a QUERY_INFO chain
	 * for true size and times; on any failure the chain falls back to the
	 * synthetic attr so the kernel is never left waiting. */
	if (fd_node_synthetic(n)) {
		fd_reply_attr(fd, ih->unique, n);
		return;
	}
	if (fd_start_getattr(fd, n, ih->unique, FUSE_GETATTR) != 0) {
		/* Could not start the chain (no slot / path too long): fall
		 * back to the synthetic attr rather than hang the kernel. */
		fd_reply_attr(fd, ih->unique, n);
	}
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

	/* Below a drive: create-or-find the child, then probe it with the
	 * getattr chain.  Its OPEN establishes existence and the dir/file
	 * split, and the QUERY_INFO steps fill in real size and times before
	 * the fuse_entry_out is sent. */
	child = fd_child_make(fd, parent->nodeid, name, namelen,
		parent->device_id, 0);
	if (child == NULL) {
		fd_reply_error(fd, ih->unique, -ENOMEM);
		return;
	}
	/* The kernel re-LOOKUPs each entry once its validity timeout lapses.
	 * If we already hold an RDPDR handle for this node, reusing it avoids
	 * a second OPEN that would leak the prior client handle; the query
	 * chain still refreshes size and times over the held handle. */
	child->nlookup++;
	if (fd_start_getattr(fd, child, ih->unique, FUSE_LOOKUP) != 0) {
		/* Could not start the chain: fall back to the synthetic entry
		 * so the kernel still sees the node.  When the node has no open
		 * handle this also drops the speculative lookup count. */
		if (!child->have_open && child->nlookup > 0)
			child->nlookup--;
		fd_reply_entry(fd, ih->unique, child);
	}
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
		/* Reuse the held handle for this OPENDIR fd; count it so its
		 * RELEASEDIR does not close the handle out from under another
		 * still-open fd of the same node. */
		n->open_refs++;
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

/* Map the open(2) access mode from fuse_open_in.flags to an NT
 * DesiredAccess.  O_RDONLY grants read, O_WRONLY write, O_RDWR both. */
static uint32_t
fd_access_from_oflags(uint32_t oflags)
{
	switch (oflags & O_ACCMODE) {
	case O_WRONLY:
		return FILE_WRITE_DATA;
	case O_RDWR:
		return FILE_READ_DATA | FILE_WRITE_DATA;
	case O_RDONLY:
	default:
		return FILE_READ_DATA;
	}
}

static void
fd_op_open(struct fuse_drive *fd, const struct fuse_in_header *ih,
		const uint8_t *body, size_t body_len)
{
	struct fd_node *n = fd_node_find(fd, ih->nodeid);
	struct fuse_open_in oi;
	struct fuse_open_out out;
	uint32_t want;

	if (n == NULL) {
		fd_reply_error(fd, ih->unique, -ENOENT);
		return;
	}
	if (n->is_dir) {
		fd_reply_error(fd, ih->unique, -EISDIR);
		return;
	}
	memset(&oi, 0, sizeof oi);
	if (body_len >= sizeof oi)
		memcpy(&oi, body, sizeof oi);
	want = fd_access_from_oflags(oi.flags);

	/*
	 * Reopen-on-upgrade.  A held handle is reused only when it already
	 * grants every bit the new open needs; otherwise we close it and
	 * reopen with the union of the old and new access so a later read
	 * over a write-opened handle still works.  This keeps one handle per
	 * node (KISS) at the cost of a close/open when the access widens.
	 */
	if (n->have_open && (n->access & want) == want) {
		/* The held handle already covers this open; hand it to the
		 * kernel and count the extra fd so a later RELEASE does not
		 * tear the shared handle down while another fd is still open. */
		n->open_refs++;
		memset(&out, 0, sizeof out);
		out.fh = ih->nodeid;
		out.open_flags = FOPEN_DIRECT_IO;
		fd_reply_ok(fd, ih->unique, &out, sizeof out);
		return;
	}
	if (n->have_open) {
		/* Access upgrade: close and reopen with the union of the old
		 * and new access.  This replaces the same logical handle, so
		 * the reopen completion must not add a second ref; remember the
		 * current count and restore it once the new handle is granted. */
		want |= n->access;
		fd_send_close(fd, n);
	}
	if (fd_send_open_ex(fd, n, ih->unique, RDP_FS_OPENFILE_TAG, want,
	    NULL) != 0)
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
fd_op_write(struct fuse_drive *fd, const struct fuse_in_header *ih,
		const uint8_t *body, size_t body_len)
{
	struct fuse_write_in wi;
	struct fd_node *n = fd_node_find(fd, ih->nodeid);
	const uint8_t *data;
	uint32_t size;

	if (n == NULL || n->is_dir || !n->have_open) {
		fd_reply_error(fd, ih->unique, -EBADF);
		return;
	}
	if ((n->access & FILE_WRITE_DATA) == 0) {
		/* The handle was opened read-only; the kernel should not write
		 * to it, but reject rather than corrupt. */
		fd_reply_error(fd, ih->unique, -EBADF);
		return;
	}
	if (body_len < sizeof wi) {
		fd_reply_error(fd, ih->unique, -EINVAL);
		return;
	}
	memcpy(&wi, body, sizeof wi);
	size = wi.size;
	/* The write data follows the fixed fuse_write_in.  Never read past
	 * the bytes the kernel actually delivered in this request. */
	if (size > body_len - sizeof wi)
		size = (uint32_t)(body_len - sizeof wi);
	if (size > FD_MAX_WRITE)
		size = FD_MAX_WRITE;
	data = body + sizeof wi;
	if (fd_send_write(fd, n, ih->unique, wi.offset, data, size) != 0)
		fd_reply_error(fd, ih->unique, -ENOMEM);
}

/* Build a FileEndOfFileInformation SetBuffer (8 bytes) for a truncate. */
static void
fd_build_eof_info(uint8_t buf[FSCC_EOF_INFO_LEN], uint64_t new_size)
{
	fd_st64(buf, new_size);
}

/*
 * Build a FileBasicInformation SetBuffer (36 bytes) that sets only the
 * timestamps the caller asks for.  A FILETIME of 0 leaves that field
 * unchanged on the remote; FileAttributes 0 likewise leaves attributes
 * untouched.  set_atime/set_mtime select which times are written.
 */
static void
fd_build_basic_info(uint8_t buf[FSCC_BASIC_INFO_LEN],
		int set_atime, uint64_t atime_ft,
		int set_mtime, uint64_t mtime_ft)
{
	memset(buf, 0, FSCC_BASIC_INFO_LEN);
	/* +0 CreationTime, +8 LastAccessTime, +16 LastWriteTime,
	 * +24 ChangeTime, +32 FileAttributes; all left 0 unless set. */
	if (set_atime)
		fd_st64(buf + 8, atime_ft);
	if (set_mtime)
		fd_st64(buf + 16, mtime_ft);
}

/*
 * Resolve the requested atime/mtime from a fuse_setattr_in into FILETIME
 * values (ATIME_NOW/MTIME_NOW become the current wall-clock time).  The
 * unix seconds are mirrored into acc so a fallback reply still reflects
 * what was asked.  Only FATTR_ATIME/FATTR_MTIME bits select a field.
 */
static void
fd_resolve_time_set(const struct fuse_setattr_in *si, struct fd_time_set *ts,
		struct fd_attr_acc *acc)
{
	uint64_t now = (uint64_t)time(NULL);

	memset(ts, 0, sizeof *ts);
	ts->set_atime = (si->valid & FATTR_ATIME) != 0;
	ts->set_mtime = (si->valid & FATTR_MTIME) != 0;
	if (ts->set_atime) {
		uint64_t sec = (si->valid & FATTR_ATIME_NOW) ? now : si->atime;
		uint32_t nsec = (si->valid & FATTR_ATIME_NOW) ? 0u : si->atimensec;
		ts->atime_ft = fd_unix_to_filetime(sec, nsec);
		acc->atime = sec;
	}
	if (ts->set_mtime) {
		uint64_t sec = (si->valid & FATTR_MTIME_NOW) ? now : si->mtime;
		uint32_t nsec = (si->valid & FATTR_MTIME_NOW) ? 0u : si->mtimensec;
		ts->mtime_ft = fd_unix_to_filetime(sec, nsec);
		acc->mtime = sec;
	}
}

/*
 * Send a FileBasicInformation set carrying the resolved time_set, tagged
 * RDP_FS_SETATTR_TAG so its completion runs the single post-set re-query.
 * Returns 0 if the set was sent, non-zero on a setup failure.
 */
static int
fd_send_time_set(struct fuse_drive *fd, struct fd_node *n, uint64_t unique,
		const struct fd_time_set *ts, const struct fd_attr_acc *acc)
{
	uint8_t basic[FSCC_BASIC_INFO_LEN];
	struct fd_inflight *f = NULL;

	fd_build_basic_info(basic, ts->set_atime, ts->atime_ft,
		ts->set_mtime, ts->mtime_ft);
	if (fd_send_set_info(fd, n, unique, FileBasicInformation,
	    RDP_FS_SETATTR_TAG, basic, sizeof basic, &f) != 0 || f == NULL)
		return -1;
	f->acc = *acc;
	return 0;
}

static void
fd_op_setattr(struct fuse_drive *fd, const struct fuse_in_header *ih,
		const uint8_t *body, size_t body_len)
{
	struct fuse_setattr_in si;
	struct fd_node *n = fd_node_find(fd, ih->nodeid);
	struct fd_attr_acc acc;
	int want_time;

	if (n == NULL) {
		fd_reply_error(fd, ih->unique, -ENOENT);
		return;
	}
	if (body_len < sizeof si) {
		fd_reply_error(fd, ih->unique, -EINVAL);
		return;
	}
	memcpy(&si, body, sizeof si);

	/* A SETATTR needs an open handle to carry the SET_INFO.  Without one
	 * we cannot honour size/time changes; report success on the parts we
	 * can synthesize so an editor's save does not see a spurious error.
	 * Known limitation: timestamp/size sets require the node to already
	 * be open (the kernel opens before truncating on the common path). */
	if (!n->have_open) {
		memset(&acc, 0, sizeof acc);
		acc.is_dir = n->is_dir;
		acc.size = si.valid & FATTR_SIZE ? si.size : 0;
		fd_reply_attr_acc(fd, ih->unique, n, &acc);
		return;
	}

	/* Seed the accumulator from the request so a fallback reply (when the
	 * post-set re-query cannot be started) still reflects what we set. */
	memset(&acc, 0, sizeof acc);
	acc.is_dir = n->is_dir;
	want_time = (si.valid & (FATTR_ATIME | FATTR_MTIME)) != 0;

	if (si.valid & FATTR_SIZE) {
		/* Truncate or extend.  Handles the O_TRUNC-on-save case where
		 * the new size is 0. */
		uint8_t eof[FSCC_EOF_INFO_LEN];
		struct fd_inflight *f = NULL;
		acc.size = si.size;
		fd_build_eof_info(eof, si.size);

		if (want_time) {
			/* Combined size + time set (a common save sequence).  The
			 * sets are async and must yield exactly one fuse reply, so
			 * send the EOF set first, tagged with the intermediate
			 * phase; resolve and stash the time set on the slot so the
			 * EOF completion can issue it after the original
			 * fuse_setattr_in is gone. */
			struct fd_time_set ts;
			fd_resolve_time_set(&si, &ts, &acc);
			if (fd_send_set_info(fd, n, ih->unique,
			    FileEndOfFileInformation, RDP_FS_SETATTR_TAG,
			    eof, sizeof eof, &f) != 0 || f == NULL) {
				fd_reply_attr_acc(fd, ih->unique, n, &acc);
				return;
			}
			f->phase = PHASE_SETATTR_EOF_THEN_TIME;
			f->acc = acc;
			f->time_set = ts;
			return;
		}

		/* Size only: the EOF completion runs the single re-query. */
		if (fd_send_set_info(fd, n, ih->unique, FileEndOfFileInformation,
		    RDP_FS_SETATTR_TAG, eof, sizeof eof, &f) != 0)
			fd_reply_attr_acc(fd, ih->unique, n, &acc);
		return;
	}

	if (want_time) {
		/* Time only.  ATIME_NOW/MTIME_NOW request the current
		 * wall-clock time. */
		struct fd_time_set ts;
		fd_resolve_time_set(&si, &ts, &acc);
		if (fd_send_time_set(fd, n, ih->unique, &ts, &acc) != 0)
			fd_reply_attr_acc(fd, ih->unique, n, &acc);
		return;
	}

	/* Mode/uid/gid/etc: nothing to push to RDPDR.  Reply with a fresh
	 * attr via the getattr chain so the kernel sees current state. */
	if (fd_start_getattr(fd, n, ih->unique, FUSE_SETATTR) != 0)
		fd_reply_attr_acc(fd, ih->unique, n, &acc);
}

static void
fd_op_release(struct fuse_drive *fd, const struct fuse_in_header *ih)
{
	struct fd_node *n = fd_node_find(fd, ih->nodeid);
	/* One RDPDR handle is shared across every fd of a node, so close it
	 * only when the last fd releases.  Decrement the open count (guarding
	 * against underflow if a stray RELEASE arrives with none outstanding)
	 * and close only when it reaches zero. */
	if (n != NULL) {
		if (n->open_refs > 0)
			n->open_refs--;
		if (n->open_refs == 0)
			fd_send_close(fd, n);
	}
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
	case FUSE_SETATTR:
		fd_op_setattr(fd, &ih, body, body_len);
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
		fd_op_open(fd, &ih, body, body_len);
		break;
	case FUSE_READ:
		fd_op_read(fd, &ih, body, body_len);
		break;
	case FUSE_WRITE:
		fd_op_write(fd, &ih, body, body_len);
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

/*
 * Decode the 8-byte FILETIME at p into unix seconds on *sec_out.  The
 * caller has already bounded the buffer so the 8 bytes are present.  The
 * accumulator keeps second granularity; the sub-second remainder is not
 * carried into the reply.
 */
static void
fd_decode_filetime(const uint8_t *p, uint64_t *sec_out)
{
	uint32_t nsec;
	fd_filetime_to_unix(fd_ld64(p), sec_out, &nsec);
	(void)nsec;
}

/*
 * Emit the final getattr reply (entry for LOOKUP, attr otherwise) from
 * the accumulated attributes, then return.  Used at the end of the
 * QUERY_INFO chain and on any fallback within it.
 */
static void
fd_getattr_reply(struct fuse_drive *fd, struct fd_inflight *f,
		struct fd_node *n)
{
	if (f->reply_op == FUSE_LOOKUP)
		fd_reply_entry_acc(fd, f->fuse_unique, n, &f->acc);
	else
		fd_reply_attr_acc(fd, f->fuse_unique, n, &f->acc);
}

/*
 * QUERY_INFO completion driving the getattr chain.  payload is the
 * forwarded DR_QUERY_INFORMATION_RSP body: Length(u32) + FSCC buffer.
 * Every FSCC field is decoded only after bounding the buffer.  On any
 * failure (bad status, short buffer) the chain falls back to whatever has
 * been accumulated so far and replies, so the kernel never hangs.
 */
static void
fd_complete_query(struct fuse_drive *fd, struct fd_inflight *f, uint32_t status,
		const uint8_t *payload, size_t payload_len)
{
	struct fd_node *n = fd_node_find(fd, f->nodeid);
	const uint8_t *fscc;
	size_t avail;
	uint32_t fscc_len;

	if (n == NULL) {
		fd_reply_error(fd, f->fuse_unique, -ENOENT);
		return;
	}

	/* Bound the inner FSCC buffer against what we actually received. */
	fscc = NULL;
	avail = 0;
	if (status == STATUS_SUCCESS && payload_len >= 4) {
		fscc_len = fd_ld32(payload);
		fscc = payload + 4;
		avail = payload_len - 4;
		if (fscc_len < avail)
			avail = fscc_len;
	}

	if (f->phase == PHASE_GETATTR_STD) {
		/* FileStandardInformation (MS-FSCC 2.4.41): EndOfFile (+8) is
		 * the size, DeletePending sits at +20 and the Directory byte
		 * is at +21, which is the dir/file split.  On a short or
		 * failed reply keep the accumulator defaults and still chain
		 * to the basic query so times can be filled. */
		if (fscc != NULL && avail >= FSCC_STD_INFO_LEN) {
			f->acc.size = fd_ld64(fscc + 8);
			f->acc.is_dir = fscc[21] != 0;
		}
		/* Chain to FileBasicInformation, carrying the accumulator. */
		if (fd_send_query(fd, n, f->fuse_unique, FileBasicInformation,
		    PHASE_GETATTR_BASIC, &f->acc, f->reply_op) == 0)
			return;
		/* Could not chain: reply with what we have. */
		fd_getattr_reply(fd, f, n);
		return;
	}

	if (f->phase == PHASE_GETATTR_BASIC) {
		/* FileBasicInformation: CreationTime(+0), LastAccessTime(+8),
		 * LastWriteTime(+16), ChangeTime(+24), FileAttributes(+32). */
		if (fscc != NULL && avail >= FSCC_BASIC_INFO_LEN) {
			uint32_t attrs;
			fd_decode_filetime(fscc + 8, &f->acc.atime);
			fd_decode_filetime(fscc + 16, &f->acc.mtime);
			fd_decode_filetime(fscc + 24, &f->acc.ctime);
			/* ChangeTime may be 0; fall back to LastWriteTime. */
			if (f->acc.ctime == 0)
				f->acc.ctime = f->acc.mtime;
			attrs = fd_ld32(fscc + 32);
			f->acc.is_dir = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
			f->acc.readonly = (attrs & FILE_ATTRIBUTE_READONLY) != 0;
		}
		/* Sync the node's dir/file split with what the client says. */
		n->is_dir = f->acc.is_dir;
		fd_getattr_reply(fd, f, n);
		return;
	}

	/* Unexpected phase for a QUERY_INFO completion. */
	fd_reply_error(fd, f->fuse_unique, -EIO);
}

/* OPEN completion serving a LOOKUP getattr chain, a direct OPEN, an
 * OPENDIR, or a write-access (re)open.  file_id was pre-extracted by the
 * worker into rsp->file_id. */
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
		/* A failed probe drops a speculative LOOKUP node so a later
		 * LOOKUP can retry cleanly.  The getattr chain bumped nlookup
		 * before the open, so undo it here. */
		if ((f->op == RDP_FS_OPEN || f->op == RDP_FS_GETATTR_TAG)
		    && f->reply_op == FUSE_LOOKUP && !n->is_drive) {
			if (n->nlookup > 0)
				n->nlookup--;
			if (n->nlookup == 0)
				n->in_use = 0;
		}
		fd_reply_error(fd, f->fuse_unique, -fd_status_to_errno(status));
		return;
	}
	n->file_id = file_id;
	n->have_open = 1;
	/* Record the access actually requested (0 means the worker used its
	 * read default, which grants read). */
	n->access = f->req_access != 0 ? f->req_access : FILE_READ_DATA;

	switch (f->op) {
	case RDP_FS_GETATTR_TAG:
		/* Opened to drive a getattr chain (from LOOKUP or GETATTR):
		 * start the FileStandardInformation query.  On a setup failure
		 * fall back to the synthetic attr. */
		if (fd_send_query(fd, n, f->fuse_unique, FileStandardInformation,
		    PHASE_GETATTR_STD, &f->acc, f->reply_op) != 0)
			fd_getattr_reply(fd, f, n);
		break;
	case RDP_FS_OPEN:
		/* Legacy LOOKUP probe path: report the entry with whatever
		 * LOOKUP guessed.  The handle stays open for a following OPEN. */
		n->nlookup++;
		fd_reply_entry(fd, f->fuse_unique, n);
		break;
	case RDP_FS_OPENFILE_TAG:   /* a direct FUSE_OPEN of a regular file */
		/* A real open or access upgrade grants this kernel fd the
		 * handle.  On an upgrade fd_send_close left open_refs holding
		 * the still-open fds, so this single bump counts only the new
		 * FUSE_OPEN and never double-counts the upgrade. */
		n->open_refs++;
		memset(&out, 0, sizeof out);
		out.fh = n->nodeid;
		out.open_flags = FOPEN_DIRECT_IO;
		fd_reply_ok(fd, f->fuse_unique, &out, sizeof out);
		break;
	case RDP_FS_OPENDIR_TAG:
		/* FUSE_OPENDIR grants this kernel fd the handle; count it so the
		 * matching RELEASEDIR (routed through fd_op_release) only closes
		 * once every dir fd is gone. */
		n->open_refs++;
		memset(&out, 0, sizeof out);
		out.fh = n->nodeid;
		fd_reply_ok(fd, f->fuse_unique, &out, sizeof out);
		break;
	default:
		fd_reply_error(fd, f->fuse_unique, -EIO);
		break;
	}
}

/*
 * WRITE completion.  payload is the forwarded DR_WRITE_RSP body, which
 * starts with Length(u32) = bytes written.  When that field is present we
 * trust it (bounded against the bytes the kernel asked to write); else we
 * fall back to rsp.length.  A short write is reported honestly so the
 * kernel re-issues the remainder. */
static void
fd_complete_write(struct fuse_drive *fd, struct fd_inflight *f, uint32_t status,
		uint32_t rsp_length, const uint8_t *payload, size_t payload_len)
{
	struct fuse_write_out out;
	uint32_t written;

	if (status != STATUS_SUCCESS) {
		fd_reply_error(fd, f->fuse_unique, -fd_status_to_errno(status));
		return;
	}
	if (payload_len >= 4)
		written = fd_ld32(payload);
	else
		written = rsp_length;
	if (written > f->read_size)
		written = f->read_size;   /* never claim more than requested */

	memset(&out, 0, sizeof out);
	out.size = written;
	fd_reply_ok(fd, f->fuse_unique, &out, sizeof out);
}

/*
 * SET_INFO completion.  When the op tag is RDP_FS_SETATTR_TAG the reply
 * must finish a FUSE_SETATTR with a fresh attr; we re-run the getattr
 * chain over the open handle for accuracy.  On a query setup failure (or
 * a set failure) we fall back to the accumulated/synthetic attr.  A plain
 * RDP_FS_SET_INFO tag is fire-and-forget (no FUSE reply expected).
 *
 * For a combined size+time setattr the first completion carries phase
 * PHASE_SETATTR_EOF_THEN_TIME: the EOF set succeeded, so issue the saved
 * FileBasicInformation set next (tagged setattr-final) and reply only once
 * that second set completes.  This keeps exactly one fuse reply per op. */
static void
fd_complete_set_info(struct fuse_drive *fd, struct fd_inflight *f,
		uint32_t status)
{
	struct fd_node *n = fd_node_find(fd, f->nodeid);
	struct fd_attr_acc acc;
	struct fd_time_set ts;
	uint64_t unique;

	if (f->op != RDP_FS_SETATTR_TAG)
		return;   /* fire-and-forget set: nothing to reply */
	if (n == NULL) {
		fd_reply_error(fd, f->fuse_unique, -ENOENT);
		return;
	}
	if (status != STATUS_SUCCESS) {
		fd_reply_error(fd, f->fuse_unique, -fd_status_to_errno(status));
		return;
	}

	/* Snapshot the slot state before issuing a follow-up send: the slot
	 * is already free and fd_inflight_alloc may reuse and memset it. */
	acc = f->acc;
	ts = f->time_set;
	unique = f->fuse_unique;

	if (f->phase == PHASE_SETATTR_EOF_THEN_TIME) {
		/* The EOF set landed; now push the saved time set.  Its
		 * completion (setattr-final, no phase) runs the single
		 * re-query and emits the one fuse reply.  A setattr always
		 * replies with an attr, so on a setup failure fall back to the
		 * accumulated attr so the kernel still gets exactly one reply. */
		if (fd_send_time_set(fd, n, unique, &ts, &acc) != 0)
			fd_reply_attr_acc(fd, unique, n, &acc);
		return;
	}

	/* Re-query for the authoritative post-set attr.  On a setup failure
	 * reply with whatever the accumulator holds.  Use the snapshot since
	 * fd_send_query may already have reused this slot. */
	if (fd_send_query(fd, n, unique, FileStandardInformation,
	    PHASE_GETATTR_STD, &acc, FUSE_SETATTR) != 0)
		fd_reply_attr_acc(fd, unique, n, &acc);
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
	case RDP_FS_GETATTR_TAG:
		fd_complete_open(fd, f, rsp->status, rsp->file_id);
		break;
	case RDP_FS_READ:
		fd_complete_read(fd, f, rsp->status, payload, payload_len);
		break;
	case RDP_FS_WRITE:
		fd_complete_write(fd, f, rsp->status, rsp->length,
			payload, payload_len);
		break;
	case RDP_FS_LIST:
		fd_complete_list(fd, f, rsp->status, payload, payload_len);
		break;
	case RDP_FS_QUERY_INFO:
		fd_complete_query(fd, f, rsp->status, payload, payload_len);
		break;
	case RDP_FS_SET_INFO:
	case RDP_FS_SETATTR_TAG:
		fd_complete_set_info(fd, f, rsp->status);
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
uint32_t fuse_drive_test_req_info_class(void);
uint32_t fuse_drive_test_req_access(void);
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
uint32_t fuse_drive_test_req_info_class(void)
	{ return fd_test_cap.req.info_class; }
uint32_t fuse_drive_test_req_access(void)
	{ return fd_test_cap.req.desired_access; }

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
