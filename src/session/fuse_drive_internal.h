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
 * fuse_drive_internal.h -- shared declarations between the protocol
 * agnostic core (fuse_drive.c) and the per OS wire backends
 * (fuse_drive_linux.c for raw /dev/fuse, fuse_drive_obsd.c for the
 * OpenBSD fusebuf protocol).
 *
 * The core owns the node table, the async in-flight model, the RDPDR
 * FS_REQ senders, the FSCC encode/decode, the NTSTATUS to errno mapping,
 * and the op/completion logic.  A backend owns its wire format only: it
 * parses one request into the OS neutral struct fd_request, and it turns
 * the core's OS neutral replies (struct fd_attr and the emit_* calls)
 * into the bytes its kernel expects.
 *
 * This header is included only by the implementation files (HAVE_FUSE or
 * HAVE_OBSD_FUSE gated); it never travels into a public API.
 */

#ifndef RDP_SESSION_FUSE_DRIVE_INTERNAL_H
#define RDP_SESSION_FUSE_DRIVE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "fuse_drive.h"
#include "../backend/proto.h"
#include "../channels/rdpdr.h"   /* RDPDR_MAX_PENDING */

/* Limits shared by the core and the backends. */
#define FD_MAX_NODES         512
#define FD_INFLIGHT_MAX      RDPDR_MAX_PENDING   /* 64 */
#define FD_NAME_MAX          255

/*
 * OS neutral op codes.  A backend->recv parses its wire request into one
 * of these; the core dispatches on it.  These are internal identifiers,
 * never sent on any wire.
 */
enum fd_op {
	FD_OP_NONE = 0,
	FD_OP_INIT,
	FD_OP_DESTROY,
	FD_OP_LOOKUP,
	FD_OP_GETATTR,
	FD_OP_SETATTR,
	FD_OP_OPEN,
	FD_OP_READ,
	FD_OP_WRITE,
	FD_OP_RELEASE,
	FD_OP_OPENDIR,
	FD_OP_READDIR,
	FD_OP_RELEASEDIR,
	FD_OP_CREATE,
	FD_OP_MKNOD,
	FD_OP_MKDIR,
	FD_OP_UNLINK,
	FD_OP_RMDIR,
	FD_OP_RENAME,
	FD_OP_FLUSH,
	FD_OP_FORGET
};

/*
 * OS neutral request descriptor.  A backend fills the fields its op uses
 * and leaves the rest zeroed; the core reads only the fields its op
 * dispatch path needs.  The name/data pointers alias the backend's own
 * receive buffer and stay valid for the duration of the synchronous
 * dispatch call only.
 */
struct fd_request {
	int      op;            /* enum fd_op */
	uint64_t unique;        /* request id used to correlate the reply */
	uint64_t nodeid;        /* node the op concerns */
	uint64_t fh;            /* open handle (carried by the kernel) */
	uint64_t offset;        /* READ/WRITE/READDIR byte offset */
	uint32_t size;          /* READ/WRITE/READDIR requested byte count */
	uint32_t flags;         /* OPEN/CREATE open(2) flags */
	uint32_t mode;          /* CREATE/MKNOD/MKDIR mode bits */
	uint32_t fattr_valid;   /* SETATTR: which fields below are set */

	/* name(s): LOOKUP/CREATE/MKNOD/MKDIR/UNLINK/RMDIR use name; RENAME
	 * uses name (old) and name2 (new). */
	const char *name;
	size_t      name_len;
	const char *name2;
	size_t      name2_len;

	/* WRITE data (aliases the backend receive buffer). */
	const uint8_t *data;
	uint32_t       data_len;

	/* SETATTR resolved fields (valid only when the matching fattr_valid
	 * bit is set). */
	uint64_t set_size;
	uint64_t set_atime;
	uint32_t set_atimensec;
	uint64_t set_mtime;
	uint32_t set_mtimensec;

	/* RENAME destination parent and the extra RENAME2 flags (rejected
	 * when non-zero). */
	uint64_t newdir;
	uint32_t rename_flags;

	/* FORGET lookup count. */
	uint64_t nlookup;
};

/* SETATTR fattr_valid bits (OS neutral; the backend maps its wire bits
 * onto these so the core never sees a Linux FATTR_* constant). */
#define FD_FATTR_SIZE   0x0001u
#define FD_FATTR_ATIME  0x0002u
#define FD_FATTR_MTIME  0x0004u

/* OS neutral file type bits carried in struct fd_attr.mode.  The backend
 * maps these onto its own S_IFDIR/S_IFREG when building the wire attr. */
#define FD_S_IFDIR  0x4000u
#define FD_S_IFREG  0x8000u
#define FD_S_IFMT   0xF000u

/*
 * OS neutral attributes the core hands an emitter.  The permission bits
 * in mode are POSIX and pass through unchanged; the type bits are the
 * FD_S_IF* above.  Times are unix seconds (0 means "no value").  The
 * emitter adds any OS specific fields (uid/gid/block size) itself.
 */
struct fd_attr {
	uint64_t ino;
	uint32_t mode;
	uint64_t size;
	uint64_t atime, mtime, ctime;
	uint32_t nlink;
};

/*
 * One decoded directory entry handed to emit_dirent_batch.  ino is the
 * node id the core assigned, name is its NUL terminated leaf, is_dir
 * splits file from directory.
 */
struct fd_dirent {
	uint64_t ino;
	const char *name;
	size_t      name_len;
	int         is_dir;
};

/*
 * Multi-step phase for an in-flight getattr/setattr/namespace chain.  A
 * GETATTR or LOOKUP on a real node walks PHASE_GETATTR_STD then
 * PHASE_GETATTR_BASIC, accumulating the decoded attributes between steps.
 * PHASE_NONE is a single-step op (OPEN/READ/LIST/WRITE/CLOSE/SET_INFO).
 */
enum fd_phase {
	PHASE_NONE = 0,
	PHASE_GETATTR_STD,    /* awaiting FileStandardInformation reply */
	PHASE_GETATTR_BASIC,  /* awaiting FileBasicInformation reply */
	PHASE_GETATTR_OPEN,   /* awaiting an OPEN before the query chain */
	PHASE_SETATTR_EOF_THEN_TIME, /* EOF set done -> issue the time set next */
	PHASE_UNLINK_OPEN,    /* delete: awaiting the OPEN(DELETE) */
	PHASE_UNLINK_SETDISP, /* delete: awaiting the FileDispositionInformation set */
	PHASE_RENAME_OPEN,    /* rename: awaiting the OPEN of the source */
	PHASE_RENAME_SET      /* rename: awaiting the FileRenameInformation set */
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
	uint32_t reply_op;     /* getattr chain: FD_OP_LOOKUP -> entry, else attr */
	enum fd_phase phase;   /* getattr/setattr chain step */
	struct fd_attr_acc acc;/* accumulated attrs for the getattr chain */
	struct fd_time_set time_set; /* pending time set for combined SETATTR */
	/* RENAME: the destination device-relative path (UTF-8) carried across
	 * the source OPEN completion, plus the destination parent nodeid so the
	 * source node can be re-parented once the rename lands. */
	char     target[1024];
	size_t   target_len;
	uint64_t target_parent;
};

struct fd_backend;

struct fuse_drive {
	int      fuse_fd;
	int      be_fd;
	uint32_t next_req_id;
	uint64_t next_nodeid;
	struct fd_node nodes[FD_MAX_NODES];
	struct fd_inflight inflight[FD_INFLIGHT_MAX];

	/* The wire backend selected at init.  Its recv parses one request
	 * into struct fd_request; its emit_* turn the core's OS neutral
	 * replies into wire bytes. */
	const struct fd_backend *backend;

	/* Reply / request sinks.  The live session writes to the fds; the
	 * regress harness substitutes in-memory capture sinks. */
	int (*send_fs_req)(struct fuse_drive *, const struct rdp_be_fs_req *,
		const void *payload, size_t payload_len);
	int (*write_reply)(struct fuse_drive *, const void *buf, size_t len);
	void *sink_ctx;
};

/*
 * Wire backend vtable.  recv parses one fully framed request from raw
 * (len bytes) into *req and returns 1 to ask the core to dispatch it, 0
 * when the backend already handled it (or there was nothing to dispatch).
 * The emit_* turn the core's OS neutral replies into wire bytes through
 * fd->write_reply.  emit_error takes the errno the way the OS expects it
 * (Linux uses a negative value in fuse_out_header.error).
 */
struct fd_backend {
	int  (*recv)(struct fuse_drive *fd, const uint8_t *raw, size_t len,
		struct fd_request *req);
	void (*emit_attr)(struct fuse_drive *fd, uint64_t unique,
		const struct fd_attr *a);
	void (*emit_entry)(struct fuse_drive *fd, uint64_t unique,
		uint64_t nodeid, const struct fd_attr *a);
	void (*emit_open)(struct fuse_drive *fd, uint64_t unique, uint64_t fh,
		int direct_io);
	void (*emit_create)(struct fuse_drive *fd, uint64_t unique,
		uint64_t nodeid, uint64_t fh, const struct fd_attr *a);
	void (*emit_read)(struct fuse_drive *fd, uint64_t unique,
		const uint8_t *data, uint32_t len);
	void (*emit_write)(struct fuse_drive *fd, uint64_t unique,
		uint32_t count);
	size_t (*emit_dirent_batch)(struct fuse_drive *fd, uint64_t unique,
		const struct fd_dirent *ents, size_t n, uint32_t maxbytes);
	void (*emit_ok)(struct fuse_drive *fd, uint64_t unique);
	void (*emit_error)(struct fuse_drive *fd, uint64_t unique, int error);
};

/* The Linux raw /dev/fuse backend (defined in fuse_drive_linux.c). */
#if HAVE_FUSE
extern const struct fd_backend fd_backend_linux;
#endif

/* node table (fuse_drive.c) */
struct fd_node *fd_node_find(struct fuse_drive *fd, uint64_t nodeid);
struct fd_node *fd_child_find(struct fuse_drive *fd, uint64_t parent,
		const char *name, size_t namelen);
struct fd_node *fd_child_make(struct fuse_drive *fd, uint64_t parent,
		const char *name, size_t namelen, uint32_t device_id, int is_dir);

/* Build a node's OS neutral attr (mode/nlink/size/times) from the node
 * and an optional accumulator.  The emitter adds any OS specific fields. */
void fd_node_to_attr(const struct fd_node *n, struct fd_attr *a,
		const struct fd_attr_acc *acc);

/* core dispatch and lifecycle (fuse_drive.c) */
void fd_dispatch(struct fuse_drive *fd, const struct fd_request *req);
void fd_common_init(struct fuse_drive *fd);

/* Drain and parse ready requests via the selected backend (backend file).
 * Returns 0 normally, -1 if the wire fd died. */
int fuse_drive_backend_process(struct fuse_drive *fd);

#endif /* RDP_SESSION_FUSE_DRIVE_INTERNAL_H */
