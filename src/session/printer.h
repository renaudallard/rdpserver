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
 * printer.h -- session side of RDP printer redirection (MS-RDPEPC).
 *
 * Owned and driven by rdp_session.c.  Each client redirected printer is
 * exposed inside the session as a RAW CUPS queue whose device URI points
 * at a per session AF_UNIX socket served by this module.  A small custom
 * CUPS backend (rdp-cups-backend) connects to that socket and forwards the
 * job spool; this module reads it and relays it to the worker as one
 * RDP_BE_PRINT_JOB message.
 *
 * The whole feature is best effort: any CUPS or lpadmin failure is logged
 * and skipped so a missing or broken cupsd never breaks a normal session.
 *
 * Wire framing on the print socket (rdp-cups-backend -> session), one job
 * per connection, all little endian:
 *
 *   u32 device_id      the RDP device id from the queue's device URI
 *   u32 spool_len      spool byte count, bounded at RDP_PRINTER_MAX_SPOOL
 *   bytes spool        spool_len bytes
 *
 * The backend writes the header and the bytes then half closes; the
 * session reads to EOF.  Spool larger than the cap is truncated by the
 * backend (it stops at the cap) and the session forwards what it gets.
 */

#ifndef RDP_PRINTER_H
#define RDP_PRINTER_H

#include <sys/types.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>

#include "../backend/proto.h"

/* Fixed header sent by rdp-cups-backend at the start of each connection,
 * shared with cups_backend.c so the two stay in lockstep. */
struct rdp_print_wire_hdr {
	uint32_t device_id;
	uint32_t spool_len;
};

/* Upper bound on the spool the session reads from one backend connection
 * and forwards to the worker; matches the worker's PRINT_JOB ceiling. */
#define RDP_PRINTER_MAX_SPOOL RDP_BE_PRINT_JOB_MAX_SPOOL

/* Maximum number of redirected printers tracked at once.  Each maps to one
 * CUPS queue; clients rarely redirect more than a handful. */
#define RDP_PRINTER_MAX_QUEUES 32

/* Maximum backend connections serviced concurrently.  CUPS runs one backend
 * process per job, so a small set is plenty. */
#define RDP_PRINTER_MAX_CONNS 8

struct rdp_printer_queue {
	uint32_t device_id;
	char     queue[64];   /* sanitized CUPS queue name, "rdp-..." */
	int      used;
};

struct rdp_printer_conn {
	int      fd;          /* accepted backend connection, -1 if free */
	struct rdp_print_wire_hdr hdr;
	size_t   hdr_got;     /* header bytes read so far */
	uint8_t *spool;       /* spool buffer, malloc'd once header is in */
	size_t   spool_got;   /* spool bytes read so far */
};

struct rdp_printer {
	int      be_fd;       /* backend socket to the worker */
	int      listen_fd;   /* AF_UNIX listener, -1 if disabled */
	char     sock_path[108];
	int      lpadmin_ok;  /* 1 if lpadmin is usable */
	/* Peer uids allowed to connect to the (world-addressable) socket: the
	 * session user, root, and the CUPS backend account, so a different
	 * local user cannot inject a print job by connecting directly. */
	uid_t    allow_uids[4];
	int      n_allow;
	char     user[64];    /* session user name, for the queue submit ACL */
	struct rdp_printer_queue queues[RDP_PRINTER_MAX_QUEUES];
	struct rdp_printer_conn  conns[RDP_PRINTER_MAX_CONNS];
};

/* Initialize the printer module: create the per session print socket and
 * probe for lpadmin.  Returns 0 on success (the socket is listening) or -1
 * if the socket could not be created, in which case the module is inert and
 * rdp_printer_close is still safe to call.  Never fails the session. */
int rdp_printer_init(struct rdp_printer *p, int be_fd);

/* Handle a RDP_BE_PRINTER_DEVICE announce: create (or, if already present,
 * leave) the matching CUPS queue.  buf/len is the raw backend payload. */
void rdp_printer_handle_device(struct rdp_printer *p, const uint8_t *buf,
    size_t len);

/* Number of fds this module wants in the poll set (listener plus active
 * connections), and a fill helper that appends them to pfd starting at
 * index *n (bounded by cap).  Service runs the returned events. */
int rdp_printer_fill_pollfds(struct rdp_printer *p, struct pollfd *pfd,
    int *n, int cap);

/* Service the listener and connection fds after poll returns.  Accepts new
 * backend connections and reads ready ones; a completed job is forwarded to
 * the worker as RDP_BE_PRINT_JOB.  Non-blocking; never stalls the loop. */
void rdp_printer_service(struct rdp_printer *p, struct pollfd *pfd, int n);

/* Tear down: remove every created CUPS queue, close all connections, close
 * and unlink the socket, free buffers.  Safe to call on a zeroed or
 * partially initialized struct. */
void rdp_printer_close(struct rdp_printer *p);

/* Exposed for unit testing: sanitize a raw printer name into a CUPS queue
 * name in out[outsz] ("rdp-" prefix, alphanumeric/dash/underscore body).
 * Returns 0 on success, -1 if out is too small. */
int rdp_printer_sanitize(const char *name, char *out, size_t outsz);

#endif /* RDP_PRINTER_H */
