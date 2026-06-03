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
 * cups_backend.c -- standalone CUPS backend "rdp".
 *
 * Installed as /usr/lib/cups/backend/rdp (mode 0755, root owned).  The
 * system cupsd invokes it two ways:
 *
 *   discovery: no arguments.  Print one device line and exit 0.
 *   print:     argv[1..5] = job-id user title copies options, and an
 *              optional argv[6] = spool file name.  The spool is read from
 *              argv[6] if present, else from stdin.  The target is taken
 *              from the DEVICE_URI environment variable, which cupsd sets
 *              from the queue's device-uri: rdp://PATH?dev=ID where PATH is
 *              the session's AF_UNIX print socket and ID is the RDP device
 *              id.  We connect to PATH, send the fixed header
 *              {u32 device_id; u32 spool_len} then the spool bytes, and
 *              exit 0 on success.
 *
 * The spool forwarded is bounded at 4 MiB to match the session/worker cap;
 * a larger job forwards its first 4 MiB and stops.  This binary is
 * deliberately tiny and dependency free (no libcups): it parses argv and
 * the environment and does blocking socket I/O.
 */

#define _GNU_SOURCE

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* CUPS backend exit codes (subset; values from cups/backend.h). */
#define CUPS_BACKEND_OK     0
#define CUPS_BACKEND_FAILED 1

/* Spool cap; must match RDP_BE_PRINT_JOB_MAX_SPOOL in the session/worker. */
#define RDP_PRINT_MAX_SPOOL (4u * 1024u * 1024u)

struct wire_hdr {
	uint32_t device_id;
	uint32_t spool_len;
};

/* Write exactly n bytes, restarting on EINTR.  Returns 0 on success. */
static int
write_full(int fd, const void *buf, size_t n)
{
	const uint8_t *p = buf;
	while (n > 0) {
		ssize_t w = write(fd, p, n);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (w == 0)
			return -1;
		p += (size_t)w;
		n -= (size_t)w;
	}
	return 0;
}

/*
 * Parse a DEVICE_URI of the form rdp://<path>?dev=<id> into the socket path
 * (copied into out[outsz]) and the device id.  Returns 0 on success.
 */
static int
parse_uri(const char *uri, char *out, size_t outsz, uint32_t *dev_out)
{
	const char *p, *q;
	unsigned long dev;
	char *end;
	size_t plen;

	if (uri == NULL)
		return -1;
	if (strncmp(uri, "rdp://", 6) != 0)
		return -1;
	p = uri + 6;
	q = strstr(p, "?dev=");
	if (q == NULL)
		return -1;
	plen = (size_t)(q - p);
	if (plen == 0 || plen >= outsz)
		return -1;
	memcpy(out, p, plen);
	out[plen] = '\0';

	errno = 0;
	dev = strtoul(q + 5, &end, 10);
	if (errno != 0 || end == q + 5 || dev > UINT32_MAX)
		return -1;
	/* Trailing characters after the number are not expected. */
	if (*end != '\0')
		return -1;
	*dev_out = (uint32_t)dev;
	return 0;
}

/*
 * Read the whole spool (from fd) into a malloc'd buffer, bounded at the cap.
 * On reaching the cap we stop reading and forward the first cap bytes.
 * Returns the buffer (caller frees) and stores its length in *len_out, or
 * NULL on allocation/read error.
 */
static uint8_t *
slurp_spool(int fd, size_t *len_out)
{
	size_t cap = 65536;
	size_t len = 0;
	uint8_t *buf = malloc(cap);

	if (buf == NULL)
		return NULL;
	for (;;) {
		ssize_t r;
		if (len == cap) {
			size_t ncap;
			uint8_t *nbuf;
			if (cap >= RDP_PRINT_MAX_SPOOL)
				break;   /* hit the ceiling; stop reading */
			ncap = cap * 2;
			if (ncap > RDP_PRINT_MAX_SPOOL)
				ncap = RDP_PRINT_MAX_SPOOL;
			nbuf = realloc(buf, ncap);
			if (nbuf == NULL) {
				free(buf);
				return NULL;
			}
			buf = nbuf;
			cap = ncap;
		}
		r = read(fd, buf + len, cap - len);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			free(buf);
			return NULL;
		}
		if (r == 0)
			break;
		len += (size_t)r;
	}
	*len_out = len;
	return buf;
}

int
main(int argc, char *argv[])
{
	const char *uri;
	char path[108];
	uint32_t device_id = 0;
	int spool_fd = STDIN_FILENO;
	int opened = 0;
	int sock = -1;
	uint8_t *spool = NULL;
	size_t spool_len = 0;
	struct wire_hdr hdr;
	struct sockaddr_un sa;
	int rc = CUPS_BACKEND_FAILED;

	/* Discovery mode: cupsd runs the backend with no arguments and reads
	 * one device line from stdout. */
	if (argc < 2) {
		puts("direct rdp \"Unknown\" \"RDP Printer Redirection\"");
		return CUPS_BACKEND_OK;
	}

	/* Print mode: argv[1]=job, [2]=user, [3]=title, [4]=copies,
	 * [5]=options, optional [6]=spool file. */
	uri = getenv("DEVICE_URI");
	if (parse_uri(uri, path, sizeof path, &device_id) != 0) {
		fprintf(stderr, "ERROR: rdp: bad or missing DEVICE_URI\n");
		return CUPS_BACKEND_FAILED;
	}

	if (argc > 6 && argv[6] != NULL && argv[6][0] != '\0') {
		spool_fd = open(argv[6], O_RDONLY);
		if (spool_fd < 0) {
			fprintf(stderr, "ERROR: rdp: open spool %s: %s\n",
			    argv[6], strerror(errno));
			return CUPS_BACKEND_FAILED;
		}
		opened = 1;
	}

	spool = slurp_spool(spool_fd, &spool_len);
	if (opened)
		(void)close(spool_fd);
	if (spool == NULL) {
		fprintf(stderr, "ERROR: rdp: reading spool: %s\n",
		    strerror(errno));
		return CUPS_BACKEND_FAILED;
	}

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf(stderr, "ERROR: rdp: socket: %s\n", strerror(errno));
		goto done;
	}
	memset(&sa, 0, sizeof sa);
	sa.sun_family = AF_UNIX;
	if (strlen(path) >= sizeof sa.sun_path) {
		fprintf(stderr, "ERROR: rdp: socket path too long\n");
		goto done;
	}
	memcpy(sa.sun_path, path, strlen(path));
	if (connect(sock, (struct sockaddr *)&sa, sizeof sa) != 0) {
		fprintf(stderr, "ERROR: rdp: connect %s: %s\n", path,
		    strerror(errno));
		goto done;
	}

	hdr.device_id = device_id;
	hdr.spool_len = (uint32_t)spool_len;
	if (write_full(sock, &hdr, sizeof hdr) != 0) {
		fprintf(stderr, "ERROR: rdp: writing header: %s\n",
		    strerror(errno));
		goto done;
	}
	if (spool_len > 0 && write_full(sock, spool, spool_len) != 0) {
		fprintf(stderr, "ERROR: rdp: writing spool: %s\n",
		    strerror(errno));
		goto done;
	}

	rc = CUPS_BACKEND_OK;

done:
	if (sock >= 0)
		(void)close(sock);
	free(spool);
	return rc;
}
