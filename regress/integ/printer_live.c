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
 * printer_live.c -- live end to end test of the session printer redirection
 * against a REAL cupsd.  NOT part of `make regress` (it needs CUPS, lpadmin,
 * lp, and the rdp-cups-backend installed in the cupsd backend dir).  Build
 * and drive it through regress/integ/printer_live.sh, which installs the
 * backend, runs this binary, and cleans up.
 *
 * It links printer.c with a tiny harness that plays both ends:
 *
 *   - A socketpair stands in for the session<->worker backend socket.
 *     sv[1] is the printer module's be_fd; sv[0] is the harness worker end.
 *   - The harness calls rdp_printer_init, then synthesizes a
 *     RDP_BE_PRINTER_DEVICE announce so the module creates a CUPS queue via
 *     the real lpadmin.
 *   - It forks `lp -d <queue> <file>`, then services the printer poll set in
 *     a loop while reading the worker end for the resulting RDP_BE_PRINT_JOB.
 *   - It checks the job's device id and that the spool the worker received
 *     contains the file's bytes (CUPS RAW queue passes them through).
 *   - It removes the queue and unlinks the socket on the way out.
 *
 * Exit 0 on success; nonzero (with a diagnostic) on any failure.
 */

#define _GNU_SOURCE

#include "../../src/session/printer.h"
#include "../../src/backend/proto.h"
#include "../../src/backend/proto_api.h"
#include "../../src/include/rdp_log.h"

#include <sys/socket.h>
#include <sys/wait.h>
#include <poll.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TEST_DEVICE_ID 4242u

static long
now_ms(void)
{
	struct timespec ts;
	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

int
main(int argc, char *argv[])
{
	struct rdp_log_cfg lc = { "printer_live", 1, RDP_LOG_INFO };
	struct rdp_printer printer;
	struct rdp_be_printer_device pd;
	int sv[2];
	const char *infile;
	uint8_t *want = NULL;
	size_t want_len = 0;
	char queue[64] = "";
	pid_t lp_pid;
	long deadline;
	int got_job = 0;
	int rc = 1;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <file-to-print>\n", argv[0]);
		return 2;
	}
	infile = argv[1];

	rdp_log_init(&lc);

	/* Load the file we expect to see arrive at the worker. */
	{
		FILE *f = fopen(infile, "rb");
		long sz;
		if (f == NULL) {
			fprintf(stderr, "open %s: %s\n", infile,
			    strerror(errno));
			return 2;
		}
		(void)fseek(f, 0, SEEK_END);
		sz = ftell(f);
		(void)fseek(f, 0, SEEK_SET);
		if (sz <= 0) {
			fprintf(stderr, "empty input file\n");
			(void)fclose(f);
			return 2;
		}
		want = malloc((size_t)sz);
		if (want == NULL || fread(want, 1, (size_t)sz, f)
		    != (size_t)sz) {
			fprintf(stderr, "read %s failed\n", infile);
			(void)fclose(f);
			free(want);
			return 2;
		}
		want_len = (size_t)sz;
		(void)fclose(f);
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		fprintf(stderr, "socketpair: %s\n", strerror(errno));
		free(want);
		return 2;
	}

	/* sv[1] is the module's backend fd to the worker; sv[0] is us. */
	if (rdp_printer_init(&printer, sv[1]) != 0) {
		fprintf(stderr, "rdp_printer_init failed\n");
		goto cleanup;
	}
	if (!printer.lpadmin_ok) {
		fprintf(stderr, "lpadmin not present; cannot run live test\n");
		goto cleanup;
	}

	/* Synthesize the printer announce and create the queue. */
	memset(&pd, 0, sizeof pd);
	pd.device_id = TEST_DEVICE_ID;
	pd.flags = RDP_BE_PRINTER_FLAG_DEFAULT;
	(void)snprintf(pd.name, sizeof pd.name, "Live Test Printer");
	(void)snprintf(pd.driver, sizeof pd.driver, "Generic / Text Only");
	rdp_printer_handle_device(&printer, (const uint8_t *)&pd, sizeof pd);

	/* Read back the queue name the module created. */
	{
		size_t i;
		for (i = 0; i < RDP_PRINTER_MAX_QUEUES; i++) {
			if (printer.queues[i].used
			    && printer.queues[i].device_id == TEST_DEVICE_ID) {
				(void)snprintf(queue, sizeof queue, "%s",
				    printer.queues[i].queue);
				break;
			}
		}
	}
	if (queue[0] == '\0') {
		fprintf(stderr, "queue was not created (lpadmin failed?)\n");
		goto cleanup;
	}
	printf("created queue %s at %s\n", queue, printer.sock_path);

	/* Submit the print job through the real CUPS spooler. */
	lp_pid = fork();
	if (lp_pid < 0) {
		fprintf(stderr, "fork: %s\n", strerror(errno));
		goto cleanup;
	}
	if (lp_pid == 0) {
		execlp("lp", "lp", "-d", queue, "--", infile, (char *)NULL);
		_exit(127);
	}

	/* Service the printer poll set until the worker sees the job or we
	 * time out.  This mirrors the session main loop's printer handling. */
	deadline = now_ms() + 30000;
	while (!got_job && now_ms() < deadline) {
		struct pollfd pfd[1 + RDP_PRINTER_MAX_CONNS + 1];
		int n = 0;
		int pr;

		/* Worker end first, so we notice the forwarded job promptly. */
		pfd[0].fd = sv[0];
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		n = 1;
		(void)rdp_printer_fill_pollfds(&printer, pfd, &n,
		    (int)(sizeof pfd / sizeof pfd[0]));

		pr = poll(pfd, (nfds_t)n, 200);
		if (pr < 0 && errno != EINTR) {
			fprintf(stderr, "poll: %s\n", strerror(errno));
			break;
		}

		/* Run the printer's listener/connection servicing. */
		rdp_printer_service(&printer, pfd + 1, n - 1);

		/* Did the worker receive the forwarded RDP_BE_PRINT_JOB? */
		if (pfd[0].revents & POLLIN) {
			uint32_t type;
			uint8_t *buf = malloc(RDP_BE_PRINT_JOB_MAX_SPOOL
			    + sizeof(struct rdp_be_print_job_hdr));
			ssize_t got;
			if (buf == NULL)
				break;
			got = rdp_be_recv(sv[0], &type, buf,
			    RDP_BE_PRINT_JOB_MAX_SPOOL
			    + sizeof(struct rdp_be_print_job_hdr));
			if (got <= 0) {
				free(buf);
				continue;
			}
			if (type == RDP_BE_PRINT_JOB
			    && (size_t)got >= sizeof(struct rdp_be_print_job_hdr)) {
				struct rdp_be_print_job_hdr h;
				size_t spool_len;
				const uint8_t *spool;
				memcpy(&h, buf, sizeof h);
				spool = buf + sizeof h;
				spool_len = (size_t)got - sizeof h;
				printf("worker received PRINT_JOB: device=%u "
				    "spool=%zu bytes\n",
				    (unsigned)h.device_id, spool_len);
				if (h.device_id != TEST_DEVICE_ID) {
					fprintf(stderr,
					    "FAIL: device id %u != %u\n",
					    (unsigned)h.device_id,
					    TEST_DEVICE_ID);
				} else if (spool_len < want_len
				    || memmem(spool, spool_len, want, want_len)
				    == NULL) {
					/* A RAW queue passes the file bytes
					 * through verbatim; they must appear
					 * in the spool the worker got. */
					fprintf(stderr, "FAIL: spool does not "
					    "contain the printed file bytes\n");
				} else {
					printf("PASS: spool contains the "
					    "printed file bytes\n");
					got_job = 1;
					rc = 0;
				}
			}
			free(buf);
		}
	}

	if (!got_job)
		fprintf(stderr, "FAIL: no PRINT_JOB reached the worker "
		    "within the timeout\n");

	/* Reap lp. */
	{
		int st;
		(void)waitpid(lp_pid, &st, 0);
	}

cleanup:
	/* rdp_printer_close removes the queue (lpadmin -x) and unlinks the
	 * socket; do it before exiting so we leave nothing behind. */
	rdp_printer_close(&printer);
	(void)close(sv[0]);
	(void)close(sv[1]);
	free(want);
	rdp_log_close();
	return rc;
}
