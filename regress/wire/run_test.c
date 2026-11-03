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
 * run_test.c -- rdp_run under the session's SA_NOCLDWAIT SIGCHLD setting.
 */

#include "../../src/session/run.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                                \
	(void)fprintf(stderr, "fail: " __VA_ARGS__);  \
	(void)fputc('\n', stderr);                    \
	exit(1);                                       \
} while (0)

int
main(void)
{
	static const char *const ok[] = { "true", NULL };
	static const char *const bad[] = { "false", NULL };
	static const char *const echo[] = { "echo", "hello", NULL };
	static const char *const missing[] = { "rdp-run-test-missing", NULL };
	struct sigaction sa, now;
	char out[4];
	ssize_t n;

	/* The session's setting: children are reaped by the kernel, which
	 * is what made waitpid fail before. */
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = SIG_DFL;
	sa.sa_flags = SA_NOCLDWAIT;
	(void)sigaction(SIGCHLD, &sa, NULL);

	if (rdp_run("true", ok, NULL, 0) != 0)
		FAIL("true reported as failing");
	if (rdp_run("false", bad, NULL, 0) != -1)
		FAIL("false reported as succeeding");
	if (rdp_run("rdp-run-test-missing", missing, NULL, 0) != -1)
		FAIL("missing program reported as succeeding");
	n = rdp_run("echo", echo, out, sizeof out);
	if (n != 3 || strcmp(out, "hel") != 0)
		FAIL("captured output %zd '%s', want 3 'hel'", n, out);
	(void)sigaction(SIGCHLD, NULL, &now);
	if (!(now.sa_flags & SA_NOCLDWAIT))
		FAIL("SIGCHLD setting not restored");
	(void)printf("run_test: all ok\n");
	return 0;
}
