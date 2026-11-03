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
 * run.c -- run a helper program and wait for its exit status.
 */

#include "run.h"

#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RUN_MAX_ARGS 32

ssize_t
rdp_run(const char *path, const char *const argv[], char *out, size_t outsz)
{
	char *child[RUN_MAX_ARGS + 1];
	struct sigaction dfl, old;
	size_t nargs = 0;
	ssize_t got = 0;
	int pfd[2] = { -1, -1 };
	int restore = 0, st;
	pid_t pid;

	if (out != NULL) {
		if (outsz == 0)
			return -1;
		out[0] = '\0';
	}
	/* Copy argv so execvp gets a char *const[] without a const-dropping
	 * cast. */
	while (argv[nargs] != NULL) {
		if (nargs >= RUN_MAX_ARGS
		    || (child[nargs] = strdup(argv[nargs])) == NULL)
			goto fail;
		nargs++;
	}
	child[nargs] = NULL;
	if (out != NULL && pipe(pfd) != 0)
		goto fail;

	memset(&dfl, 0, sizeof dfl);
	dfl.sa_handler = SIG_DFL;
	sigemptyset(&dfl.sa_mask);
	if (sigaction(SIGCHLD, &dfl, &old) == 0)
		restore = 1;

	pid = fork();
	if (pid < 0)
		goto fail;
	if (pid == 0) {
		int devnull = open("/dev/null", O_RDWR);
		if (devnull >= 0) {
			(void)dup2(devnull, STDIN_FILENO);
			(void)dup2(devnull, STDOUT_FILENO);
			(void)dup2(devnull, STDERR_FILENO);
			if (devnull > STDERR_FILENO)
				(void)close(devnull);
		}
		if (out != NULL) {
			(void)dup2(pfd[1], STDOUT_FILENO);
			(void)close(pfd[0]);
			(void)close(pfd[1]);
		}
		execvp(path, child);
		_exit(127);
	}

	if (out != NULL) {
		(void)close(pfd[1]);
		pfd[1] = -1;
		/* Drain all of stdout so the child never blocks on a full pipe,
		 * keeping what fits. */
		for (;;) {
			char drop[256];
			int keep = (size_t)got < outsz - 1;
			ssize_t r = keep
			    ? read(pfd[0], out + got, outsz - 1 - (size_t)got)
			    : read(pfd[0], drop, sizeof drop);
			if (r < 0 && errno == EINTR)
				continue;
			if (r <= 0)
				break;
			if (keep)
				got += r;
		}
		out[got] = '\0';
		(void)close(pfd[0]);
		pfd[0] = -1;
	}
	while (waitpid(pid, &st, 0) < 0) {
		if (errno != EINTR)
			goto fail;
	}
	if (restore)
		(void)sigaction(SIGCHLD, &old, NULL);
	while (nargs > 0)
		free(child[--nargs]);
	return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? got : -1;

fail:
	if (restore)
		(void)sigaction(SIGCHLD, &old, NULL);
	if (pfd[0] >= 0)
		(void)close(pfd[0]);
	if (pfd[1] >= 0)
		(void)close(pfd[1]);
	while (nargs > 0)
		free(child[--nargs]);
	return -1;
}
