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
 * mic.c -- session side of RDP microphone redirection.  See mic.h for the
 * design.  The client's captured PCM (forwarded by the worker) is fed into
 * a PulseAudio module-pipe-source so applications in the session can select
 * "rdp_microphone" as their recording device.
 */

#include "mic.h"

#include "../include/compat.h"
#include "../include/rdp_log.h"
#include "../common/io.h"

#include <ctype.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

/*
 * Parse the module index pactl prints on stdout after "load-module".
 * Kept outside the HAVE_PULSEAUDIO gate so it is always compiled and
 * unit testable.  Accepts an optional trailing newline and surrounding
 * whitespace but nothing else; a non-numeric line (an error message) or
 * an empty line yields -1.
 */
long
rdp_mic_parse_index(const char *out, size_t len)
{
	size_t i = 0;
	size_t j;
	long v = 0;
	int digits = 0;

	if (out == NULL)
		return -1;
	/* Skip leading whitespace. */
	while (i < len && isspace((unsigned char)out[i]))
		i++;
	/* Accumulate the decimal digits with an overflow guard. */
	for (; i < len && out[i] >= '0' && out[i] <= '9'; i++) {
		int d = out[i] - '0';
		if (v > (LONG_MAX - d) / 10)
			return -1;
		v = v * 10 + d;
		digits++;
	}
	if (digits == 0)
		return -1;
	/* Only trailing whitespace may follow the number. */
	for (j = i; j < len; j++) {
		if (out[j] == '\0')
			break;
		if (!isspace((unsigned char)out[j]))
			return -1;
	}
	return v;
}

#if HAVE_PULSEAUDIO

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

/* Path to pactl.  A fixed path keeps us from running an attacker planted
 * pactl found via $PATH; PipeWire and PulseAudio both install it here. */
#ifndef RDP_PACTL_PATH
# define RDP_PACTL_PATH "/usr/bin/pactl"
#endif

/* The source name applications select as their input device. */
#define RDP_MIC_SOURCE_NAME "rdp_microphone"

struct rdp_mic {
	int  module;          /* loaded module index, or -1 if none */
	int  fd;              /* O_WRONLY FIFO write end, or -1 if not open */
	char fifo[256];       /* FIFO path, module-pipe-source's read end */
};

/* Probe whether pactl exists and is executable. */
static int
pactl_present(void)
{
	return access(RDP_PACTL_PATH, X_OK) == 0;
}

/*
 * Build the per session FIFO path under the best available runtime dir.
 * Bounds the result to the field; returns 0 on success, -1 if too long.
 */
static int
build_fifo_path(char *out, size_t outsz)
{
	const char *dir = getenv("XDG_RUNTIME_DIR");
	int n;

	if (dir == NULL || dir[0] != '/')
		dir = getenv("TMPDIR");
	if (dir == NULL || dir[0] != '/')
		dir = "/tmp";
	n = snprintf(out, outsz, "%s/rdp-mic-%ld.fifo", dir, (long)getpid());
	if (n < 0 || (size_t)n >= outsz)
		return -1;
	return 0;
}

/* Maximum pactl arguments we ever pass (load-module is the longest). */
#define PACTL_MAX_ARGS 8

/*
 * Run pactl with the given NULL terminated argv (argv[0] is the path),
 * capturing its stdout into cap (NUL terminated, bounded by capsz).  Returns
 * the number of stdout bytes captured (>= 0) if pactl exited 0, or -1 on any
 * failure (fork/exec error or a non-zero exit).  No shell is involved, so the
 * source name and FIFO path cannot be read as shell metacharacters.
 */
static ssize_t
run_pactl(const char *const argv[], char *cap, size_t capsz)
{
	char *child[PACTL_MAX_ARGS + 1];
	size_t nargs = 0;
	int pfd[2];
	pid_t pid;
	int st;
	ssize_t got = 0;
	struct sigaction sigchld_dfl, sigchld_old;
	int sigchld_restore;

	if (cap == NULL || capsz == 0)
		return -1;
	cap[0] = '\0';

	while (argv[nargs] != NULL) {
		if (nargs >= PACTL_MAX_ARGS)
			return -1;
		child[nargs] = strdup(argv[nargs]);
		if (child[nargs] == NULL) {
			while (nargs > 0)
				free(child[--nargs]);
			return -1;
		}
		nargs++;
	}
	child[nargs] = NULL;

	if (pipe(pfd) != 0) {
		while (nargs > 0)
			free(child[--nargs]);
		return -1;
	}

	/* The session installs a process-wide SIGCHLD handler with
	 * SA_NOCLDWAIT, under which a terminated child is auto-reaped and
	 * waitpid cannot return its status (it fails with ECHILD).  Restore the
	 * default disposition around the fork and wait so we read pactl's exit
	 * status, then put the handler back (the same workaround set_keymap
	 * uses for setxkbmap). */
	sigchld_restore = 0;
	memset(&sigchld_dfl, 0, sizeof sigchld_dfl);
	sigchld_dfl.sa_handler = SIG_DFL;
	sigemptyset(&sigchld_dfl.sa_mask);
	if (sigaction(SIGCHLD, &sigchld_dfl, &sigchld_old) == 0)
		sigchld_restore = 1;

	pid = fork();
	if (pid < 0) {
		if (sigchld_restore)
			(void)sigaction(SIGCHLD, &sigchld_old, NULL);
		(void)close(pfd[0]);
		(void)close(pfd[1]);
		while (nargs > 0)
			free(child[--nargs]);
		return -1;
	}
	if (pid == 0) {
		int devnull = open("/dev/null", O_RDWR);
		if (devnull >= 0) {
			(void)dup2(devnull, STDIN_FILENO);
			(void)dup2(devnull, STDERR_FILENO);
			if (devnull > STDERR_FILENO)
				(void)close(devnull);
		}
		(void)dup2(pfd[1], STDOUT_FILENO);
		(void)close(pfd[0]);
		(void)close(pfd[1]);
		execv(RDP_PACTL_PATH, child);
		_exit(127);
	}

	(void)close(pfd[1]);
	while (nargs > 0)
		free(child[--nargs]);

	/* Drain pactl's stdout into cap, keeping one byte for the NUL. */
	for (;;) {
		ssize_t r;
		if ((size_t)got >= capsz - 1) {
			char drop[256];
			r = read(pfd[0], drop, sizeof drop);
			if (r <= 0) {
				if (r < 0 && errno == EINTR)
					continue;
				break;
			}
			continue;
		}
		r = read(pfd[0], cap + got, capsz - 1 - (size_t)got);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (r == 0)
			break;
		got += r;
	}
	cap[got] = '\0';
	(void)close(pfd[0]);

	while (waitpid(pid, &st, 0) < 0) {
		if (errno != EINTR) {
			if (sigchld_restore)
				(void)sigaction(SIGCHLD, &sigchld_old, NULL);
			return -1;
		}
	}
	if (sigchld_restore)
		(void)sigaction(SIGCHLD, &sigchld_old, NULL);
	if (WIFEXITED(st) && WEXITSTATUS(st) == 0)
		return got;
	return -1;
}

/*
 * Open (or reopen) the FIFO write end, non-blocking.  module-pipe-source owns
 * the read end; with no reader yet the open can fail with ENXIO, so this is
 * allowed to fail quietly and is retried lazily on the next write.  Returns 0
 * when m->fd is open, -1 otherwise.
 */
static int
fifo_open(struct rdp_mic *m)
{
	int fd;

	if (m->fd >= 0)
		return 0;
	fd = open(m->fifo, O_WRONLY | O_NONBLOCK);
	if (fd < 0)
		return -1;
	(void)rdp_set_cloexec(fd);
	m->fd = fd;
	return 0;
}

struct rdp_mic *
rdp_mic_open(void)
{
	struct rdp_mic *m;
	char cap[64];
	char src_arg[64];
	char file_arg[256 + 16];
	ssize_t n;
	long idx;

	if (!pactl_present()) {
		rdp_info("mic: %s not found; virtual microphone disabled",
		    RDP_PACTL_PATH);
		return NULL;
	}

	m = calloc(1, sizeof *m);
	if (m == NULL)
		return NULL;
	m->module = -1;
	m->fd = -1;

	if (build_fifo_path(m->fifo, sizeof m->fifo) != 0) {
		rdp_warn("mic: runtime dir path too long; microphone off");
		free(m);
		return NULL;
	}

	/* module-pipe-source creates the FIFO when it loads.  Remove any stale
	 * path first so a leftover from a crashed prior session does not make
	 * the load fail. */
	(void)unlink(m->fifo);

	(void)snprintf(src_arg, sizeof src_arg, "source_name=%s",
	    RDP_MIC_SOURCE_NAME);
	(void)snprintf(file_arg, sizeof file_arg, "file=%s", m->fifo);

	{
		const char *av[PACTL_MAX_ARGS + 1];
		size_t k = 0;

		av[k++] = RDP_PACTL_PATH;
		av[k++] = "load-module";
		av[k++] = "module-pipe-source";
		av[k++] = src_arg;
		av[k++] = file_arg;
		av[k++] = "format=s16le";
		av[k++] = "rate=44100";
		av[k++] = "channels=2";
		av[k] = NULL;

		n = run_pactl(av, cap, sizeof cap);
	}
	if (n < 0) {
		rdp_warn("mic: pactl load-module failed; microphone off");
		(void)unlink(m->fifo);
		free(m);
		return NULL;
	}

	idx = rdp_mic_parse_index(cap, (size_t)n);
	if (idx < 0 || idx > INT_MAX) {
		rdp_warn("mic: could not parse pactl module index; "
		    "microphone off");
		(void)unlink(m->fifo);
		free(m);
		return NULL;
	}
	m->module = (int)idx;

	/* Try to open the FIFO write end now; if no reader is attached yet the
	 * open is retried lazily on the first write. */
	(void)fifo_open(m);

	rdp_info("mic: source %s ready (module %d, fifo %s)",
	    RDP_MIC_SOURCE_NAME, m->module, m->fifo);
	return m;
}

void
rdp_mic_write(struct rdp_mic *m, const void *pcm, size_t len)
{
	const uint8_t *p = pcm;
	size_t off = 0;

	if (m == NULL || pcm == NULL || len == 0)
		return;
	if (m->fd < 0 && fifo_open(m) != 0)
		return;   /* no reader yet: drop this chunk */

	while (off < len) {
		ssize_t w = write(m->fd, p + off, len - off);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/* The source is not draining fast enough; drop
				 * the rest rather than block the session loop. */
				return;
			}
			/* The reader went away (EPIPE) or another error: close
			 * the fd so the next write reopens it. */
			(void)close(m->fd);
			m->fd = -1;
			return;
		}
		off += (size_t)w;
	}
}

void
rdp_mic_close(struct rdp_mic *m)
{
	if (m == NULL)
		return;

	if (m->fd >= 0) {
		(void)close(m->fd);
		m->fd = -1;
	}
	if (m->module >= 0) {
		char idx[16];
		char cap[64];
		const char *av[] = {
			RDP_PACTL_PATH, "unload-module", idx, NULL
		};
		(void)snprintf(idx, sizeof idx, "%d", m->module);
		(void)run_pactl(av, cap, sizeof cap);
		m->module = -1;
	}
	/* module-pipe-source unlinks the FIFO on unload, but remove it anyway
	 * in case the unload failed or never ran so nothing is left behind. */
	if (m->fifo[0] != '\0') {
		(void)unlink(m->fifo);
		m->fifo[0] = '\0';
	}
	free(m);
}

#else /* !HAVE_PULSEAUDIO */

struct rdp_mic *rdp_mic_open(void) { return NULL; }
void rdp_mic_write(struct rdp_mic *m, const void *p, size_t l)
{ (void)m; (void)p; (void)l; }
void rdp_mic_close(struct rdp_mic *m) { (void)m; }

#endif /* HAVE_PULSEAUDIO */
