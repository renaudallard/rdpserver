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
 * mic_live.c -- live end to end test of the session microphone source.
 *
 * Drives the REAL mic.c against a REAL PulseAudio/PipeWire server:
 *   1. rdp_mic_open() loads module-pipe-source and opens the FIFO.
 *   2. Verify "pactl list short sources" shows rdp_microphone.
 *   3. Start parecord recording from rdp_microphone into a raw file (with a
 *      small capture latency so it flushes within the short test window).
 *   4. Feed a known full-scale antisymmetric square wave via rdp_mic_write
 *      for ~0.4 s.
 *   5. Stop parecord, rdp_mic_close().
 *   6. Verify the recording contains a run of the pattern's loud
 *      antisymmetric frames (allowing leading silence/underrun and the
 *      float32 path's tiny byte perturbation), the source is gone, and the
 *      FIFO is unlinked.
 *
 * NOT part of `make regress` (it needs pactl/parecord and a Pulse server).
 * The argv is one path: the raw file parecord records into.
 */

#define _GNU_SOURCE

#include "../../src/session/mic.h"

#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef RDP_PACTL_PATH
# define RDP_PACTL_PATH "/usr/bin/pactl"
#endif
#ifndef RDP_PARECORD_PATH
# define RDP_PARECORD_PATH "/usr/bin/parecord"
#endif

#define SOURCE_NAME "rdp_microphone"
#define RATE 44100
#define CHANNELS 2
#define BYTES_PER_FRAME (CHANNELS * 2)   /* s16le stereo */

/*
 * The PCM pattern we feed is a distinctive full-scale 1 kHz square wave that
 * is antisymmetric across the two channels: the left sample is +/- AMP and
 * the right is its negation.  This survives PulseAudio/PipeWire's internal
 * float32 conversion and tiny resampling (which perturb exact byte values, so
 * a byte-exact memcmp would be wrong here), yet stays recognizable: loud
 * frames whose left sample is near full scale and whose right sample mirrors
 * it cannot come from leading silence or random underrun fill, so finding a
 * run of them proves our bytes reached a recorder reading the source.
 */
#define MIC_AMP   20000      /* near full scale (|s16| max is 32767) */
#define MIC_FREQ  1000       /* 1 kHz square wave */
#define MIC_LOUD  15000      /* a "loud" frame has |left| above this */

/* Sleep for ms milliseconds, restarting on EINTR. */
static void
sleep_ms(long ms)
{
	struct timespec ts;
	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (ms % 1000) * 1000000L;
	while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
		;
}

/* Run "pactl list short sources" and return 1 if rdp_microphone is present,
 * 0 if not, -1 on a tooling error. */
static int
source_present(void)
{
	int pfd[2];
	pid_t pid;
	char buf[8192];
	size_t got = 0;
	int st;

	if (pipe(pfd) != 0)
		return -1;
	pid = fork();
	if (pid < 0) {
		(void)close(pfd[0]);
		(void)close(pfd[1]);
		return -1;
	}
	if (pid == 0) {
		(void)dup2(pfd[1], STDOUT_FILENO);
		(void)close(pfd[0]);
		(void)close(pfd[1]);
		execl(RDP_PACTL_PATH, "pactl", "list", "short", "sources",
		    (char *)NULL);
		_exit(127);
	}
	(void)close(pfd[1]);
	for (;;) {
		ssize_t r;
		if (got >= sizeof buf - 1)
			break;
		r = read(pfd[0], buf + got, sizeof buf - 1 - got);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (r == 0)
			break;
		got += (size_t)r;
	}
	buf[got] = '\0';
	(void)close(pfd[0]);
	while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
		;
	if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0))
		return -1;
	return strstr(buf, SOURCE_NAME) != NULL ? 1 : 0;
}

/*
 * Fill one 20 ms chunk of s16le stereo with the antisymmetric full-scale
 * square wave, continuing the wave phase from sample index *phase so chunks
 * concatenate into a continuous tone.
 */
#define CHUNK_FRAMES 882                       /* 20 ms at 44100 Hz */
static void
fill_chunk(int16_t *buf, long *phase)
{
	int i;
	for (i = 0; i < CHUNK_FRAMES; i++) {
		long n = *phase + i;
		/* One full square period spans RATE/MIC_FREQ frames; the high
		 * half is the first half of each period. */
		int high = ((n * MIC_FREQ * 2) / RATE) % 2 == 0;
		int16_t s = (int16_t)(high ? MIC_AMP : -MIC_AMP);
		buf[i * 2 + 0] = s;        /* left */
		buf[i * 2 + 1] = (int16_t)(-s);  /* right mirrors left */
	}
	*phase += CHUNK_FRAMES;
}

/*
 * Count frames in the s16le stereo recording whose left sample is loud and
 * whose right sample mirrors it (|left + right| small).  Such frames are our
 * antisymmetric square wave; silence and underrun fill produce none.  hlen is
 * the recording length in bytes.
 */
static size_t
count_pattern_frames(const uint8_t *hay, size_t hlen)
{
	size_t frames = hlen / BYTES_PER_FRAME;
	size_t i;
	size_t hits = 0;

	for (i = 0; i < frames; i++) {
		int16_t l, r;
		memcpy(&l, hay + i * BYTES_PER_FRAME, 2);
		memcpy(&r, hay + i * BYTES_PER_FRAME + 2, 2);
		if ((l > MIC_LOUD || l < -MIC_LOUD)
		    && (int)l + (int)r < 4000 && (int)l + (int)r > -4000)
			hits++;
	}
	return hits;
}

int
main(int argc, char **argv)
{
	struct rdp_mic *m;
	const char *recfile;
	char fifo_path[256];
	const char *dir;
	long phase = 0;
	pid_t rec;
	int reps;
	int present;
	uint8_t *rbuf;
	size_t rlen = 0;
	size_t hits;
	int rfd;
	int rc = 1;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <record-file>\n", argv[0]);
		return 2;
	}
	recfile = argv[1];

	/* Replicate the session's process-wide SIGCHLD disposition
	 * (SA_NOCLDWAIT auto-reap) so this test exercises rdp_mic_open under
	 * the same condition rdp-session runs it: without run_pactl's local
	 * SIG_DFL restore, waitpid would fail with ECHILD and the mic would
	 * never load. */
	{
		struct sigaction sa;
		memset(&sa, 0, sizeof sa);
		sa.sa_handler = SIG_DFL;
		sa.sa_flags = SA_NOCLDWAIT;
		sigemptyset(&sa.sa_mask);
		(void)sigaction(SIGCHLD, &sa, NULL);
	}

	/* 1. Open the mic: loads module-pipe-source and opens the FIFO. */
	m = rdp_mic_open();
	if (m == NULL) {
		fprintf(stderr, "mic_live: rdp_mic_open failed "
		    "(no pactl or no pulse server?)\n");
		return 2;
	}
	printf("mic_live: rdp_mic_open ok\n");

	/* The FIFO path mic.c built is deterministic from our pid. */
	dir = getenv("XDG_RUNTIME_DIR");
	if (dir == NULL || dir[0] != '/')
		dir = getenv("TMPDIR");
	if (dir == NULL || dir[0] != '/')
		dir = "/tmp";
	(void)snprintf(fifo_path, sizeof fifo_path, "%s/rdp-mic-%ld.fifo",
	    dir, (long)getpid());

	/* 2. The source must now exist. */
	present = source_present();
	if (present != 1) {
		fprintf(stderr, "mic_live: source %s not listed after open "
		    "(present=%d)\n", SOURCE_NAME, present);
		rdp_mic_close(m);
		return 1;
	}
	printf("mic_live: source %s present after open\n", SOURCE_NAME);

	/* 3. Start parecord on the source into recfile (raw s16le stereo). */
	(void)unlink(recfile);
	rec = fork();
	if (rec < 0) {
		fprintf(stderr, "mic_live: fork parecord: %s\n",
		    strerror(errno));
		rdp_mic_close(m);
		return 1;
	}
	if (rec == 0) {
		int devnull = open("/dev/null", O_RDWR);
		if (devnull >= 0) {
			(void)dup2(devnull, STDIN_FILENO);
			(void)dup2(devnull, STDERR_FILENO);
		}
		/* A small capture latency makes parecord deliver and flush
		 * promptly; its multi-second default fragment would never be
		 * written within this short test window. */
		execl(RDP_PARECORD_PATH, "parecord",
		    "--latency-msec=50",
		    "--device=" SOURCE_NAME,
		    "--format=s16le", "--rate=44100", "--channels=2",
		    "--file-format=raw", recfile, (char *)NULL);
		_exit(127);
	}

	/* Give parecord a moment to connect and start draining the FIFO. */
	sleep_ms(500);

	/* 4. Feed the pattern: a continuous antisymmetric square wave in 20 ms
	 * chunks for ~0.4 s of audio. */
	{
		int16_t chunk[CHUNK_FRAMES * CHANNELS];
		for (reps = 0; reps < 20; reps++) {     /* ~0.4 s */
			fill_chunk(chunk, &phase);
			rdp_mic_write(m, chunk, sizeof chunk);
			sleep_ms(20);
		}
	}
	printf("mic_live: wrote pattern (%d chunks)\n", reps);

	/* 5. Stop parecord and close the mic. */
	sleep_ms(200);
	(void)kill(rec, SIGTERM);
	while (waitpid(rec, NULL, 0) < 0 && errno == EINTR)
		;

	/* 6a. Read back the recording and look for the pattern. */
	rfd = open(recfile, O_RDONLY);
	if (rfd < 0) {
		fprintf(stderr, "mic_live: open %s: %s\n", recfile,
		    strerror(errno));
		rdp_mic_close(m);
		return 1;
	}
	rbuf = malloc(8u * 1024u * 1024u);
	if (rbuf == NULL) {
		(void)close(rfd);
		rdp_mic_close(m);
		return 1;
	}
	for (;;) {
		ssize_t r;
		if (rlen >= 8u * 1024u * 1024u)
			break;
		r = read(rfd, rbuf + rlen, 8u * 1024u * 1024u - rlen);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (r == 0)
			break;
		rlen += (size_t)r;
	}
	(void)close(rfd);
	printf("mic_live: recorded %zu bytes\n", rlen);

	/* Require a solid run of our antisymmetric loud frames: roughly half of
	 * a 1 kHz square wave's samples are loud, so even a fraction of the
	 * ~0.4 s we fed (allowing for leading silence and underrun) yields
	 * thousands.  A few hundred is far more than silence or noise produces
	 * and proves the bytes round-tripped through the source. */
	hits = count_pattern_frames(rbuf, rlen);
	printf("mic_live: %zu pattern frames in recording\n", hits);
	if (hits >= 500) {
		printf("mic_live: pattern found in recording\n");
		rc = 0;
	} else {
		fprintf(stderr, "mic_live: pattern NOT found in recording "
		    "(%zu frames)\n", hits);
		rc = 1;
	}
	free(rbuf);

	/* 6b. Close the mic: unloads the module, closes fd, unlinks FIFO. */
	rdp_mic_close(m);
	printf("mic_live: rdp_mic_close done\n");

	/* 6c. The source must be gone now. */
	present = source_present();
	if (present == 0) {
		printf("mic_live: source %s removed after close\n",
		    SOURCE_NAME);
	} else {
		fprintf(stderr, "mic_live: source %s still present after close "
		    "(present=%d)\n", SOURCE_NAME, present);
		rc = 1;
	}

	/* 6d. The FIFO must be gone. */
	if (access(fifo_path, F_OK) != 0) {
		printf("mic_live: fifo %s unlinked\n", fifo_path);
	} else {
		fprintf(stderr, "mic_live: fifo %s still present after close\n",
		    fifo_path);
		(void)unlink(fifo_path);
		rc = 1;
	}

	(void)unlink(recfile);
	return rc;
}
