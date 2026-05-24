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
 * audio_sndio.c -- sndio capture backend for rdp-session (OpenBSD).
 */

#include "audio.h"

#include "../include/compat.h"
#include "../include/rdp_log.h"

#if HAVE_SNDIO

#include <sndio.h>
#include <stdlib.h>
#include <string.h>

struct rdp_audio {
	struct sio_hdl *hdl;
};

struct rdp_audio *
rdp_audio_open(void)
{
	struct rdp_audio *a;
	struct sio_par par;

	a = calloc(1, sizeof *a);
	if (a == NULL) return NULL;

	a->hdl = sio_open(SIO_DEVANY, SIO_REC, 0);
	if (a->hdl == NULL) {
		rdp_warn("sndio: sio_open failed");
		free(a);
		return NULL;
	}

	sio_initpar(&par);
	par.bits = 16;
	par.sig = 1;
	par.le = 1;
	par.rchan = 2;
	par.rate = 44100;
	par.appbufsz = 44100 / 10;

	if (!sio_setpar(a->hdl, &par) || !sio_getpar(a->hdl, &par)) {
		rdp_warn("sndio: setpar failed");
		sio_close(a->hdl);
		free(a);
		return NULL;
	}

	if (!sio_start(a->hdl)) {
		rdp_warn("sndio: start failed");
		sio_close(a->hdl);
		free(a);
		return NULL;
	}

	rdp_info("sndio: recording %uHz %uch %ubit",
	    par.rate, par.rchan, par.bits);
	return a;
}

ssize_t
rdp_audio_read(struct rdp_audio *a, void *buf, size_t len)
{
	size_t n;
	if (a == NULL || a->hdl == NULL) return -1;
	n = sio_read(a->hdl, buf, len);
	if (n == 0 && sio_eof(a->hdl)) return -1;
	return (ssize_t)n;
}

void
rdp_audio_close(struct rdp_audio *a)
{
	if (a == NULL) return;
	if (a->hdl != NULL) {
		sio_stop(a->hdl);
		sio_close(a->hdl);
	}
	free(a);
}

#else /* !HAVE_SNDIO */

struct rdp_audio *rdp_audio_open(void) { return NULL; }
ssize_t rdp_audio_read(struct rdp_audio *a, void *b, size_t l)
{ (void)a; (void)b; (void)l; return -1; }
void rdp_audio_close(struct rdp_audio *a) { (void)a; }

#endif
