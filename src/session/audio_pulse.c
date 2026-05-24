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
 * audio_pulse.c -- PulseAudio capture backend for rdp-session.
 *
 * Opens a recording stream on a PulseAudio null sink's monitor.
 * Creates the null sink if it doesn't exist, so each RDP session
 * gets its own audio namespace.
 */

#include "audio.h"

#include "../include/compat.h"
#include "../include/rdp_log.h"

#if HAVE_PULSEAUDIO

#include <pulse/simple.h>
#include <pulse/error.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct rdp_audio {
	pa_simple *pa;
};

struct rdp_audio *
rdp_audio_open(void)
{
	struct rdp_audio *a;
	pa_sample_spec ss;
	pa_buffer_attr ba;
	int err;
	char sink_name[64];
	char monitor[80];
	char cmd[256];

	(void)snprintf(sink_name, sizeof sink_name,
	    "rdpserver_%d", (int)getpid());
	(void)snprintf(cmd, sizeof cmd,
	    "pactl load-module module-null-sink "
	    "sink_name=%s sink_properties=device.description=rdpserver "
	    ">/dev/null 2>&1", sink_name);
	(void)system(cmd);

	(void)snprintf(monitor, sizeof monitor, "%s.monitor", sink_name);

	ss.format = PA_SAMPLE_S16LE;
	ss.channels = 2;
	ss.rate = 44100;

	memset(&ba, 0, sizeof ba);
	ba.maxlength = 44100 * 4;
	ba.fragsize = 4410 * 4;

	a = calloc(1, sizeof *a);
	if (a == NULL) return NULL;

	a->pa = pa_simple_new(NULL, "rdpserver", PA_STREAM_RECORD,
	    monitor, "RDP audio", &ss, NULL, &ba, &err);
	if (a->pa == NULL) {
		rdp_warn("pulse: %s", pa_strerror(err));
		free(a);
		return NULL;
	}
	rdp_info("pulse: recording from %s", monitor);
	return a;
}

ssize_t
rdp_audio_read(struct rdp_audio *a, void *buf, size_t len)
{
	int err;
	pa_usec_t latency;
	size_t avail;

	if (a == NULL || a->pa == NULL) return -1;
	latency = pa_simple_get_latency(a->pa, &err);
	if (latency == (pa_usec_t)-1) return 0;
	avail = (size_t)(latency * 176400 / 1000000);
	if (avail < len) return 0;
	if (pa_simple_read(a->pa, buf, len, &err) < 0) {
		rdp_warn("pulse read: %s", pa_strerror(err));
		return -1;
	}
	return (ssize_t)len;
}

void
rdp_audio_close(struct rdp_audio *a)
{
	char cmd[128];
	if (a == NULL) return;
	if (a->pa != NULL) pa_simple_drain(a->pa, NULL);
	if (a->pa != NULL) pa_simple_free(a->pa);
	(void)snprintf(cmd, sizeof cmd,
	    "pactl unload-module module-null-sink 2>/dev/null");
	(void)system(cmd);
	free(a);
}

#else /* !HAVE_PULSEAUDIO */

struct rdp_audio *rdp_audio_open(void) { return NULL; }
ssize_t rdp_audio_read(struct rdp_audio *a, void *b, size_t l)
{ (void)a; (void)b; (void)l; return -1; }
void rdp_audio_close(struct rdp_audio *a) { (void)a; }

#endif
