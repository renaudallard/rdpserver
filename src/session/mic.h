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
 * mic.h -- session side of RDP microphone redirection (MS-RDPEAI).
 *
 * Presents the client's microphone PCM (arriving from the worker as
 * RDP_BE_AUDIO_INPUT messages) as a PulseAudio capture source named
 * "rdp_microphone" that applications in the session can record from.
 *
 * The source is a module-pipe-source backed by a FIFO under the
 * session's runtime dir; rdp_mic_write feeds the FIFO the PCM bytes.
 * Everything is best effort: with no pactl, no Pulse server, or a
 * failed module load the module stays inert and the session runs
 * normally without a virtual mic.  The whole feature is gated by
 * HAVE_PULSEAUDIO; elsewhere these are no-op stubs.
 *
 * PCM format: 16-bit signed LE, stereo, 44100 Hz (the AUDIO_INPUT
 * default), matching the module-pipe-source we load.
 */

#ifndef RDP_MIC_H
#define RDP_MIC_H

#include <sys/types.h>
#include <stddef.h>

struct rdp_mic;

/* Create the PulseAudio pipe source and open its FIFO for writing.
 * Returns NULL (and the session runs without a virtual mic) on any
 * failure.  Never breaks the session. */
struct rdp_mic *rdp_mic_open(void);

/* Feed len bytes of PCM to the source's FIFO, non-blocking.  When the
 * FIFO is full (no reader draining) the excess is dropped rather than
 * blocking the session loop.  A NULL mic is a no-op. */
void rdp_mic_write(struct rdp_mic *m, const void *pcm, size_t len);

/* Unload the pactl module, close the fd, unlink the FIFO and free the
 * state.  A NULL mic is a no-op. */
void rdp_mic_close(struct rdp_mic *m);

/*
 * Parse the module index pactl prints on stdout after a successful
 * "load-module".  pactl writes the new module's integer index followed
 * by a newline (and nothing else).  Returns the parsed non-negative
 * index, or -1 if the output is not a plain non-negative integer.
 *
 * Exposed (and always compiled, even in the stub build) so it can be
 * unit tested without a live Pulse server.
 */
long rdp_mic_parse_index(const char *out, size_t len);

#endif /* RDP_MIC_H */
