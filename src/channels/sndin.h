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
 * sndin.h -- MS-RDPEAI (Audio Input Redirection) implementation.
 *
 * The client captures its microphone and streams the PCM samples to the
 * server over the AUDIO_INPUT dynamic virtual channel.  The server drives
 * a small negotiation handshake (Version, Formats, Open) then receives
 * Data PDUs carrying the captured audio.  We offer and capture PCM
 * (16-bit LE, stereo, 44100 Hz), the same WAVEFORMATEX layout RDPSND
 * advertises for output.
 *
 * Every SNDIN PDU begins with a one-byte MessageId.  The client is
 * untrusted: every parse here is bounded against the PDU length.
 */

#ifndef RDP_SNDIN_H
#define RDP_SNDIN_H

#include "../include/compat.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* SNDIN MessageId values (MS-RDPEAI 2.2.1). */
#define SNDIN_MSG_VERSION       0x01
#define SNDIN_MSG_FORMATS       0x02
#define SNDIN_MSG_OPEN          0x03
#define SNDIN_MSG_OPEN_REPLY    0x04
#define SNDIN_MSG_DATA_INCOMING 0x05
#define SNDIN_MSG_DATA          0x06
#define SNDIN_MSG_FORMATCHANGE  0x07

#define SNDIN_VERSION           1u

/* WAVEFORMATEX wFormatTag we offer (raw PCM, the only format we capture). */
#define SNDIN_WAVE_FORMAT_PCM   0x0001

/* Negotiation phase, advanced by rdp_sndin_handle as the client replies. */
enum sndin_phase {
	SNDIN_INIT = 0,     /* nothing sent yet */
	SNDIN_VERSION_SENT, /* server Version sent, awaiting client Version */
	SNDIN_FORMATS_SENT, /* server Formats sent, awaiting client Formats */
	SNDIN_OPEN_SENT,    /* server Open sent, awaiting Open Reply */
	SNDIN_STREAMING     /* Open Reply S_OK; Data PDUs may now arrive */
};

struct sndin_state {
	enum sndin_phase phase;
	/* The capture format we asked the client to open, mirrored so the
	 * caller knows the PCM layout of the bytes a Data PDU returns. */
	uint16_t nChannels;
	uint32_t nSamplesPerSec;
	uint16_t wBitsPerSample;
	uint16_t nBlockAlign;
};

/* Reset a sndin_state to the INIT phase (zeroing is also valid). */
void rdp_sndin_init(struct sndin_state *st);

/* Build the server Version PDU (MSG_SNDIN_VERSION).  Returns the byte
 * count written, or -1 if it would not fit. */
ssize_t rdp_sndin_build_version(uint8_t *out, size_t cap);

/* Build the server Formats PDU (MSG_SNDIN_FORMATS) offering PCM 16-bit
 * stereo 44100 Hz.  Returns the byte count written, or -1. */
ssize_t rdp_sndin_build_formats(uint8_t *out, size_t cap);

/* Build the server Open PDU (MSG_SNDIN_OPEN) selecting client format
 * index `initial_format` and the PCM capture format.  Returns bytes
 * written, or -1. */
ssize_t rdp_sndin_build_open(uint8_t *out, size_t cap,
		uint32_t frames_per_packet, uint32_t initial_format);

/* Consume one inbound SNDIN PDU and advance the state machine.
 *
 * `in`/`in_len` is the raw PDU starting at the MessageId byte.  On the
 * negotiation messages the next server PDU is emitted into `out`
 * (capacity `out_cap`) and its length stored in *out_len (0 if none).
 * On a Data PDU the audio payload is returned via audio_out and audio_len
 * (pointing into `in`, valid only until the next call); these are NULL and
 * 0 for every other message.
 *
 * Returns the parsed MessageId (>0) on success, or -1 on a malformed or
 * truncated PDU.  An out buffer too small to hold the response is not an
 * error: *out_len stays 0 and the caller simply sends nothing. */
int rdp_sndin_handle(struct sndin_state *st,
		const uint8_t *in, size_t in_len,
		uint8_t *out, size_t out_cap, size_t *out_len,
		const uint8_t **audio_out, size_t *audio_len);

#endif /* RDP_SNDIN_H */
