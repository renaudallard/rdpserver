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
 * rdpsnd.h -- MS-RDPEA (Audio Output Virtual Channel) implementation.
 *
 * Negotiates PCM (16-bit LE, stereo, 44100 Hz) and G.711 A-law with
 * the client and streams captured audio via SNDC_WAVE2.  A-law halves
 * the wire bandwidth and is selected for WAN when the operator opts in
 * (rdpd -W) and the client supports it.
 */

#ifndef RDP_RDPSND_H
#define RDP_RDPSND_H

#include "../include/compat.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define SNDC_CLOSE              0x01
#define SNDC_WAVE               0x02
#define SNDC_SETVOLUME          0x03
#define SNDC_SETPITCH           0x04
#define SNDC_WAVECONFIRM        0x05
#define SNDC_TRAINING           0x06   /* also the client Training Confirm */
#define SNDC_FORMATS            0x07
#define SNDC_CRYPTKEY           0x08
#define SNDC_WAVEENCRYPT        0x09
#define SNDC_UDPWAVE            0x0A
#define SNDC_UDPWAVELAST        0x0B
#define SNDC_QUALITYMODE        0x0C
#define SNDC_WAVE2              0x0D

#define RDPSND_VERSION          0x06

#define WAVE_FORMAT_PCM         0x0001
#define WAVE_FORMAT_ALAW        0x0006

struct rdpsnd_state {
	int negotiated;
	int client_format_count;
	uint8_t block_no;
	uint16_t timestamp;
	uint16_t format_no;          /* index of the chosen output format */
	uint16_t chosen_tag;         /* WAVE_FORMAT_* of the chosen format */
	uint32_t chosen_rate;
	uint16_t chosen_block_align;
};

/* Build the Server Audio Formats and Version PDU.  Advertises PCM
 * (index 0) and G.711 A-law (index 1). */
ssize_t rdp_rdpsnd_build_formats(uint8_t *out, size_t cap);

/* Handle an inbound RDPSND PDU (Client Audio Formats, Training
 * Confirm, Wave Confirm).  prefer_wan selects the compact A-law
 * format when the client also supports it.  Returns 0 on success. */
int rdp_rdpsnd_handle(struct rdpsnd_state *st,
		const uint8_t *pdu, size_t len, int prefer_wan);

/* Build a Training PDU (server sends this, client confirms). */
ssize_t rdp_rdpsnd_build_training(uint8_t *out, size_t cap);

/* Build a SNDC_WAVE2 PDU carrying audio in the chosen format
 * (st->format_no references the negotiated format list index). */
ssize_t rdp_rdpsnd_build_wave2(struct rdpsnd_state *st,
		uint8_t *out, size_t cap,
		const uint8_t *data, size_t data_len);

/* Encode S16LE PCM to G.711 A-law (1 byte per sample).  out must hold
 * at least pcm_len/2 bytes; returns the number of A-law bytes. */
size_t rdp_rdpsnd_alaw_encode(const uint8_t *pcm, size_t pcm_len,
		uint8_t *out);

#endif /* RDP_RDPSND_H */
