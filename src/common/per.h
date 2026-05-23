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
 * per.h -- ASN.1 PER (Aligned) helpers, minimal subset for GCC/MCS.
 *
 * PER Aligned (X.691) is used by T.124 GCC Conference Create
 * Request/Response, which RDP carries inside the MCS Connect
 * Initial/Response userData.  We only need a small slice:
 *
 *  - choice (single-byte choice index)
 *  - length determinant in the "small unconstrained" form: 1 byte
 *    if value < 128 (top bit 0), else 2 bytes (top bits 10).
 *  - object identifier (writes a fixed precomputed encoding)
 *  - integer 16/32-bit big-endian aligned
 *  - octet string n (where n is fixed by spec): just raw bytes.
 *  - sequence-of header (a length determinant).
 *
 * The encoders write into a buffer; decoders return an offset
 * advance or -1.
 */

#ifndef RDP_PER_H
#define RDP_PER_H

#include "buf.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Length determinant, "fragmented small" variant used by GCC user
 * data.  Values 0..127 take 1 byte (top bit 0).  Values 128..16383
 * take 2 bytes (0x8000 | value, big-endian). */
int     rdp_per_write_length(struct rdp_buf *b, size_t length);
ssize_t rdp_per_read_length(const uint8_t *p, size_t left, size_t *out);

/* Choice: single byte. */
int     rdp_per_write_choice(struct rdp_buf *b, uint8_t choice);
ssize_t rdp_per_read_choice(const uint8_t *p, size_t left, uint8_t *out);

/* Selection (preamble bit map for SEQUENCE OPTIONAL members).  We
 * encode a single byte. */
int     rdp_per_write_selection(struct rdp_buf *b, uint8_t bits);

/* Number-of-set 4-bit value (used for "number of sets" in GCC). */
int     rdp_per_write_numeric_string(struct rdp_buf *b,
		const char *s, size_t n);

/* Object identifier: writes a precomputed DER encoding because GCC's
 * OID is constant {0 0 20 124 0 1}, which the spec literally calls
 * out as a fixed sequence of bytes.  We provide a helper that emits
 * the canonical bytes. */
int     rdp_per_write_object_identifier_gcc(struct rdp_buf *b);
ssize_t rdp_per_read_object_identifier_gcc(const uint8_t *p, size_t left);

/* 16/32-bit aligned integers. */
int     rdp_per_write_u16(struct rdp_buf *b, uint16_t v);
int     rdp_per_write_u32(struct rdp_buf *b, uint32_t v);
ssize_t rdp_per_read_u16(const uint8_t *p, size_t left, uint16_t *out);
ssize_t rdp_per_read_u32(const uint8_t *p, size_t left, uint32_t *out);

/* Fixed-length octet string: just the bytes, no length prefix. */
int     rdp_per_write_octet_string(struct rdp_buf *b,
		const void *data, size_t n);

/* "Number of user data sets" is a constrained integer 1..256 minus 1,
 * encoded in a single byte (value = n-1). */
int     rdp_per_write_user_data_count(struct rdp_buf *b, uint8_t count);
ssize_t rdp_per_read_user_data_count(const uint8_t *p, size_t left,
		uint8_t *count_out);

/* H.221 non-standard parameter key: 4 octets ASCII (used by GCC to
 * tag the RDP-specific user-data blob: "Duca" in the request,
 * "McDn" in the response). */
int     rdp_per_write_h221_key(struct rdp_buf *b, const char key[4]);
ssize_t rdp_per_read_h221_key(const uint8_t *p, size_t left, char out[4]);

#endif /* RDP_PER_H */
