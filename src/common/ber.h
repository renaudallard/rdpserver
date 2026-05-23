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
 * ber.h -- ASN.1 BER encoding helpers, minimal subset for MCS.
 *
 * BER (Basic Encoding Rules, X.690) uses TLV.  This subset covers
 * what T.125 MCS Connect Initial / Connect Response need:
 *
 *  - Application tag (single byte for tag < 31, two bytes 0x?F TT
 *    for 31..127 -- in T.125 we only see tags 8, 10, 11, 14, 15,
 *    16, 25, 26, 8, 101, 102, so we encode the multi-byte form for
 *    >= 31).
 *  - Length: 1 byte for 0..127, 0x81+N for 128..2^(8N)-1.
 *  - INTEGER, BOOLEAN, OCTET STRING, SEQUENCE, ENUMERATED.
 *
 * All encoders write into a struct rdp_buf and return -1 if they
 * would overflow.  Decoders work over a const slice and advance an
 * "off" cursor.
 */

#ifndef RDP_BER_H
#define RDP_BER_H

#include "buf.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define RDP_BER_CLASS_UNIVERSAL    0x00
#define RDP_BER_CLASS_APPLICATION  0x40
#define RDP_BER_CLASS_CONTEXT      0x80
#define RDP_BER_CLASS_PRIVATE      0xC0
#define RDP_BER_PRIMITIVE          0x00
#define RDP_BER_CONSTRUCTED        0x20

#define RDP_BER_TAG_BOOLEAN       0x01
#define RDP_BER_TAG_INTEGER       0x02
#define RDP_BER_TAG_OCTET_STRING  0x04
#define RDP_BER_TAG_ENUMERATED    0x0a
#define RDP_BER_TAG_SEQUENCE      0x30  /* (universal 16 | constructed) */

/* Write a tag byte for tag number < 31 with given class/PC. */
int rdp_ber_write_tag(struct rdp_buf *b, uint8_t cls, uint8_t pc, uint8_t tag);

/* Write a multi-byte application tag (for tag >= 31).  Two-byte
 * form: 0x?F (class | pc | 0x1F), then 7-bit per byte big-endian
 * with continuation bit.  In T.125 we use this for tags 101, 102. */
int rdp_ber_write_app_tag(struct rdp_buf *b, uint8_t pc, uint32_t tag);

/* Write a length field.  Picks short or long form. */
int rdp_ber_write_length(struct rdp_buf *b, size_t length);

/* Combined helpers. */
int rdp_ber_write_universal(struct rdp_buf *b, uint8_t pc, uint8_t tag,
		size_t length);
int rdp_ber_write_integer(struct rdp_buf *b, uint32_t v);
int rdp_ber_write_boolean(struct rdp_buf *b, int v);
int rdp_ber_write_octet_string(struct rdp_buf *b, const void *data, size_t n);
int rdp_ber_write_enumerated(struct rdp_buf *b, uint8_t v);

/* Compute the number of bytes a length field would take. */
size_t rdp_ber_sizeof_length(size_t length);

/* Compute the size of the application tag for a given tag number. */
size_t rdp_ber_sizeof_app_tag(uint32_t tag);

/* Decoders.  Each returns the consumed byte count on success and
 * fills the out parameter, or -1 on malformed/truncated input. */
ssize_t rdp_ber_read_length(const uint8_t *p, size_t left, size_t *out);
ssize_t rdp_ber_read_app_tag(const uint8_t *p, size_t left, uint8_t pc,
		uint32_t tag, size_t *value_len_out);
ssize_t rdp_ber_read_universal_tag(const uint8_t *p, size_t left,
		uint8_t pc, uint8_t tag, size_t *value_len_out);
ssize_t rdp_ber_read_integer(const uint8_t *p, size_t left, uint32_t *out);
ssize_t rdp_ber_read_enumerated(const uint8_t *p, size_t left, uint8_t *out);
ssize_t rdp_ber_read_boolean(const uint8_t *p, size_t left, int *out);
ssize_t rdp_ber_read_octet_string(const uint8_t *p, size_t left,
		const uint8_t **data_out, size_t *len_out);

#endif /* RDP_BER_H */
