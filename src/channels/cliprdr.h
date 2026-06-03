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
 * cliprdr.h -- MS-RDPECLIP (Clipboard Virtual Channel) PDU builders
 * and parsers.  Text-only subset for v1; binary formats and the
 * file-copy path are deferred.
 *
 * CLIPRDR PDUs ride on a static virtual channel named "CLIPRDR"
 * (allocated by the client in CS_NET at MCS connect time).  Each
 * PDU is wrapped in CHANNEL_PDU_HEADER (MS-RDPBCGR 2.2.6.1.1):
 *
 *   u32 length    total uncompressed PDU bytes across fragments
 *   u32 flags     CHANNEL_FLAG_FIRST=0x1, CHANNEL_FLAG_LAST=0x2,
 *                 CHANNEL_FLAG_SHOW_PROTOCOL=0x10, ...
 *
 * The inner CLIPRDR header (MS-RDPECLIP 2.2.1) is:
 *
 *   u16 msgType
 *   u16 msgFlags
 *   u32 dataLen   payload bytes that follow this header
 *
 * v1 implements:
 *   CB_MONITOR_READY (server -> client, sent post-activation)
 *   CB_CLIP_CAPS     (both directions, negotiates long format names)
 *   CB_FORMAT_LIST   (both directions, announces available formats)
 *   CB_FORMAT_LIST_RESPONSE
 *   CB_FORMAT_DATA_REQUEST
 *   CB_FORMAT_DATA_RESPONSE
 *
 * v1 formats: CF_UNICODETEXT (13).  CF_TEXT (1) is recognised on
 * the inbound path and converted to UTF-8 before being passed to
 * the X11 side.
 */

#ifndef RDP_CLIPRDR_H
#define RDP_CLIPRDR_H

#include "../include/compat.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define CB_MONITOR_READY               0x0001
#define CB_FORMAT_LIST                 0x0002
#define CB_FORMAT_LIST_RESPONSE        0x0003
#define CB_FORMAT_DATA_REQUEST         0x0004
#define CB_FORMAT_DATA_RESPONSE        0x0005
#define CB_TEMP_DIRECTORY              0x0006
#define CB_CLIP_CAPS                   0x0007
#define CB_FILECONTENTS_REQUEST        0x0008
#define CB_FILECONTENTS_RESPONSE       0x0009
#define CB_LOCK_CLIPDATA               0x000A
#define CB_UNLOCK_CLIPDATA             0x000B

#define CB_RESPONSE_NONE 0x0000
#define CB_RESPONSE_OK   0x0001
#define CB_RESPONSE_FAIL 0x0002
#define CB_ASCII_NAMES   0x0004

#define CB_CAPSTYPE_GENERAL          0x0001
#define CB_CAPS_VERSION_1            0x00000001
#define CB_CAPS_VERSION_2            0x00000002
#define CB_USE_LONG_FORMAT_NAMES     0x00000002
#define CB_STREAM_FILECLIP_ENABLED   0x00000004
#define CB_FILECLIP_NO_FILE_PATHS    0x00000008
#define CB_CAN_LOCK_CLIPDATA         0x00000010

#define CF_TEXT          1
#define CF_OEMTEXT       7
#define CF_UNICODETEXT  13

/* Channel PDU header flags (MS-RDPBCGR 2.2.6.1.1). */
#define CHANNEL_FLAG_FIRST           0x00000001
#define CHANNEL_FLAG_LAST            0x00000002
#define CHANNEL_FLAG_SHOW_PROTOCOL   0x00000010

#define RDP_CLIPRDR_HDR_LEN 8

/* Builders.  Each writes into `out` (capacity `cap`) and returns the
 * total byte count, or -1 on overflow.  Caller wraps the result in
 * CHANNEL_PDU_HEADER + Send Data Indication + X.224 DT + TPKT before
 * writing to the TLS stream. */

ssize_t rdp_cliprdr_build_monitor_ready(uint8_t *out, size_t cap);
ssize_t rdp_cliprdr_build_clip_caps(uint8_t *out, size_t cap);
ssize_t rdp_cliprdr_build_format_list_response(uint8_t *out, size_t cap,
		int ok);
ssize_t rdp_cliprdr_build_format_list_unicode_text(uint8_t *out, size_t cap);
ssize_t rdp_cliprdr_build_format_data_request(uint8_t *out, size_t cap,
		uint32_t format_id);
ssize_t rdp_cliprdr_build_format_data_response(uint8_t *out, size_t cap,
		const void *data, size_t data_len, int ok);

/* Decoders. */

struct rdp_cliprdr_hdr {
	uint16_t msg_type;
	uint16_t msg_flags;
	uint32_t data_len;
};

int rdp_cliprdr_parse_hdr(const uint8_t *p, size_t len,
		struct rdp_cliprdr_hdr *out);

/* Parse a CB_FORMAT_LIST body (the bytes after the CLIPRDR header).
 * Sets *has_unicode_text / *has_text to 1 if those formats appear.
 * Honours the long-format-names path when use_long_names is true;
 * otherwise expects ASCII 32-byte format names. */
int rdp_cliprdr_parse_format_list(const uint8_t *p, size_t len,
		int use_long_names,
		int *has_unicode_text, int *has_text);

/* Parse a CB_FORMAT_DATA_REQUEST body.  Returns the requested
 * format id. */
int rdp_cliprdr_parse_format_data_request(const uint8_t *p, size_t len,
		uint32_t *format_id_out);

/*
 * Inbound virtual-channel reassembly (MS-RDPBCGR 2.2.6.1).  A CLIPRDR PDU
 * larger than one MCS Send Data payload arrives as a run of fragments,
 * each prefixed by a CHANNEL_PDU_HEADER carrying the total PDU length and
 * the CHANNEL_FLAG_FIRST / CHANNEL_FLAG_LAST bits.  Feed each fragment's
 * body; a complete PDU is returned for dispatch.  max_pdu bounds the
 * accumulator so a hostile peer cannot drive unbounded allocation.
 */
struct rdp_cliprdr_reasm {
	uint8_t *buf;
	size_t   cap;
	size_t   len;
	size_t   max_pdu;
	int      active;
};

void rdp_cliprdr_reasm_init(struct rdp_cliprdr_reasm *r, size_t max_pdu);
void rdp_cliprdr_reasm_reset(struct rdp_cliprdr_reasm *r);

/*
 * Feed one fragment body.  `total` is the CHANNEL_PDU_HEADER length field
 * (present on every fragment), `flags` its FIRST/LAST bits.  On a complete
 * PDU, sets *pdu / *pdu_len (valid until the next feed or reset) and
 * returns 1; the caller dispatches then calls reset.  Returns 0 when more
 * fragments are needed, or -1 on a malformed or oversize stream (the
 * accumulator is reset).  A single FIRST|LAST fragment is returned in
 * place with no copy.
 */
int rdp_cliprdr_reasm_feed(struct rdp_cliprdr_reasm *r,
		const uint8_t *frag, size_t frag_len,
		uint32_t total, uint32_t flags,
		const uint8_t **pdu, size_t *pdu_len);

#endif /* RDP_CLIPRDR_H */
