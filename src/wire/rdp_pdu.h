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
 * rdp_pdu.h -- RDP share-control / share-data PDU framing and the
 * Phase A finalization PDUs.
 *
 * Every PDU after the activation handshake is wrapped in a Share
 * Control header (MS-RDPBCGR 2.2.8.1.1.1.1):
 *
 *   uint16  totalLength (LE, includes this header)
 *   uint16  pduType     (LE, low 4 bits type, high 4 bits version=1)
 *   uint16  pduSource   (LE, MCS user channel)
 *
 * "Data" PDUs (pduType=7) carry an additional Share Data header:
 *
 *   uint32  shareId
 *   uint8   pad1
 *   uint8   streamId
 *   uint16  uncompressedLength
 *   uint8   pduType2
 *   uint8   compressedType
 *   uint16  compressedLength
 */

#ifndef RDP_PDU_H
#define RDP_PDU_H

#include "../include/compat.h"

#include <stddef.h>
#include <sys/types.h>
#include <stdint.h>

#define RDP_PDU_TYPE_DEMAND_ACTIVE   1
#define RDP_PDU_TYPE_CONFIRM_ACTIVE  3
#define RDP_PDU_TYPE_DEACTIVATE_ALL  6
#define RDP_PDU_TYPE_DATA            7

#define RDP_PDU2_UPDATE              2
#define RDP_PDU2_CONTROL            20
#define RDP_PDU2_POINTER            27
#define RDP_PDU2_INPUT              28
#define RDP_PDU2_SYNCHRONIZE       31
#define RDP_PDU2_REFRESH_RECT      33
#define RDP_PDU2_FONTLIST          39
#define RDP_PDU2_FONTMAP           40
#define RDP_PDU2_SHUTDOWN_REQUEST  36
#define RDP_PDU2_SHUTDOWN_DENIED   37
#define RDP_PDU2_SAVE_SESSION_INFO 38

#define RDP_INFOTYPE_LOGON              0
#define RDP_INFOTYPE_LOGON_LONG         1
#define RDP_INFOTYPE_LOGON_PLAINNOTIFY  2
#define RDP_INFOTYPE_LOGON_EXTENDED     3

#define RDP_LOGON_EX_AUTORECONNECTCOOKIE 0x00000001

#define RDP_STREAM_LOW   1
#define RDP_STREAM_MED   2
#define RDP_STREAM_HIGH  4

#define RDP_CTRL_REQUEST_CONTROL 1
#define RDP_CTRL_GRANTED_CONTROL 2
#define RDP_CTRL_DETACH          3
#define RDP_CTRL_COOPERATE       4

#define RDP_SYNCMSGTYPE_SYNC     1

#define RDP_FONTLIST_FIRST       1
#define RDP_FONTLIST_LAST        2
#define RDP_FONTMAP_FIRST        1
#define RDP_FONTMAP_LAST         2

/* Build a share-control header into out for non-data PDUs.  Caller
 * fills in the body that follows.  Returns header size. */
ssize_t rdp_pdu_build_share_control(uint8_t *out, size_t cap,
		uint16_t pdu_type, uint16_t pdu_source,
		uint16_t total_length);

/* Build a share-data header into out for data PDUs.  total_length is
 * the size of the whole share control PDU (header + share data
 * header + body).  body_len is the body that follows the share
 * data header.  Returns the combined share control + share data
 * header size (18 bytes). */
ssize_t rdp_pdu_build_share_data(uint8_t *out, size_t cap,
		uint16_t pdu_source, uint32_t share_id,
		uint8_t  pdu_type2, uint16_t total_length);

/* Parse a share-control header.  Returns the bytes consumed (6).
 * Fills out the type, source, total length. */
ssize_t rdp_pdu_parse_share_control(const uint8_t *p, size_t len,
		uint16_t *pdu_type_out, uint16_t *pdu_source_out,
		uint16_t *total_length_out);

/* Parse a share-data header.  Returns the bytes consumed (12 -- the
 * portion AFTER the share control header). */
ssize_t rdp_pdu_parse_share_data(const uint8_t *p, size_t len,
		uint32_t *share_id_out, uint8_t *pdu_type2_out);

/* Finalization PDU builders.  Each writes a complete share control
 * (+ share data) PDU into out.  Caller wraps in MCS Send Data, then
 * X.224 DT, then TPKT. */
ssize_t rdp_pdu_build_synchronize(uint8_t *out, size_t cap,
		uint16_t pdu_source, uint32_t share_id,
		uint16_t target_user);

ssize_t rdp_pdu_build_control(uint8_t *out, size_t cap,
		uint16_t pdu_source, uint32_t share_id,
		uint16_t action, uint16_t grant_id, uint32_t control_id);

ssize_t rdp_pdu_build_font_map(uint8_t *out, size_t cap,
		uint16_t pdu_source, uint32_t share_id);

/* Convenience: parse the body of a Confirm Active (the share control
 * is already stripped).  Hands the inner cap-set blob to the caller. */
int rdp_pdu_extract_confirm_active(const uint8_t *p, size_t len,
		const uint8_t **caps_out, size_t *caps_len_out);

/* Build a Server Save Session Info PDU carrying the auto-reconnect
 * cookie (ARC_SC_PRIVATE_PACKET).  Returns total share-data PDU
 * bytes. */
ssize_t rdp_pdu_build_save_session_info_arc(uint8_t *out, size_t cap,
		uint16_t pdu_source, uint32_t share_id,
		uint32_t logon_id, const uint8_t arc_random[16]);

#endif /* RDP_PDU_H */
