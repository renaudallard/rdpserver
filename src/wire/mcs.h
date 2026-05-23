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
 * mcs.h -- T.125 MCS layer, RDP subset.
 *
 * MCS is a thin multipoint multiplexer.  RDP uses it to carry:
 *  - Connect Initial / Connect Response (BER-encoded application
 *    tagged sequences, with a GCC payload nested inside as PER).
 *  - Erect Domain Request, Attach User Request/Confirm, Channel
 *    Join Request/Confirm (T.125 DomainPDUs -- single-byte choice).
 *  - Send Data Request / Send Data Indication (carries an MCS user
 *    ID + channel ID + per-channel payload).
 *
 * After the Connect Initial/Response phase, every subsequent MCS
 * PDU starts with a single byte whose high 6 bits are the choice:
 *
 *   choice  meaning
 *   ------  --------------------------------------------
 *      1    Erect Domain Request          (byte 0x04)
 *      8    Disconnect Provider Ultimatum (byte 0x20)
 *     10    Attach User Request           (byte 0x28)
 *     11    Attach User Confirm           (byte 0x2c)
 *     14    Channel Join Request          (byte 0x38)
 *     15    Channel Join Confirm          (byte 0x3c)
 *     25    Send Data Request             (byte 0x64)
 *     26    Send Data Indication          (byte 0x68)
 *
 * RDP reserves these channel/user IDs by convention:
 *   1003   I/O channel (the "main" RDP channel)
 *   1004   first virtual channel allocated by the server
 *   1007   first user channel (assigned in Attach User Confirm)
 *
 * The server picks them; the client just echoes back via Channel
 * Join Request.
 */

#ifndef RDP_MCS_H
#define RDP_MCS_H

#include "../include/compat.h"
#include "../common/buf.h"

#include <stddef.h>
#include <stdint.h>

#define RDP_MCS_TYPE_ERECT_DOMAIN     0x04
#define RDP_MCS_TYPE_ATTACH_USER_REQ  0x28
#define RDP_MCS_TYPE_ATTACH_USER_CFM  0x2c
#define RDP_MCS_TYPE_CHANNEL_JOIN_REQ 0x38
#define RDP_MCS_TYPE_CHANNEL_JOIN_CFM 0x3c
#define RDP_MCS_TYPE_DISCONNECT       0x20
#define RDP_MCS_TYPE_SEND_DATA_REQ    0x64
#define RDP_MCS_TYPE_SEND_DATA_IND    0x68

/* RDP-conventional MCS IDs. */
#define RDP_MCS_IO_CHANNEL_ID       1003
#define RDP_MCS_GLOBAL_CHANNEL_ID   1003
#define RDP_MCS_USER_CHANNEL_BASE   1001
#define RDP_MCS_SERVER_USER_ID      1002

/* RDP Client Data Block (CS_*) and Server Data Block (SC_*) types
 * embedded inside GCC user data.  Each block is:
 *   uint16 type (LE)
 *   uint16 length (LE) -- includes header
 *   bytes  payload
 */
#define RDP_CS_CORE      0xC001
#define RDP_CS_SECURITY  0xC002
#define RDP_CS_NET       0xC003
#define RDP_CS_CLUSTER   0xC004
#define RDP_CS_MONITOR   0xC005
#define RDP_CS_MCS_MSGCHANNEL 0xC006
#define RDP_CS_MONITOR_EX     0xC008
#define RDP_CS_MULTITRANSPORT 0xC00A
#define RDP_SC_CORE      0x0C01
#define RDP_SC_SECURITY  0x0C02
#define RDP_SC_NET       0x0C03

/* Parsed contents of an MCS Connect Initial -- the bits we need. */
#define RDP_MCS_MAX_CHANNELS 32

struct rdp_mcs_channel_def {
	char     name[8];        /* zero-padded; not necessarily NUL-terminated */
	uint32_t options;
};

struct rdp_mcs_connect_initial {
	/* CS_CORE highlights. */
	uint32_t client_version;
	uint16_t desktop_width;
	uint16_t desktop_height;
	uint16_t color_depth;
	uint32_t keyboard_layout;
	uint32_t client_build;
	char     client_hostname[16];

	/* CS_SECURITY. */
	uint32_t encryption_methods;
	uint32_t ext_encryption_methods;

	/* CS_NET: requested virtual channels. */
	uint32_t                    channel_count;
	struct rdp_mcs_channel_def  channels[RDP_MCS_MAX_CHANNELS];

	/* CS_CLUSTER. */
	uint32_t cluster_flags;
	uint32_t redirected_session_id;
};

/* Build a MCS Connect Response into out (cap bytes), assigning the
 * supplied channel IDs to the requested channels and the I/O
 * channel.  Returns wire byte count or -1 on overflow. */
struct rdp_mcs_connect_response {
	uint16_t  io_channel_id;       /* almost always 1003 */
	uint16_t  user_channel_base;   /* almost always 1004 */
	uint16_t  channel_count;
	uint16_t  channel_ids[RDP_MCS_MAX_CHANNELS];
	uint32_t  encryption_method;   /* 0 when TLS is in use */
	uint32_t  encryption_level;    /* 0 when TLS is in use */
	uint16_t  requested_protocols; /* echoed from CS */
};

ssize_t rdp_mcs_parse_connect_initial(const uint8_t *p, size_t len,
		struct rdp_mcs_connect_initial *out);

ssize_t rdp_mcs_build_connect_response(uint8_t *out, size_t cap,
		const struct rdp_mcs_connect_response *r);

/* DomainPDU helpers (the byte-0x04, 0x28, etc. messages). */
ssize_t rdp_mcs_build_attach_user_confirm(uint8_t *out, size_t cap,
		uint16_t user_id);
ssize_t rdp_mcs_build_channel_join_confirm(uint8_t *out, size_t cap,
		uint16_t user_id, uint16_t channel_id);
ssize_t rdp_mcs_build_disconnect(uint8_t *out, size_t cap, uint8_t reason);

ssize_t rdp_mcs_parse_erect_domain(const uint8_t *p, size_t len);
ssize_t rdp_mcs_parse_attach_user_request(const uint8_t *p, size_t len);
ssize_t rdp_mcs_parse_channel_join_request(const uint8_t *p, size_t len,
		uint16_t *user_id_out, uint16_t *channel_id_out);
ssize_t rdp_mcs_parse_disconnect(const uint8_t *p, size_t len,
		uint8_t *reason_out);

/* Send Data envelope: 1 byte type | 2 BE user id | 2 BE channel id |
 * 1 byte flags (CHANNEL_FLAG_FIRST/LAST etc.) | length-determinant
 * | payload. */
ssize_t rdp_mcs_build_send_data_indication(uint8_t *out, size_t cap,
		uint16_t user_id, uint16_t channel_id,
		const void *payload, size_t payload_len);

ssize_t rdp_mcs_parse_send_data_request(const uint8_t *p, size_t len,
		uint16_t *user_id_out, uint16_t *channel_id_out,
		const uint8_t **payload_out, size_t *payload_len_out);

#endif /* RDP_MCS_H */
