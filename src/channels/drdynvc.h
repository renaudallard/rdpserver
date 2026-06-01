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
 * drdynvc.h -- Dynamic Virtual Channel (MS-RDPEDYC) + Display
 * Control Channel (MS-RDPEDISP) minimal implementation.
 *
 * We implement just enough DRDYNVC to accept xfreerdp's
 * /dynamic-resolution resize requests:
 *   - Server sends Capabilities (version 1) on the DRDYNVC static channel
 *   - Client sends Capabilities back
 *   - Client sends Create Request for "Microsoft::Windows::RDS::DisplayControl"
 *   - Server accepts (Create Response status 0)
 *   - Client sends Data PDUs with Display Update monitor layouts
 *   - Server parses and returns the new width/height
 */

#ifndef RDP_DRDYNVC_H
#define RDP_DRDYNVC_H

#include "../include/compat.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define DRDYNVC_CMD_CREATE       0x01
#define DRDYNVC_CMD_DATA_FIRST   0x02
#define DRDYNVC_CMD_DATA         0x03
#define DRDYNVC_CMD_CLOSE        0x04
#define DRDYNVC_CMD_CAPS         0x05

struct drdynvc_state {
	int      caps_exchanged;
	int      disp_channel_id;  /* -1 if not yet created */
	int      disp_create_pending; /* waiting for Create Response */
	int      gfx_channel_id;  /* -1 if not yet created */
	int      gfx_create_pending; /* waiting for Create Response */
	uint8_t *reasm_buf;
	size_t   reasm_cap;
	size_t   reasm_len;
	uint32_t reasm_total;
	int      reasm_chan;       /* channel being reassembled */
};

/* Build DRDYNVC Capabilities Request (version 1). */
ssize_t rdp_drdynvc_build_caps(uint8_t *out, size_t cap);

/* Build DRDYNVC Create Request for the GFX channel. */
ssize_t rdp_drdynvc_build_create_gfx(struct drdynvc_state *st,
		uint8_t *out, size_t cap);

/* Build DRDYNVC Create Request for the DisplayControl channel. */
ssize_t rdp_drdynvc_build_create_disp(struct drdynvc_state *st,
		uint8_t *out, size_t cap);

/* Build a DISPLAYCONTROL_CAPS_PDU (MS-RDPEDISP) inner payload. */
ssize_t rdp_drdynvc_build_disp_caps(uint8_t *out, size_t cap);

/* Process an inbound DRDYNVC PDU.  Returns:
 *   0 = handled, no resize
 *  >0 = resize requested; *new_w, *new_h set
 *  <0 = error
 * `resp_out` (capacity `resp_cap`) receives any response PDU to send
 * back (e.g., Create Response); `resp_len` is set to its length
 * (0 if none). */
/* Returns:
 *   0 = handled, no action needed
 *   1 = resize requested (new_w/new_h set)
 *   3 = GFX data arrived (gfx_data/gfx_len set)
 *  <0 = error */
int rdp_drdynvc_handle(struct drdynvc_state *st,
		const uint8_t *pdu, size_t len,
		uint8_t *resp_out, size_t resp_cap, size_t *resp_len,
		uint16_t *new_w, uint16_t *new_h,
		const uint8_t **gfx_data, size_t *gfx_len);

/* Free reassembly buffer and reset state. */
void rdp_drdynvc_cleanup(struct drdynvc_state *st);

#endif /* RDP_DRDYNVC_H */
