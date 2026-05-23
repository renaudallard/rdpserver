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
 * license.h -- Licensing PDU (MS-RDPELE) -- minimal subset.
 *
 * We answer every license exchange with "Valid Client" so clients
 * proceed without per-user licensing.  This is what xrdp does and
 * what most Linux RDP deployments want.
 */

#ifndef RDP_LICENSE_H
#define RDP_LICENSE_H

#include "../include/compat.h"

#include <stddef.h>
#include <sys/types.h>

#define RDP_LIC_PREAMBLE_VERSION_3_0  0x03
#define RDP_LIC_EXT_ERROR_MSG_SUPPORTED 0x80
#define RDP_LIC_MSGTYPE_ERROR_ALERT   0xff

#define RDP_LIC_ERROR_INVALID_CLIENT  0x00000008
#define RDP_LIC_STATUS_VALID_CLIENT   0x00000007
#define RDP_LIC_STATE_NO_TRANSITION   0x00000002

/* Build the "valid client" license alert into out.  This is the
 * complete PDU body (the SEC_LICENSE_PKT bit goes on the security
 * header outside this function).  Returns bytes written. */
ssize_t rdp_license_build_valid_client(uint8_t *out, size_t cap);

#endif /* RDP_LICENSE_H */
