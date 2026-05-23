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
 * nla.h -- CredSSP / NLA server entry point.
 *
 * NLA performs authentication BEFORE any RDP session work, with
 * credentials encrypted under a key derived from the user's
 * NT hash.  For us to validate that, we need server-side access
 * to the NT hash via a backend such as winbind, sssd, or
 * smbpasswd.  This drop ships the wire-level CredSSP + NTLMv2
 * machinery; the actual hash-lookup hook is left for a follow-up
 * (see SECURITY.md).
 *
 * Until a hash backend is provided, `rdp_nla_server` parses the
 * client's NEGOTIATE/AUTHENTICATE, replies with a syntactically
 * valid CHALLENGE, then fails at the authInfo decryption step.
 * Operators should keep NLA disabled in production (the default)
 * and rely on the greeter + PAM/bsd_auth.
 */

#ifndef RDP_NLA_H
#define RDP_NLA_H

#include "../include/compat.h"

#include <stddef.h>

struct rdp_tls;

/* Run the NLA flow on an already-established TLS handle.  On
 * success (which requires a hash backend that isn't wired yet)
 * returns 0 and fills user/pass.  Returns -1 on any failure;
 * caller should drop the connection. */
int rdp_nla_server(struct rdp_tls *t,
		char *user, size_t user_size,
		char *pass, size_t pass_size);

#endif /* RDP_NLA_H */
