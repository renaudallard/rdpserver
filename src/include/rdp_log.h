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
 * rdp_log.h -- logging interface.
 *
 * Production builds route through syslog(3); foreground/debug runs
 * write to stderr with a timestamped prefix.  Call rdp_log_init()
 * once at start-up and rdp_log_close() before exit.
 */

#ifndef RDP_LOG_H
#define RDP_LOG_H

#include <stdarg.h>

enum rdp_log_level {
	RDP_LOG_ERR   = 0,
	RDP_LOG_WARN  = 1,
	RDP_LOG_INFO  = 2,
	RDP_LOG_DEBUG = 3,
};

struct rdp_log_cfg {
	const char        *ident;     /* program name */
	int                foreground;/* 1: write to stderr; 0: syslog */
	enum rdp_log_level level;     /* messages above this are dropped */
};

void rdp_log_init(const struct rdp_log_cfg *cfg);
void rdp_log_close(void);
void rdp_log(enum rdp_log_level lvl, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
void rdp_vlog(enum rdp_log_level lvl, const char *fmt, va_list ap);

#define rdp_err(...)   rdp_log(RDP_LOG_ERR,   __VA_ARGS__)
#define rdp_warn(...)  rdp_log(RDP_LOG_WARN,  __VA_ARGS__)
#define rdp_info(...)  rdp_log(RDP_LOG_INFO,  __VA_ARGS__)
#define rdp_debug(...) rdp_log(RDP_LOG_DEBUG, __VA_ARGS__)

#endif /* RDP_LOG_H */
