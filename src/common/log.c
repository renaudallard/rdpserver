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
 * log.c -- logging implementation.
 *
 * Two destinations: syslog(3) for production, stderr for foreground
 * runs and the regress suite.  rdp_log_init() picks one and the rest
 * of the program calls rdp_log() / rdp_debug() etc. without caring.
 */

#include "../include/rdp_log.h"
#include "../include/compat.h"

#include <syslog.h>
#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int               cfg_inited;
static int               cfg_foreground;
static enum rdp_log_level cfg_level = RDP_LOG_INFO;
static char              cfg_ident[32];

static int
to_syslog_pri(enum rdp_log_level lvl)
{
	switch (lvl) {
	case RDP_LOG_ERR:   return LOG_ERR;
	case RDP_LOG_WARN:  return LOG_WARNING;
	case RDP_LOG_INFO:  return LOG_INFO;
	case RDP_LOG_DEBUG: return LOG_DEBUG;
	}
	return LOG_INFO;
}

static const char *
level_tag(enum rdp_log_level lvl)
{
	switch (lvl) {
	case RDP_LOG_ERR:   return "err";
	case RDP_LOG_WARN:  return "warn";
	case RDP_LOG_INFO:  return "info";
	case RDP_LOG_DEBUG: return "debug";
	}
	return "info";
}

void
rdp_log_init(const struct rdp_log_cfg *cfg)
{
	cfg_foreground = cfg->foreground;
	cfg_level = cfg->level;
	if (cfg->ident != NULL) {
		(void)strncpy(cfg_ident, cfg->ident, sizeof cfg_ident - 1);
		cfg_ident[sizeof cfg_ident - 1] = '\0';
	} else {
		(void)strncpy(cfg_ident, "rdp", sizeof cfg_ident - 1);
	}
	if (!cfg_foreground)
		openlog(cfg_ident, LOG_PID | LOG_NDELAY, LOG_DAEMON);
	cfg_inited = 1;
}

void
rdp_log_close(void)
{
	if (!cfg_inited)
		return;
	if (!cfg_foreground)
		closelog();
	cfg_inited = 0;
}

#if defined(__clang__)
# pragma clang diagnostic ignored "-Wformat-nonliteral"
#elif defined(__GNUC__)
# pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif

void
rdp_vlog(enum rdp_log_level lvl, const char *fmt, va_list ap)
{
	if (!cfg_inited)
		return;
	if ((int)lvl > (int)cfg_level)
		return;

	if (cfg_foreground) {
		struct timespec ts;
		struct tm tm;
		char tbuf[32];

		(void)clock_gettime(CLOCK_REALTIME, &ts);
		(void)gmtime_r(&ts.tv_sec, &tm);
		(void)strftime(tbuf, sizeof tbuf,
			"%Y-%m-%dT%H:%M:%SZ", &tm);
		(void)fprintf(stderr, "%s %s[%s] ",
			tbuf, cfg_ident, level_tag(lvl));
		(void)vfprintf(stderr, fmt, ap);
		(void)fputc('\n', stderr);
		(void)fflush(stderr);
	} else {
		vsyslog(to_syslog_pri(lvl), fmt, ap);
	}
}

void
rdp_log(enum rdp_log_level lvl, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	rdp_vlog(lvl, fmt, ap);
	va_end(ap);
}
