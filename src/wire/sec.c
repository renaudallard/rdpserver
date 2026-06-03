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
 * sec.c -- security header and Client Info PDU.
 */

#include "sec.h"

#include "../common/utf16.h"
#include "../include/rdp_log.h"

#include <stdio.h>
#include <string.h>

ssize_t
rdp_sec_parse_header(const uint8_t *p, size_t len, uint32_t *flags_out)
{
	if (len < RDP_SEC_HDR_LEN) return -1;
	*flags_out = (uint32_t)p[0] | ((uint32_t)p[1] << 8);
	/* p[2..3] = flagsHi -- must be 0 for TLS-secured traffic, but
	 * some clients put junk there.  We just ignore it. */
	return RDP_SEC_HDR_LEN;
}

ssize_t
rdp_sec_build_header(uint8_t *out, size_t cap, uint32_t flags)
{
	if (cap < RDP_SEC_HDR_LEN) return -1;
	out[0] = (uint8_t)(flags & 0xff);
	out[1] = (uint8_t)((flags >> 8) & 0xff);
	out[2] = 0;
	out[3] = 0;
	return RDP_SEC_HDR_LEN;
}

/* Decode a UTF-16LE or ANSI string into UTF-8 in dst.  cb does NOT
 * include the trailing NUL (per spec) but the NUL bytes ARE present
 * on the wire and must be included in the offset advance.  We add
 * the implicit terminator size when stepping past. */
static int
decode_string(int unicode, const uint8_t *p, size_t cb,
		char *dst, size_t dsz)
{
	if (unicode) {
		size_t need = rdp_utf16le_to_utf8(dst, dsz - 1, p, cb);
		if (need == (size_t)-1)
			return -1;
		if (need >= dsz)
			need = dsz - 1;
		dst[need] = '\0';
		return 0;
	} else {
		size_t n = cb < dsz - 1 ? cb : dsz - 1;
		memcpy(dst, p, n);
		dst[n] = '\0';
		return 0;
	}
}

/* Format a POSIX TZ offset field (minutes, positive is west of UTC) as
 * "[-]H[:MM]". */
static void
tz_fmt_offset(char *b, size_t cap, int32_t min)
{
	int neg = min < 0;
	long a = neg ? -(long)min : min;
	unsigned hh = (unsigned)(a / 60);
	unsigned mm = (unsigned)(a % 60);
	if (mm != 0)
		(void)snprintf(b, cap, "%s%u:%02u", neg ? "-" : "", hh, mm);
	else
		(void)snprintf(b, cap, "%s%u", neg ? "-" : "", hh);
}

/* Format an ISO-8601-style bracketed zone label "<[+-]HH[MM]>" from a UTC
 * offset in minutes (positive is east of UTC).  POSIX accepts this
 * numeric form for the abbreviation, so no Windows-to-name table or real
 * abbreviation is needed. */
static void
tz_fmt_label(char *b, size_t cap, int32_t utc_min)
{
	int neg = utc_min < 0;
	long a = neg ? -(long)utc_min : utc_min;
	unsigned hh = (unsigned)(a / 60);
	unsigned mm = (unsigned)(a % 60);
	if (mm != 0)
		(void)snprintf(b, cap, "<%c%02u%02u>", neg ? '-' : '+', hh, mm);
	else
		(void)snprintf(b, cap, "<%c%02u>", neg ? '-' : '+', hh);
}

/* Format a POSIX transition time "H" or "H:MM". */
static void
tz_fmt_time(char *b, size_t cap, uint16_t h, uint16_t m)
{
	if (m != 0)
		(void)snprintf(b, cap, "%u:%02u", h, m);
	else
		(void)snprintf(b, cap, "%u", h);
}

#define TZ_OFF_LIMIT (14 * 60)   /* no real zone exceeds UTC +/- 14h */

int
rdp_tz_to_posix(int32_t bias, int32_t std_bias, int32_t dst_bias,
		const struct rdp_tz_systemtime *std,
		const struct rdp_tz_systemtime *dst,
		int have_name, char *out, size_t cap)
{
	char std_lbl[16], dst_lbl[16], std_o[12], dst_o[12], dt[12], st[12];
	char tmp[96];
	/* Sum in 64 bits: the biases are raw int32 from the wire, so a
	 * 32-bit add could overflow (undefined behavior) before the range
	 * check below.  After the check both fit comfortably in int32. */
	int64_t std_off = (int64_t)bias + std_bias;
	int64_t dst_off = (int64_t)bias + dst_bias;
	int meaningful, has_dst, n;

	if (cap == 0) return -1;
	out[0] = '\0';

	/* An all-zero block with no name is an unfilled field, not a real
	 * UTC client; leave the session in the server's zone. */
	meaningful = have_name || bias != 0
		|| std->month != 0 || dst->month != 0;
	if (!meaningful) return 0;
	/* Reject implausible offsets rather than emit a bogus TZ string. */
	if (std_off < -TZ_OFF_LIMIT || std_off > TZ_OFF_LIMIT
	    || dst_off < -TZ_OFF_LIMIT || dst_off > TZ_OFF_LIMIT)
		return 0;

	/* A usable DST rule needs both transitions with in-range fields. */
	has_dst = std->month >= 1 && std->month <= 12
		&& dst->month >= 1 && dst->month <= 12
		&& std->dow <= 6 && dst->dow <= 6
		&& std->day >= 1 && std->day <= 5
		&& dst->day >= 1 && dst->day <= 5
		&& std->hour <= 23 && dst->hour <= 23
		&& std->minute <= 59 && dst->minute <= 59;

	/* std_off/dst_off are within +/- TZ_OFF_LIMIT here, so narrowing to
	 * int32 for the formatters is value-preserving. */
	tz_fmt_label(std_lbl, sizeof std_lbl, (int32_t)-std_off);
	tz_fmt_offset(std_o, sizeof std_o, (int32_t)std_off);

	if (!has_dst) {
		n = snprintf(tmp, sizeof tmp, "%s%s", std_lbl, std_o);
	} else {
		tz_fmt_label(dst_lbl, sizeof dst_lbl, (int32_t)-dst_off);
		tz_fmt_offset(dst_o, sizeof dst_o, (int32_t)dst_off);
		tz_fmt_time(dt, sizeof dt, dst->hour, dst->minute);
		tz_fmt_time(st, sizeof st, std->hour, std->minute);
		/* POSIX: std<off>dst<off>,START(daylight),END(standard) */
		n = snprintf(tmp, sizeof tmp,
			"%s%s%s%s,M%u.%u.%u/%s,M%u.%u.%u/%s",
			std_lbl, std_o, dst_lbl, dst_o,
			dst->month, dst->day, dst->dow, dt,
			std->month, std->day, std->dow, st);
	}
	if (n < 0 || (size_t)n >= cap)
		return -1;
	memcpy(out, tmp, (size_t)n + 1);
	return n;
}

static uint16_t
tz_rd16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static int32_t
tz_rd32(const uint8_t *p)
{
	return (int32_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8)
		| ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

static void
tz_rd_systemtime(const uint8_t *p, struct rdp_tz_systemtime *t)
{
	/* TS_SYSTEMTIME: wYear(0) wMonth(2) wDayOfWeek(4) wDay(6)
	 * wHour(8) wMinute(10) wSecond(12) wMilliseconds(14). */
	t->month  = tz_rd16(p + 2);
	t->dow    = tz_rd16(p + 4);
	t->day    = tz_rd16(p + 6);
	t->hour   = tz_rd16(p + 8);
	t->minute = tz_rd16(p + 10);
}

int
rdp_client_info_parse(const uint8_t *p, size_t len,
		struct rdp_client_info *info,
		const uint8_t **pw_out, size_t *pw_len_out)
{
	size_t off = 0;
	uint16_t cbDomain, cbUserName, cbPassword, cbAltShell, cbWorkingDir;
	int unicode;
	size_t step;

	memset(info, 0, sizeof *info);
	if (pw_out) *pw_out = NULL;
	if (pw_len_out) *pw_len_out = 0;

	if (len < 18) return -1;
	info->codepage = (uint32_t)p[0] | ((uint32_t)p[1] << 8)
		| ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
	info->flags = (uint32_t)p[4] | ((uint32_t)p[5] << 8)
		| ((uint32_t)p[6] << 16) | ((uint32_t)p[7] << 24);
	cbDomain     = (uint16_t)p[8]  | ((uint16_t)p[9]  << 8);
	cbUserName   = (uint16_t)p[10] | ((uint16_t)p[11] << 8);
	cbPassword   = (uint16_t)p[12] | ((uint16_t)p[13] << 8);
	cbAltShell   = (uint16_t)p[14] | ((uint16_t)p[15] << 8);
	cbWorkingDir = (uint16_t)p[16] | ((uint16_t)p[17] << 8);
	off = 18;
	unicode = (info->flags & RDP_INFO_UNICODE) != 0;
	step = unicode ? 2 : 1;

	/* Each string is cbX bytes + an implicit terminator (2 for
	 * UTF-16LE, 1 for ANSI).  cbX does not include the terminator. */
	#define READ_STR(cb, field) do {                                \
		if (off + (cb) + step > len) return -1;                  \
		if (decode_string(unicode, p + off, (cb), (field),      \
				sizeof (field)) != 0)                            \
			return -1;                                          \
		off += (cb) + step;                                     \
	} while (0)

	READ_STR(cbDomain,   info->domain);
	READ_STR(cbUserName, info->username);

	if (off + cbPassword + step > len) return -1;
	if (cbPassword > 0) {
		info->have_password = 1;
		if (pw_out) *pw_out = p + off;
		if (pw_len_out) *pw_len_out = cbPassword;
	}
	off += cbPassword + step;

	READ_STR(cbAltShell,   info->alt_shell);
	READ_STR(cbWorkingDir, info->working_dir);

	#undef READ_STR

	/* Parse optional extraInfo area (MS-RDPBCGR 2.2.1.11.1.1.1).
	 * Walk past clientAddress, clientDir, clientTimeZone (172 bytes),
	 * clientSessionId (4), performanceFlags (4), then check for
	 * cbAutoReconnectLen + autoReconnectCookie. */
	info->have_arc = 0;
	{
		/* clientAddressFamily (2) + cbClientAddress (2) */
		if (off + 4 > len) return 0;
		{
			uint16_t cbAddr = (uint16_t)p[off + 2]
				| ((uint16_t)p[off + 3] << 8);
			off += 4 + cbAddr;
		}
		/* cbClientDir (2) + clientDir */
		if (off + 2 > len) return 0;
		{
			uint16_t cbDir = (uint16_t)p[off]
				| ((uint16_t)p[off + 1] << 8);
			off += 2 + cbDir;
		}
		/* clientTimeZone (TS_TIME_ZONE_INFORMATION, 172 bytes):
		 *   Bias(4) StandardName(64) StandardDate(16) StandardBias(4)
		 *   DaylightName(64) DaylightDate(16) DaylightBias(4).
		 * Decode it into a POSIX TZ string for the session; on a
		 * truncated PDU just leave the zone empty. */
		if (off + 172 <= len) {
			const uint8_t *tz = p + off;
			struct rdp_tz_systemtime sd, dd;
			int32_t bias = tz_rd32(tz + 0);
			int32_t std_bias = tz_rd32(tz + 84);
			int32_t dst_bias = tz_rd32(tz + 168);
			int have_name = (tz[4] | tz[5]) != 0;
			tz_rd_systemtime(tz + 68, &sd);   /* StandardDate */
			tz_rd_systemtime(tz + 152, &dd);  /* DaylightDate */
			(void)rdp_tz_to_posix(bias, std_bias, dst_bias,
				&sd, &dd, have_name,
				info->timezone, sizeof info->timezone);
		}
		/* clientTimeZone (172) + clientSessionId (4) + performanceFlags (4) */
		off += 172 + 4 + 4;
		if (off > len) return 0;
		/* cbAutoReconnectLen (2) */
		if (off + 2 > len) return 0;
		{
			uint16_t cbArc = (uint16_t)p[off]
				| ((uint16_t)p[off + 1] << 8);
			off += 2;
			if (cbArc == 28 && off + 28 <= len) {
				/* ARC_CS_PRIVATE_PACKET: cbLen(4) version(4)
				 * logonId(4) securityVerifier(16) */
				uint32_t arcVer;
				off += 4; /* cbLen */
				arcVer = (uint32_t)p[off]
					| ((uint32_t)p[off + 1] << 8)
					| ((uint32_t)p[off + 2] << 16)
					| ((uint32_t)p[off + 3] << 24);
				off += 4;
				if (arcVer == 1) {
					info->arc_logon_id =
						(uint32_t)p[off]
						| ((uint32_t)p[off + 1] << 8)
						| ((uint32_t)p[off + 2] << 16)
						| ((uint32_t)p[off + 3] << 24);
					off += 4;
					memcpy(info->arc_security_verifier,
						p + off, 16);
					info->have_arc = 1;
				}
			}
		}
	}
	return 0;
}
