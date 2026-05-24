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
 * rdpdr.c -- MS-RDPEFS device redirection protocol.
 */

#include "rdpdr.h"

#include "../include/rdp_log.h"
#include "../common/buf.h"

#include <string.h>

static uint16_t
ld16(const uint8_t *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t
ld32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
		| ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void
st16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v & 0xff);
	p[1] = (uint8_t)((v >> 8) & 0xff);
}

static void
st32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v & 0xff);
	p[1] = (uint8_t)((v >> 8) & 0xff);
	p[2] = (uint8_t)((v >> 16) & 0xff);
	p[3] = (uint8_t)((v >> 24) & 0xff);
}

ssize_t
rdp_rdpdr_build_announce(uint8_t *out, size_t cap)
{
	if (cap < 12) return -1;
	st16(out, RDPDR_CTYP_CORE);
	st16(out + 2, PAKID_CORE_SERVER_ANNOUNCE);
	st16(out + 4, 1);      /* versionMajor */
	st16(out + 6, 13);     /* versionMinor (0x000D = RDP 6.x) */
	st32(out + 8, 1);      /* clientId (server-assigned) */
	return 12;
}

ssize_t
rdp_rdpdr_build_caps(uint8_t *out, size_t cap)
{
	size_t off = 0;

	/* Header + numCapabilities(u16) + pad(u16) + capability sets */
	if (cap < 4 + 4 + 44 + 4 * 8) return -1;

	st16(out, RDPDR_CTYP_CORE);
	st16(out + 2, PAKID_CORE_SERVER_CAPABILITY);
	off = 4;

	st16(out + off, 5); off += 2;   /* numCapabilities */
	st16(out + off, 0); off += 2;   /* padding */

	/* General Capability Set: header(8) + data(32) = 40 bytes */
	st16(out + off, CAP_GENERAL_TYPE); off += 2;
	st16(out + off, 40); off += 2;  /* capabilityLength */
	st32(out + off, 1); off += 4;   /* version */
	st32(out + off, 1); off += 4;   /* osType: OS_TYPE_WINNT */
	st32(out + off, 0); off += 4;   /* osVersion */
	st16(out + off, 1); off += 2;   /* protocolMajor */
	st16(out + off, 13); off += 2;  /* protocolMinor */
	st32(out + off, 0xFFFF); off += 4; /* ioCode1 */
	st32(out + off, 0); off += 4;   /* ioCode2 */
	st32(out + off, 0x07); off += 4; /* extendedPDU */
	st32(out + off, 0); off += 4;   /* extraFlags1 */
	st32(out + off, 0); off += 4;   /* extraFlags2 */

	/* Printer Capability Set: header(8) only */
	st16(out + off, CAP_PRINTER_TYPE); off += 2;
	st16(out + off, 8); off += 2;
	st32(out + off, 1); off += 4;

	/* Port Capability Set */
	st16(out + off, CAP_PORT_TYPE); off += 2;
	st16(out + off, 8); off += 2;
	st32(out + off, 1); off += 4;

	/* Drive Capability Set */
	st16(out + off, CAP_DRIVE_TYPE); off += 2;
	st16(out + off, 8); off += 2;
	st32(out + off, 1); off += 4;

	/* Smartcard Capability Set */
	st16(out + off, CAP_SMARTCARD_TYPE); off += 2;
	st16(out + off, 8); off += 2;
	st32(out + off, 1); off += 4;

	return (ssize_t)off;
}

ssize_t
rdp_rdpdr_build_clientid_confirm(uint8_t *out, size_t cap,
		uint32_t client_id)
{
	if (cap < 12) return -1;
	st16(out, RDPDR_CTYP_CORE);
	st16(out + 2, PAKID_CORE_CLIENTID_CONFIRM);
	st16(out + 4, 1);       /* versionMajor */
	st16(out + 6, 13);      /* versionMinor */
	st32(out + 8, client_id);
	return 12;
}

ssize_t
rdp_rdpdr_build_user_loggedon(uint8_t *out, size_t cap)
{
	if (cap < 4) return -1;
	st16(out, RDPDR_CTYP_CORE);
	st16(out + 2, PAKID_CORE_USER_LOGGEDON);
	return 4;
}

ssize_t
rdp_rdpdr_build_device_reply(uint8_t *out, size_t cap,
		uint32_t device_id, uint32_t status)
{
	if (cap < 12) return -1;
	st16(out, RDPDR_CTYP_CORE);
	st16(out + 2, PAKID_CORE_DEVICE_REPLY);
	st32(out + 4, device_id);
	st32(out + 8, status);
	return 12;
}

static const char *
device_type_name(uint32_t dt)
{
	switch (dt) {
	case RDPDR_DTYP_SERIAL:     return "serial";
	case RDPDR_DTYP_PARALLEL:   return "parallel";
	case RDPDR_DTYP_PRINT:      return "printer";
	case RDPDR_DTYP_FILESYSTEM: return "drive";
	case RDPDR_DTYP_SMARTCARD:  return "smartcard";
	default: return "unknown";
	}
}

static int
handle_client_announce(struct rdpdr_state *st,
		const uint8_t *body, size_t blen)
{
	if (blen < 8) return -1;
	st->version_major = ld16(body);
	st->version_minor = ld16(body + 2);
	st->client_id = ld32(body + 4);
	rdp_info("rdpdr: client announce v%u.%u id=%u",
		(unsigned)st->version_major,
		(unsigned)st->version_minor,
		(unsigned)st->client_id);
	return 0;
}

static int
handle_client_name(struct rdpdr_state *st,
		const uint8_t *body, size_t blen)
{
	uint32_t unicode, name_len;
	if (blen < 12) return -1;
	unicode = ld32(body);
	name_len = ld32(body + 8);
	if (12 + name_len > blen)
		name_len = (uint32_t)(blen > 12 ? blen - 12 : 0);
	if (name_len > sizeof st->client_name - 1)
		name_len = sizeof st->client_name - 1;
	if (unicode) {
		uint32_t i;
		for (i = 0; i < name_len / 2 && i < sizeof st->client_name - 1; i++)
			st->client_name[i] = (char)body[12 + i * 2];
		st->client_name[i] = '\0';
	} else {
		memcpy(st->client_name, body + 12,
			name_len < sizeof st->client_name
				? name_len : sizeof st->client_name - 1);
		st->client_name[sizeof st->client_name - 1] = '\0';
	}
	rdp_info("rdpdr: client name '%s'", st->client_name);
	return 0;
}

static int
handle_device_list(struct rdpdr_state *st,
		const uint8_t *body, size_t blen,
		uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
	uint32_t count, i;
	size_t off = 0, roff = *resp_len;

	if (blen < 4) return -1;
	count = ld32(body);
	off = 4;
	rdp_info("rdpdr: device list: %u devices", (unsigned)count);

	for (i = 0; i < count && off + 20 <= blen; i++) {
		uint32_t dt = ld32(body + off);
		uint32_t did = ld32(body + off + 4);
		char name[9];
		uint32_t data_len;

		memcpy(name, body + off + 8, 8);
		name[8] = '\0';
		data_len = ld32(body + off + 16);
		if (data_len > blen - off - 20) break;
		off += 20 + data_len;

		rdp_info("rdpdr: device %u: type=%s id=%u name='%s'",
			i, device_type_name(dt), (unsigned)did, name);

		if (st->device_count < RDPDR_MAX_DEVICES) {
			struct rdpdr_device *d = &st->devices[st->device_count];
			d->in_use = 1;
			d->device_type = dt;
			d->device_id = did;
			memcpy(d->name, name, sizeof d->name);
			st->device_count++;
		}

		if (roff + 12 <= resp_cap) {
			ssize_t rn = rdp_rdpdr_build_device_reply(
				resp + roff, resp_cap - roff,
				did, 0);
			if (rn > 0) roff += (size_t)rn;
		}
	}
	*resp_len = roff;
	return 0;
}

static struct rdpdr_pending *
alloc_pending(struct rdpdr_state *st, uint32_t device_id,
		uint32_t major, uint32_t *cid_out)
{
	int i;
	for (i = 0; i < RDPDR_MAX_PENDING; i++) {
		if (!st->pending[i].in_use) {
			st->pending[i].in_use = 1;
			st->pending[i].completion_id = st->next_completion_id++;
			st->pending[i].device_id = device_id;
			st->pending[i].major_function = major;
			st->pending[i].be_req_id = 0;
			*cid_out = st->pending[i].completion_id;
			return &st->pending[i];
		}
	}
	return NULL;
}

static void
put_irp_header(uint8_t *out, uint32_t device_id, uint32_t file_id,
		uint32_t completion_id, uint32_t major, uint32_t minor)
{
	st16(out, RDPDR_CTYP_CORE);
	st16(out + 2, PAKID_CORE_DEVICE_IOREQUEST);
	st32(out + 4, device_id);
	st32(out + 8, file_id);
	st32(out + 12, completion_id);
	st32(out + 16, major);
	st32(out + 20, minor);
}

#define IRP_HDR_SIZE 24

ssize_t
rdp_rdpdr_build_irp_create(struct rdpdr_state *st,
		uint8_t *out, size_t cap,
		uint32_t device_id, const char *path,
		uint32_t desired_access, uint32_t disposition,
		uint32_t options, uint32_t *completion_id_out)
{
	uint32_t cid;
	size_t path_len = strlen(path);
	size_t upath_len = (path_len + 1) * 2;
	size_t total = IRP_HDR_SIZE + 32 + upath_len;
	size_t i, off;

	if (cap < total) return -1;
	if (alloc_pending(st, device_id, IRP_MJ_CREATE, &cid) == NULL)
		return -1;
	*completion_id_out = cid;

	memset(out, 0, total);
	put_irp_header(out, device_id, 0, cid, IRP_MJ_CREATE, 0);
	off = IRP_HDR_SIZE;
	st32(out + off, desired_access); off += 4;
	st32(out + off, 0); off += 4; st32(out + off, 0); off += 4;
	st32(out + off, 0x07); off += 4;
	st32(out + off, disposition); off += 4;
	st32(out + off, options); off += 4;
	st32(out + off, (uint32_t)upath_len); off += 4;
	st32(out + off, 0); off += 4;
	for (i = 0; i < path_len; i++) {
		out[off + i * 2] = (uint8_t)path[i];
		out[off + i * 2 + 1] = 0;
	}
	return (ssize_t)total;
}

ssize_t
rdp_rdpdr_build_irp_read(struct rdpdr_state *st,
		uint8_t *out, size_t cap,
		uint32_t device_id, uint32_t file_id,
		uint32_t length, uint64_t offset,
		uint32_t *completion_id_out)
{
	uint32_t cid;
	size_t total = IRP_HDR_SIZE + 32;

	if (cap < total) return -1;
	if (alloc_pending(st, device_id, IRP_MJ_READ, &cid) == NULL)
		return -1;
	*completion_id_out = cid;

	memset(out, 0, total);
	put_irp_header(out, device_id, file_id, cid, IRP_MJ_READ, 0);
	st32(out + IRP_HDR_SIZE, length);
	st32(out + IRP_HDR_SIZE + 4, (uint32_t)(offset & 0xFFFFFFFF));
	st32(out + IRP_HDR_SIZE + 8, (uint32_t)(offset >> 32));
	return (ssize_t)total;
}

ssize_t
rdp_rdpdr_build_irp_close(struct rdpdr_state *st,
		uint8_t *out, size_t cap,
		uint32_t device_id, uint32_t file_id,
		uint32_t *completion_id_out)
{
	uint32_t cid;
	size_t total = IRP_HDR_SIZE + 32;

	if (cap < total) return -1;
	if (alloc_pending(st, device_id, IRP_MJ_CLOSE, &cid) == NULL)
		return -1;
	*completion_id_out = cid;

	memset(out, 0, total);
	put_irp_header(out, device_id, file_id, cid, IRP_MJ_CLOSE, 0);
	return (ssize_t)total;
}

ssize_t
rdp_rdpdr_build_irp_query_dir(struct rdpdr_state *st,
		uint8_t *out, size_t cap,
		uint32_t device_id, uint32_t file_id,
		const char *pattern, int initial,
		uint32_t *completion_id_out)
{
	uint32_t cid;
	size_t plen = pattern ? strlen(pattern) : 0;
	size_t ulen = (plen + 1) * 2;
	size_t total = IRP_HDR_SIZE + 1 + 4 + ulen + 24;
	size_t off, i;

	if (cap < total) return -1;
	if (alloc_pending(st, device_id, IRP_MJ_DIRECTORY_CONTROL, &cid) == NULL)
		return -1;
	*completion_id_out = cid;

	memset(out, 0, total);
	put_irp_header(out, device_id, file_id, cid,
		IRP_MJ_DIRECTORY_CONTROL, IRP_MN_QUERY_DIRECTORY);
	off = IRP_HDR_SIZE;
	st32(out + off, FileBothDirectoryInformation); off += 4;
	out[off] = initial ? 1 : 0; off += 1;
	st32(out + off, (uint32_t)ulen); off += 4;
	memset(out + off, 0, 20); off += 20;
	for (i = 0; i < plen; i++) {
		out[off + i * 2] = (uint8_t)pattern[i];
		out[off + i * 2 + 1] = 0;
	}
	return (ssize_t)total;
}

size_t
rdp_rdpdr_pdu_len(uint16_t component, uint16_t packet_id,
		const uint8_t *pdu, size_t avail)
{
	(void)pdu;
	if (avail < 4) return 0;
	if (component != RDPDR_CTYP_CORE)
		return avail;
	switch (packet_id) {
	case PAKID_CORE_SERVER_ANNOUNCE:
	case PAKID_CORE_CLIENTID_CONFIRM:
		return 12;
	case PAKID_CORE_USER_LOGGEDON:
		return 4;
	case PAKID_CORE_DEVICE_REPLY:
		return 12;
	case PAKID_CORE_DEVICE_IOREQUEST:
		return avail;
	case PAKID_CORE_DEVICE_IOCOMPLETION:
		return avail;
	case PAKID_CORE_SERVER_CAPABILITY: {
		uint16_t ncaps, i;
		size_t off = 8;
		if (avail < 8) return avail;
		ncaps = ld16(pdu + 4);
		for (i = 0; i < ncaps && off + 4 <= avail; i++) {
			uint16_t clen = ld16(pdu + off + 2);
			if (clen < 4) clen = 4;
			off += clen;
		}
		return off;
	}
	default:
		return avail;
	}
}

int
rdp_rdpdr_handle(struct rdpdr_state *st,
		const uint8_t *pdu, size_t len,
		uint8_t *resp_out, size_t resp_cap, size_t *resp_len,
		struct rdpdr_completion *comp)
{
	uint16_t component, packet_id;

	*resp_len = 0;
	if (len < 4) return -1;

	component = ld16(pdu);
	packet_id = ld16(pdu + 2);

	if (component == RDPDR_CTYP_CORE) {
		switch (packet_id) {
		case PAKID_CORE_CLIENTID_CONFIRM:
			handle_client_announce(st, pdu + 4, len - 4);
			break;
		case PAKID_CORE_CLIENT_NAME:
			handle_client_name(st, pdu + 4, len - 4);
			{
				ssize_t n;
				n = rdp_rdpdr_build_caps(
					resp_out, resp_cap);
				if (n > 0) *resp_len = (size_t)n;
				n = rdp_rdpdr_build_clientid_confirm(
					resp_out + *resp_len,
					resp_cap - *resp_len,
					st->client_id);
				if (n > 0) *resp_len += (size_t)n;
			}
			break;
		case PAKID_CORE_CLIENT_CAPABILITY:
			rdp_debug("rdpdr: client capabilities received");
			st->handshake_done = 1;
			{
				ssize_t n;
				n = rdp_rdpdr_build_user_loggedon(
					resp_out + *resp_len,
					resp_cap - *resp_len);
				if (n > 0) *resp_len += (size_t)n;
			}
			break;
		case PAKID_CORE_DEVICE_LIST_ANNOUNCE:
			handle_device_list(st, pdu + 4, len - 4,
				resp_out, resp_cap, resp_len);
			break;
		case PAKID_CORE_DEVICE_LIST_REMOVE:
			rdp_debug("rdpdr: device list remove");
			break;
		case PAKID_CORE_DEVICE_IOCOMPLETION: {
			uint32_t did, cid, ios;
			int i;
			if (len < 4 + 12) break;
			did = ld32(pdu + 4);
			cid = ld32(pdu + 8);
			ios = ld32(pdu + 12);
			for (i = 0; i < RDPDR_MAX_PENDING; i++) {
				if (st->pending[i].in_use
				    && st->pending[i].completion_id == cid) {
					if (comp != NULL) {
						comp->completion_id = cid;
						comp->device_id = did;
						comp->major_function =
						    st->pending[i].major_function;
						comp->io_status = ios;
						comp->be_req_id =
						    st->pending[i].be_req_id;
						comp->data = pdu + 16;
						comp->data_len = len > 16
						    ? len - 16 : 0;
					}
					st->pending[i].in_use = 0;
					rdp_debug("rdpdr: completion cid=%u "
					    "status=0x%08x major=%u",
					    cid, ios,
					    (unsigned)st->pending[i]
						.major_function);
					return 1;
				}
			}
			rdp_warn("rdpdr: unknown completion cid=%u", cid);
			break;
		}
		default:
			rdp_debug("rdpdr: core packet 0x%04x",
				(unsigned)packet_id);
			break;
		}
	} else if (component == RDPDR_CTYP_PRN) {
		rdp_debug("rdpdr: printer packet 0x%04x",
			(unsigned)packet_id);
	} else {
		rdp_debug("rdpdr: unknown component 0x%04x",
			(unsigned)component);
	}
	return 0;
}
