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
 * cam.c -- MS-RDPECAM (Video Capture Virtual Channel) PDU build/parse.
 */

#include "cam.h"

#include "../common/buf.h"

#include <string.h>

/* On-wire record sizes. */
#define CAM_STREAM_DESC_SIZE 5
#define CAM_MEDIA_TYPE_SIZE  26

/* ---- builders (server -> client) ------------------------------------- */

static ssize_t
build_header_only(uint8_t *out, size_t cap, uint8_t version, uint8_t msg_id)
{
	struct rdp_buf b;

	rdp_buf_init(&b, out, cap);
	if (rdp_buf_put_u8(&b, version) != 0) return -1;
	if (rdp_buf_put_u8(&b, msg_id) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

static ssize_t
build_stream_index(uint8_t *out, size_t cap, uint8_t version, uint8_t msg_id,
    uint8_t stream_index)
{
	struct rdp_buf b;

	rdp_buf_init(&b, out, cap);
	if (rdp_buf_put_u8(&b, version) != 0) return -1;
	if (rdp_buf_put_u8(&b, msg_id) != 0) return -1;
	if (rdp_buf_put_u8(&b, stream_index) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

/* Append one CAM_MEDIA_TYPE_DESCRIPTION (26 bytes). */
static int
put_media_type(struct rdp_buf *b, const struct rdp_cam_media_type *mt)
{
	if (rdp_buf_put_u8(b, mt->format) != 0) return -1;
	if (rdp_buf_put_u32le(b, mt->width) != 0) return -1;
	if (rdp_buf_put_u32le(b, mt->height) != 0) return -1;
	if (rdp_buf_put_u32le(b, mt->frame_rate_num) != 0) return -1;
	if (rdp_buf_put_u32le(b, mt->frame_rate_den) != 0) return -1;
	if (rdp_buf_put_u32le(b, mt->aspect_num) != 0) return -1;
	if (rdp_buf_put_u32le(b, mt->aspect_den) != 0) return -1;
	if (rdp_buf_put_u8(b, mt->flags) != 0) return -1;
	return 0;
}

ssize_t
rdp_cam_build_select_version_response(uint8_t *out, size_t cap, uint8_t version)
{
	return build_header_only(out, cap, version,
	    CAM_MSG_SELECT_VERSION_RESPONSE);
}

ssize_t
rdp_cam_build_activate(uint8_t *out, size_t cap, uint8_t version)
{
	return build_header_only(out, cap, version,
	    CAM_MSG_ACTIVATE_DEVICE_REQUEST);
}

ssize_t
rdp_cam_build_deactivate(uint8_t *out, size_t cap, uint8_t version)
{
	return build_header_only(out, cap, version,
	    CAM_MSG_DEACTIVATE_DEVICE_REQUEST);
}

ssize_t
rdp_cam_build_stream_list_request(uint8_t *out, size_t cap, uint8_t version)
{
	return build_header_only(out, cap, version,
	    CAM_MSG_STREAM_LIST_REQUEST);
}

ssize_t
rdp_cam_build_media_type_list_request(uint8_t *out, size_t cap,
    uint8_t version, uint8_t stream_index)
{
	return build_stream_index(out, cap, version,
	    CAM_MSG_MEDIA_TYPE_LIST_REQUEST, stream_index);
}

ssize_t
rdp_cam_build_current_media_type_request(uint8_t *out, size_t cap,
    uint8_t version, uint8_t stream_index)
{
	return build_stream_index(out, cap, version,
	    CAM_MSG_CURRENT_MEDIA_TYPE_REQUEST, stream_index);
}

ssize_t
rdp_cam_build_start_streams_request(uint8_t *out, size_t cap, uint8_t version,
    uint8_t stream_index, const struct rdp_cam_media_type *mt)
{
	struct rdp_buf b;

	if (mt == NULL) return -1;
	rdp_buf_init(&b, out, cap);
	if (rdp_buf_put_u8(&b, version) != 0) return -1;
	if (rdp_buf_put_u8(&b, CAM_MSG_START_STREAMS_REQUEST) != 0) return -1;
	/* One CAM_START_STREAM_INFO: StreamIndex + media type (27 bytes). */
	if (rdp_buf_put_u8(&b, stream_index) != 0) return -1;
	if (put_media_type(&b, mt) != 0) return -1;
	return (ssize_t)rdp_buf_used(&b);
}

ssize_t
rdp_cam_build_stop_streams_request(uint8_t *out, size_t cap, uint8_t version)
{
	return build_header_only(out, cap, version,
	    CAM_MSG_STOP_STREAMS_REQUEST);
}

ssize_t
rdp_cam_build_sample_request(uint8_t *out, size_t cap, uint8_t version,
    uint8_t stream_index)
{
	return build_stream_index(out, cap, version, CAM_MSG_SAMPLE_REQUEST,
	    stream_index);
}

ssize_t
rdp_cam_build_property_list_request(uint8_t *out, size_t cap, uint8_t version)
{
	return build_header_only(out, cap, version,
	    CAM_MSG_PROPERTY_LIST_REQUEST);
}

/* ---- parser (client -> server) --------------------------------------- */

static uint32_t
ld32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
	    | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t
ld16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* Parse the DeviceName (UTF-16LE) + VirtualChannelName (ASCII), both NUL
 * terminated and concatenated.  body points just past the 2-byte header. */
static int
parse_device_added(const uint8_t *body, size_t blen, struct rdp_cam_msg *out)
{
	size_t i, name_end;

	/* Scan for the UTF-16 NUL terminator (two zero bytes at an even
	 * offset). */
	name_end = (size_t)-1;
	for (i = 0; i + 1 < blen; i += 2) {
		if (body[i] == 0 && body[i + 1] == 0) {
			name_end = i;
			break;
		}
	}
	if (name_end == (size_t)-1) return -1;
	out->device_name = body;
	out->device_name_len = name_end;

	/* VirtualChannelName: ASCII NUL terminated, right after the UTF-16
	 * terminator. */
	{
		size_t cstart = name_end + 2;
		size_t cend = (size_t)-1;
		for (i = cstart; i < blen; i++) {
			if (body[i] == 0) { cend = i; break; }
		}
		if (cend == (size_t)-1) return -1;
		/* The channel name is the per-device DVC name the server must
		 * open, so an empty one is unusable; reject it like FreeRDP. */
		if (cend == cstart) return -1;
		out->channel_name = (const char *)(body + cstart);
		out->channel_name_len = cend - cstart;
	}
	return 0;
}

static int
parse_device_removed(const uint8_t *body, size_t blen, struct rdp_cam_msg *out)
{
	size_t i, cend = (size_t)-1;

	for (i = 0; i < blen; i++) {
		if (body[i] == 0) { cend = i; break; }
	}
	if (cend == (size_t)-1) return -1;
	if (cend == 0) return -1;        /* empty channel name is unusable */
	out->channel_name = (const char *)body;
	out->channel_name_len = cend;
	return 0;
}

static void
read_media_type(const uint8_t *p, struct rdp_cam_media_type *mt)
{
	mt->format         = p[0];
	mt->width          = ld32(p + 1);
	mt->height         = ld32(p + 5);
	mt->frame_rate_num = ld32(p + 9);
	mt->frame_rate_den = ld32(p + 13);
	mt->aspect_num     = ld32(p + 17);
	mt->aspect_den     = ld32(p + 21);
	mt->flags          = p[25];
}

int
rdp_cam_parse(const uint8_t *p, size_t len, struct rdp_cam_msg *out)
{
	const uint8_t *body;
	size_t blen;

	memset(out, 0, sizeof *out);
	if (len < CAM_HEADER_SIZE) return -1;
	out->version = p[0];
	out->msg_id = p[1];
	if (out->msg_id < CAM_MSG_SUCCESS_RESPONSE ||
	    out->msg_id > CAM_MSG_SET_PROPERTY_VALUE_REQUEST)
		return -1;
	body = p + CAM_HEADER_SIZE;
	blen = len - CAM_HEADER_SIZE;

	switch (out->msg_id) {
	case CAM_MSG_SUCCESS_RESPONSE:
	case CAM_MSG_SELECT_VERSION_REQUEST:
		return 0;                       /* header only */
	case CAM_MSG_ERROR_RESPONSE:
		if (blen < 4) return -1;
		out->error_code = ld32(body);
		return 0;
	case CAM_MSG_DEVICE_ADDED:
		return parse_device_added(body, blen, out);
	case CAM_MSG_DEVICE_REMOVED:
		return parse_device_removed(body, blen, out);
	case CAM_MSG_STREAM_LIST_RESPONSE: {
		size_t n, i;
		if (blen < CAM_STREAM_DESC_SIZE) return -1;  /* need one record */
		n = blen / CAM_STREAM_DESC_SIZE;
		if (n > CAM_MAX_STREAMS) {
			n = CAM_MAX_STREAMS;
			out->streams_truncated = 1;
		}
		for (i = 0; i < n; i++) {
			const uint8_t *r = body + i * CAM_STREAM_DESC_SIZE;
			out->streams[i].frame_source_types = ld16(r);
			out->streams[i].category = r[2];
			out->streams[i].selected = r[3];
			out->streams[i].can_be_shared = r[4];
		}
		out->n_streams = n;
		return 0;
	}
	case CAM_MSG_MEDIA_TYPE_LIST_RESPONSE: {
		size_t n = blen / CAM_MEDIA_TYPE_SIZE;
		size_t i;
		if (n > CAM_MAX_MEDIA_TYPES) {
			n = CAM_MAX_MEDIA_TYPES;
			out->media_types_truncated = 1;
		}
		for (i = 0; i < n; i++)
			read_media_type(body + i * CAM_MEDIA_TYPE_SIZE,
			    &out->media_types[i]);
		out->n_media_types = n;
		return 0;
	}
	case CAM_MSG_CURRENT_MEDIA_TYPE_RESPONSE:
		if (blen < CAM_MEDIA_TYPE_SIZE) return -1;
		read_media_type(body, &out->media_types[0]);
		out->n_media_types = 1;
		return 0;
	case CAM_MSG_SAMPLE_RESPONSE:
		if (blen < 1) return -1;
		out->stream_index = body[0];
		out->sample = body + 1;
		out->sample_len = blen - 1;
		return 0;
	case CAM_MSG_SAMPLE_ERROR_RESPONSE:
		if (blen < 5) return -1;
		out->stream_index = body[0];
		out->error_code = ld32(body + 1);
		return 0;
	case CAM_MSG_PROPERTY_VALUE_RESPONSE:
		if (blen < 5) return -1;
		out->property_mode = body[0];
		out->property_value = (int32_t)ld32(body + 1);
		return 0;
	case CAM_MSG_PROPERTY_LIST_RESPONSE:
		/* List of 19-byte descriptors; we do not drive properties, so
		 * the body is accepted but not decoded. */
		return 0;
	default:
		/* A valid id we do not expect from the client; header parsed. */
		return 0;
	}
}
