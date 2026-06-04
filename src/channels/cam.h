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
 * cam.h -- MS-RDPECAM (Video Capture Virtual Channel) PDU build/parse.
 *
 * Two dynamic virtual channels carry the protocol.  The control channel
 * "RDCamera_Device_Enumerator" carries the SelectVersion handshake and the
 * DeviceAdded / DeviceRemoved notifications.  Each camera then gets its own
 * channel, named by the VirtualChannelName the client sends in its
 * DeviceAddedNotification, over which the server drives the device: Activate,
 * StreamList, MediaTypeList, StartStreams, then a stream of SampleResponse
 * frames.  Every PDU starts with a 2-byte header (Version u8, MessageId u8);
 * the server is the camera consumer, so it SENDS the *Request PDUs and
 * RECEIVES the *Response PDUs.  All multi-byte integers are little-endian.
 */
#ifndef RDP_CAM_H
#define RDP_CAM_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define CAM_ENUM_CHANNEL_NAME "RDCamera_Device_Enumerator"
#define CAM_PROTO_VERSION 0x02
#define CAM_HEADER_SIZE   2

/* Message IDs (CAM_SHARED_MSG_HEADER.MessageId, MS-RDPECAM 2.2.1.1). */
#define CAM_MSG_SUCCESS_RESPONSE            0x01
#define CAM_MSG_ERROR_RESPONSE              0x02
#define CAM_MSG_SELECT_VERSION_REQUEST      0x03
#define CAM_MSG_SELECT_VERSION_RESPONSE     0x04
#define CAM_MSG_DEVICE_ADDED                0x05
#define CAM_MSG_DEVICE_REMOVED              0x06
#define CAM_MSG_ACTIVATE_DEVICE_REQUEST     0x07
#define CAM_MSG_DEACTIVATE_DEVICE_REQUEST   0x08
#define CAM_MSG_STREAM_LIST_REQUEST         0x09
#define CAM_MSG_STREAM_LIST_RESPONSE        0x0A
#define CAM_MSG_MEDIA_TYPE_LIST_REQUEST     0x0B
#define CAM_MSG_MEDIA_TYPE_LIST_RESPONSE    0x0C
#define CAM_MSG_CURRENT_MEDIA_TYPE_REQUEST  0x0D
#define CAM_MSG_CURRENT_MEDIA_TYPE_RESPONSE 0x0E
#define CAM_MSG_START_STREAMS_REQUEST       0x0F
#define CAM_MSG_STOP_STREAMS_REQUEST        0x10
#define CAM_MSG_SAMPLE_REQUEST              0x11
#define CAM_MSG_SAMPLE_RESPONSE             0x12
#define CAM_MSG_SAMPLE_ERROR_RESPONSE       0x13
#define CAM_MSG_PROPERTY_LIST_REQUEST       0x14
#define CAM_MSG_PROPERTY_LIST_RESPONSE      0x15
#define CAM_MSG_PROPERTY_VALUE_REQUEST      0x16
#define CAM_MSG_PROPERTY_VALUE_RESPONSE     0x17
#define CAM_MSG_SET_PROPERTY_VALUE_REQUEST  0x18

/* Media formats (CAM_MEDIA_TYPE_DESCRIPTION.Format, MS-RDPECAM 2.2.1.3). */
#define CAM_FORMAT_H264   0x01
#define CAM_FORMAT_MJPG   0x02
#define CAM_FORMAT_YUY2   0x03
#define CAM_FORMAT_NV12   0x04
#define CAM_FORMAT_I420   0x05
#define CAM_FORMAT_RGB24  0x06
#define CAM_FORMAT_RGB32  0x07

/* Media type description flags. */
#define CAM_MT_FLAG_DECODING_REQUIRED 0x01
#define CAM_MT_FLAG_BOTTOM_UP_IMAGE   0x02

/* Stream description (CAM_STREAM_CATEGORY / source types). */
#define CAM_STREAM_SOURCE_COLOR    0x0001
#define CAM_STREAM_SOURCE_INFRARED 0x0002
#define CAM_STREAM_CATEGORY_CAPTURE 0x01

/* Error codes (CAM_ERROR_RESPONSE.ErrorCode, MS-RDPECAM 2.2.1.2). */
#define CAM_ERR_NONE              0x00000000u
#define CAM_ERR_UNEXPECTED        0x00000001u
#define CAM_ERR_INVALID_MESSAGE   0x00000002u
#define CAM_ERR_NOT_INITIALIZED   0x00000003u
#define CAM_ERR_INVALID_REQUEST   0x00000004u
#define CAM_ERR_INVALID_STREAM    0x00000005u
#define CAM_ERR_INVALID_MEDIA     0x00000006u
#define CAM_ERR_OUT_OF_MEMORY     0x00000007u
#define CAM_ERR_ITEM_NOT_FOUND    0x00000008u
#define CAM_ERR_SET_NOT_FOUND     0x00000009u
#define CAM_ERR_NOT_SUPPORTED     0x0000000Au

/* Parsed-response bounds.  A camera offers far fewer than these in practice;
 * extra records are reported via the truncation flags rather than over-read. */
#define CAM_MAX_STREAMS      8
#define CAM_MAX_MEDIA_TYPES  64

/* CAM_MEDIA_TYPE_DESCRIPTION (26 bytes on the wire). */
struct rdp_cam_media_type {
	uint8_t  format;
	uint32_t width;
	uint32_t height;
	uint32_t frame_rate_num;
	uint32_t frame_rate_den;
	uint32_t aspect_num;
	uint32_t aspect_den;
	uint8_t  flags;
};

/* CAM_STREAM_DESCRIPTION (5 bytes on the wire). */
struct rdp_cam_stream_desc {
	uint16_t frame_source_types;
	uint8_t  category;
	uint8_t  selected;
	uint8_t  can_be_shared;
};

/* One parsed inbound (client -> server) PDU.  Pointer/array fields that alias
 * the input (device_name, channel_name, sample) are valid only while the
 * source buffer is. */
struct rdp_cam_msg {
	uint8_t  version;
	uint8_t  msg_id;

	uint32_t error_code;     /* ERROR_RESPONSE, SAMPLE_ERROR_RESPONSE */
	uint8_t  stream_index;   /* SAMPLE_RESPONSE, SAMPLE_ERROR_RESPONSE */

	/* DEVICE_ADDED / DEVICE_REMOVED.  device_name is UTF-16LE (no
	 * terminator), channel_name is ASCII (no terminator). */
	const uint8_t *device_name;
	size_t         device_name_len;
	const char    *channel_name;
	size_t         channel_name_len;

	/* STREAM_LIST_RESPONSE. */
	struct rdp_cam_stream_desc streams[CAM_MAX_STREAMS];
	size_t n_streams;
	int    streams_truncated;

	/* MEDIA_TYPE_LIST_RESPONSE / CURRENT_MEDIA_TYPE_RESPONSE. */
	struct rdp_cam_media_type media_types[CAM_MAX_MEDIA_TYPES];
	size_t n_media_types;
	int    media_types_truncated;

	/* SAMPLE_RESPONSE: raw encoded frame, aliasing the input. */
	const uint8_t *sample;
	size_t         sample_len;

	/* PROPERTY_VALUE_RESPONSE. */
	uint8_t property_mode;
	int32_t property_value;
};

/* Parse one inbound PDU.  Returns 0 and fills *out on success, -1 on a
 * malformed or truncated PDU.  out is always zeroed first.
 *
 * The parser range-checks only the message id and the lengths; enum-valued
 * fields (media_types[].format and .flags, streams[].frame_source_types and
 * .category, error_code) are surfaced as the raw on-wire values.  Callers
 * MUST validate those against the CAM_FORMAT_* / CAM_MT_FLAG_* / CAM_STREAM_* /
 * CAM_ERR_* ranges before acting on them. */
int rdp_cam_parse(const uint8_t *p, size_t len, struct rdp_cam_msg *out);

/* Builders for the server-sent PDUs.  Each writes into out (cap bytes) and
 * returns the byte count, or -1 if cap is too small. */
ssize_t rdp_cam_build_select_version_response(uint8_t *out, size_t cap,
    uint8_t version);
ssize_t rdp_cam_build_activate(uint8_t *out, size_t cap, uint8_t version);
ssize_t rdp_cam_build_deactivate(uint8_t *out, size_t cap, uint8_t version);
ssize_t rdp_cam_build_stream_list_request(uint8_t *out, size_t cap,
    uint8_t version);
ssize_t rdp_cam_build_media_type_list_request(uint8_t *out, size_t cap,
    uint8_t version, uint8_t stream_index);
ssize_t rdp_cam_build_current_media_type_request(uint8_t *out, size_t cap,
    uint8_t version, uint8_t stream_index);
ssize_t rdp_cam_build_start_streams_request(uint8_t *out, size_t cap,
    uint8_t version, uint8_t stream_index,
    const struct rdp_cam_media_type *mt);
ssize_t rdp_cam_build_stop_streams_request(uint8_t *out, size_t cap,
    uint8_t version);
ssize_t rdp_cam_build_sample_request(uint8_t *out, size_t cap,
    uint8_t version, uint8_t stream_index);
ssize_t rdp_cam_build_property_list_request(uint8_t *out, size_t cap,
    uint8_t version);

#endif /* RDP_CAM_H */
