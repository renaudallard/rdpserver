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
 * cam_test.c -- MS-RDPECAM PDU build/parse.
 *
 * Checks the server-sent request byte layout, the parse of the client
 * response PDUs (including the UTF-16 + ASCII device notification and the
 * fixed-size record arrays), and rejection of truncated or malformed PDUs
 * (the bounds are covered by $(TEST_SAN)).
 */

#include "../../src/channels/cam.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...) do {                                \
	(void)fprintf(stderr, "fail: " __VA_ARGS__);  \
	(void)fputc('\n', stderr);                    \
	exit(1);                                       \
} while (0)

static uint32_t
ld32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
	    | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void
test_build(void)
{
	uint8_t out[64];
	ssize_t n;
	struct rdp_cam_media_type mt;

	n = rdp_cam_build_select_version_response(out, sizeof out, 2);
	if (n != 2 || out[0] != 0x02 || out[1] != 0x04)
		FAIL("select_version_response");

	n = rdp_cam_build_activate(out, sizeof out, 2);
	if (n != 2 || out[1] != 0x07) FAIL("activate");
	n = rdp_cam_build_deactivate(out, sizeof out, 2);
	if (n != 2 || out[1] != 0x08) FAIL("deactivate");
	n = rdp_cam_build_stream_list_request(out, sizeof out, 2);
	if (n != 2 || out[1] != 0x09) FAIL("stream_list_request");
	n = rdp_cam_build_stop_streams_request(out, sizeof out, 2);
	if (n != 2 || out[1] != 0x10) FAIL("stop_streams_request");
	n = rdp_cam_build_property_list_request(out, sizeof out, 2);
	if (n != 2 || out[1] != 0x14) FAIL("property_list_request");

	n = rdp_cam_build_media_type_list_request(out, sizeof out, 2, 1);
	if (n != 3 || out[1] != 0x0B || out[2] != 0x01)
		FAIL("media_type_list_request");
	n = rdp_cam_build_current_media_type_request(out, sizeof out, 2, 0);
	if (n != 3 || out[1] != 0x0D || out[2] != 0x00)
		FAIL("current_media_type_request");
	n = rdp_cam_build_sample_request(out, sizeof out, 2, 0);
	if (n != 3 || out[1] != 0x11 || out[2] != 0x00)
		FAIL("sample_request");

	/* StartStreamsRequest: header + 1-byte stream index + 26-byte type. */
	memset(&mt, 0, sizeof mt);
	mt.format = CAM_FORMAT_YUY2;
	mt.width = 640; mt.height = 480;
	mt.frame_rate_num = 30; mt.frame_rate_den = 1;
	mt.aspect_num = 0x11223344; mt.aspect_den = 0x55667788;
	mt.flags = 0;
	n = rdp_cam_build_start_streams_request(out, sizeof out, 2, 0, &mt);
	if (n != 29) FAIL("start_streams len %zd", (ssize_t)n);
	if (out[0] != 0x02 || out[1] != 0x0F) FAIL("start_streams header");
	if (out[2] != 0x00) FAIL("start_streams index");
	if (out[3] != CAM_FORMAT_YUY2) FAIL("start_streams format");
	if (ld32(out + 4) != 640) FAIL("start_streams width");
	if (ld32(out + 8) != 480) FAIL("start_streams height");
	if (ld32(out + 12) != 30) FAIL("start_streams fps num");
	if (ld32(out + 16) != 1) FAIL("start_streams fps den");
	if (ld32(out + 20) != 0x11223344) FAIL("start_streams aspect num");
	if (ld32(out + 24) != 0x55667788) FAIL("start_streams aspect den");
	if (out[28] != 0) FAIL("start_streams flags");

	/* NULL media type and too-small buffers are rejected. */
	if (rdp_cam_build_start_streams_request(out, sizeof out, 2, 0, NULL)
	    != -1) FAIL("start_streams null mt accepted");
	if (rdp_cam_build_select_version_response(out, 1, 2) != -1)
		FAIL("small-cap header accepted");
	if (rdp_cam_build_sample_request(out, 2, 2, 0) != -1)
		FAIL("small-cap stream-index accepted");
	if (rdp_cam_build_start_streams_request(out, 28, 2, 0, &mt) != -1)
		FAIL("small-cap start_streams accepted");
}

static void
test_parse(void)
{
	struct rdp_cam_msg m;

	/* SuccessResponse / SelectVersionRequest: header only. */
	{
		const uint8_t s[] = { 0x02, 0x01 };
		if (rdp_cam_parse(s, sizeof s, &m) != 0) FAIL("parse success");
		if (m.version != 2 || m.msg_id != CAM_MSG_SUCCESS_RESPONSE)
			FAIL("success fields");
	}
	/* ErrorResponse. */
	{
		const uint8_t e[] = { 0x02, 0x02, 0x07, 0x00, 0x00, 0x00 };
		if (rdp_cam_parse(e, sizeof e, &m) != 0) FAIL("parse error");
		if (m.error_code != CAM_ERR_OUT_OF_MEMORY) FAIL("error code");
	}
	/* DeviceAddedNotification: "Hi" UTF-16LE + "cam0" ASCII. */
	{
		const uint8_t d[] = {
			0x02, 0x05,
			'H', 0x00, 'i', 0x00, 0x00, 0x00,   /* DeviceName */
			'c', 'a', 'm', '0', 0x00            /* channel name */
		};
		if (rdp_cam_parse(d, sizeof d, &m) != 0) FAIL("parse added");
		if (m.device_name_len != 4) FAIL("device name len %zu",
		    m.device_name_len);
		if (m.channel_name_len != 4 ||
		    memcmp(m.channel_name, "cam0", 4) != 0) FAIL("channel name");
	}
	/* DeviceRemovedNotification. */
	{
		const uint8_t d[] = { 0x02, 0x06, 'c', 'a', 'm', '0', 0x00 };
		if (rdp_cam_parse(d, sizeof d, &m) != 0) FAIL("parse removed");
		if (m.channel_name_len != 4 ||
		    memcmp(m.channel_name, "cam0", 4) != 0)
			FAIL("removed channel name");
	}
	/* StreamListResponse: one 5-byte description. */
	{
		const uint8_t s[] = {
			0x02, 0x0A,
			0x01, 0x00, 0x01, 0x01, 0x00
		};
		if (rdp_cam_parse(s, sizeof s, &m) != 0) FAIL("parse streams");
		if (m.n_streams != 1) FAIL("n_streams %zu", m.n_streams);
		if (m.streams[0].frame_source_types != CAM_STREAM_SOURCE_COLOR)
			FAIL("stream source");
		if (m.streams[0].category != CAM_STREAM_CATEGORY_CAPTURE)
			FAIL("stream category");
		if (m.streams[0].selected != 1) FAIL("stream selected");
	}
	/* MediaTypeListResponse: two 26-byte descriptors. */
	{
		uint8_t s[2 + 2 * 26];
		size_t i;
		memset(s, 0, sizeof s);
		s[0] = 0x02; s[1] = 0x0C;
		s[2 + 0] = CAM_FORMAT_MJPG;       /* first format */
		s[2 + 1] = 0x80; s[2 + 2] = 0x02; /* width 640 */
		s[2 + 26 + 0] = CAM_FORMAT_YUY2;  /* second format */
		if (rdp_cam_parse(s, sizeof s, &m) != 0) FAIL("parse media");
		if (m.n_media_types != 2) FAIL("n_media %zu", m.n_media_types);
		if (m.media_types[0].format != CAM_FORMAT_MJPG) FAIL("media[0]");
		if (m.media_types[0].width != 640) FAIL("media[0] width %u",
		    m.media_types[0].width);
		if (m.media_types[1].format != CAM_FORMAT_YUY2) FAIL("media[1]");
		for (i = 0; i < m.n_media_types; i++)
			(void)i;
	}
	/* CurrentMediaTypeResponse: one 26-byte descriptor. */
	{
		uint8_t s[2 + 26];
		memset(s, 0, sizeof s);
		s[0] = 0x02; s[1] = 0x0E;
		s[2] = CAM_FORMAT_NV12;
		if (rdp_cam_parse(s, sizeof s, &m) != 0) FAIL("parse current");
		if (m.n_media_types != 1) FAIL("current n");
		if (m.media_types[0].format != CAM_FORMAT_NV12) FAIL("current fmt");
	}
	/* SampleResponse: stream index + raw frame. */
	{
		const uint8_t s[] = { 0x02, 0x12, 0x00, 'A', 'B', 'C', 'D' };
		if (rdp_cam_parse(s, sizeof s, &m) != 0) FAIL("parse sample");
		if (m.stream_index != 0) FAIL("sample index");
		if (m.sample_len != 4 || memcmp(m.sample, "ABCD", 4) != 0)
			FAIL("sample bytes");
	}
	/* SampleErrorResponse. */
	{
		const uint8_t s[] = { 0x02, 0x13, 0x00, 0x05, 0x00, 0x00, 0x00 };
		if (rdp_cam_parse(s, sizeof s, &m) != 0) FAIL("parse sample err");
		if (m.stream_index != 0 || m.error_code != CAM_ERR_INVALID_STREAM)
			FAIL("sample err fields");
	}
	/* PropertyValueResponse. */
	{
		const uint8_t s[] = { 0x02, 0x17, 0x02, 0x64, 0x00, 0x00, 0x00 };
		if (rdp_cam_parse(s, sizeof s, &m) != 0) FAIL("parse prop");
		if (m.property_mode != 2 || m.property_value != 100)
			FAIL("prop fields");
	}
}

static void
test_bad(void)
{
	struct rdp_cam_msg m;
	size_t i;

	/* Short header. */
	{
		const uint8_t s[] = { 0x02 };
		if (rdp_cam_parse(s, 0, &m) != -1) FAIL("empty accepted");
		if (rdp_cam_parse(s, 1, &m) != -1) FAIL("1-byte accepted");
	}
	/* Out-of-range message ids. */
	{
		const uint8_t lo[] = { 0x02, 0x00 };
		const uint8_t hi[] = { 0x02, 0x19 };
		if (rdp_cam_parse(lo, sizeof lo, &m) != -1) FAIL("id 0 accepted");
		if (rdp_cam_parse(hi, sizeof hi, &m) != -1) FAIL("id 0x19 ok");
	}
	/* ErrorResponse too short. */
	{
		const uint8_t s[] = { 0x02, 0x02, 0x00, 0x00 };
		if (rdp_cam_parse(s, sizeof s, &m) != -1) FAIL("short error ok");
	}
	/* DeviceAdded: no UTF-16 terminator. */
	{
		const uint8_t s[] = { 0x02, 0x05, 'H', 0x00, 'i', 0x00 };
		if (rdp_cam_parse(s, sizeof s, &m) != -1)
			FAIL("unterminated name accepted");
	}
	/* DeviceAdded: UTF-16 terminator but no ASCII NUL. */
	{
		const uint8_t s[] = { 0x02, 0x05, 0x00, 0x00, 'c', 'a', 'm' };
		if (rdp_cam_parse(s, sizeof s, &m) != -1)
			FAIL("unterminated channel accepted");
	}
	/* DeviceRemoved: no NUL. */
	{
		const uint8_t s[] = { 0x02, 0x06, 'c', 'a', 'm' };
		if (rdp_cam_parse(s, sizeof s, &m) != -1)
			FAIL("unterminated removed accepted");
	}
	/* DeviceAdded with an empty (immediately NUL) channel name. */
	{
		const uint8_t s[] = { 0x02, 0x05, 0x00, 0x00, 0x00 };
		if (rdp_cam_parse(s, sizeof s, &m) != -1)
			FAIL("empty channel name accepted");
	}
	/* DeviceRemoved with a leading NUL (empty name). */
	{
		const uint8_t s[] = { 0x02, 0x06, 0x00 };
		if (rdp_cam_parse(s, sizeof s, &m) != -1)
			FAIL("empty removed name accepted");
	}
	/* StreamListResponse too short for one 5-byte descriptor. */
	{
		const uint8_t s[] = { 0x02, 0x0A, 0x01, 0x00 };
		if (rdp_cam_parse(s, sizeof s, &m) != -1)
			FAIL("short stream list accepted");
	}
	/* CurrentMediaType: body shorter than a descriptor. */
	{
		uint8_t s[2 + 25];
		memset(s, 0, sizeof s);
		s[0] = 0x02; s[1] = 0x0E;
		if (rdp_cam_parse(s, sizeof s, &m) != -1)
			FAIL("short current media accepted");
	}
	/* SampleResponse without a stream index byte. */
	{
		const uint8_t s[] = { 0x02, 0x12 };
		if (rdp_cam_parse(s, sizeof s, &m) != -1)
			FAIL("empty sample accepted");
	}
	/* SampleErrorResponse too short. */
	{
		const uint8_t s[] = { 0x02, 0x13, 0x00, 0x05 };
		if (rdp_cam_parse(s, sizeof s, &m) != -1)
			FAIL("short sample err accepted");
	}
	/* A truncated MediaTypeListResponse (trailing partial record) keeps
	 * only the whole records and never over-reads. */
	{
		uint8_t s[2 + 26 + 10];
		memset(s, 0, sizeof s);
		s[0] = 0x02; s[1] = 0x0C;
		s[2] = CAM_FORMAT_I420;
		if (rdp_cam_parse(s, sizeof s, &m) != 0) FAIL("trailing media");
		if (m.n_media_types != 1) FAIL("trailing media count %zu",
		    m.n_media_types);
	}
	/* Header-only response with a zero-length body parses cleanly for
	 * every length from 2 up. */
	for (i = 2; i < 8; i++) {
		uint8_t s[8];
		memset(s, 0, sizeof s);
		s[0] = 0x02; s[1] = CAM_MSG_SUCCESS_RESPONSE;
		if (rdp_cam_parse(s, i, &m) != 0) FAIL("success len %zu", i);
	}
}

int
main(void)
{
	test_build();
	test_parse();
	test_bad();
	(void)printf("cam_test: all ok\n");
	return 0;
}
