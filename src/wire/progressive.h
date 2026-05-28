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
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 */
/*
 * progressive.h -- CAPROGRESSIVE (MS-RDPRFX over MS-RDPEGFX) encoder.
 *
 * Mirrors the API of h264enc.h.  Encodes raw BGR/BGRX frames to
 * RFX_PROGRESSIVE_DATABLOCK chains suitable for embedding in a
 * WireToSurface1 PDU with codecId 0x0009.
 */

#ifndef RDP_PROGRESSIVE_H
#define RDP_PROGRESSIVE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct rdp_progressive;

/* Open an encoder for a desktop of width x height pixels. */
struct rdp_progressive *rdp_progressive_open(uint16_t width, uint16_t height);

/* Resize the encoder to new dimensions.  Returns 0 on success. */
int rdp_progressive_resize(struct rdp_progressive *p,
		uint16_t width, uint16_t height);

/* Encode one BGR24 top-down frame.  On success returns 0 and sets
 * *out / *out_len to an internal buffer valid until the next call. */
int rdp_progressive_encode(struct rdp_progressive *p,
		const uint8_t *bgr, uint16_t width, uint16_t height,
		const uint8_t **out, size_t *out_len);

void rdp_progressive_close(struct rdp_progressive *p);

#endif /* RDP_PROGRESSIVE_H */
