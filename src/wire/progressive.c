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
 * progressive.c -- CAPROGRESSIVE encoder.
 *
 * Pipeline: BGR -> YCbCr -> 64x64 tile -> CDF 9/7 DWT (3 levels)
 *           -> quantization -> linearization -> RLGR2 -> tile_simple
 *           -> region/frame wrapper.
 *
 * Wire structure (MS-RDPRFX 3.1.8):
 *   SYNC (0xCCC0) magic=0xCACCACCA version=0x0100
 *   CONTEXT (0xCCC3) ctxId=0 tileSize=64 flags=0
 *   FRAME_BEGIN (0xCCC1) frameIndex regionCount=1
 *   REGION (0xCCC4)
 *     tileSize=64 numRects numQuant=1 numProgQuant=0 flags=0
 *     numTiles tileDataSize
 *     RFX_RECT[numRects]
 *     RFX_COMPONENT_CODEC_QUANT[numQuant]
 *     TILE_SIMPLE (0xCCC5)[numTiles]
 *   FRAME_END (0xCCC2)
 */

#include "progressive.h"

#include <stdlib.h>
#include <string.h>

struct rdp_progressive {
	uint16_t width;
	uint16_t height;
	uint32_t frame_index;
	uint8_t *out_buf;
	size_t   out_cap;
	size_t   out_len;
};

struct rdp_progressive *
rdp_progressive_open(uint16_t width, uint16_t height)
{
	struct rdp_progressive *p = calloc(1, sizeof *p);
	if (p == NULL) return NULL;
	p->width = width;
	p->height = height;
	return p;
}

int
rdp_progressive_resize(struct rdp_progressive *p,
		uint16_t width, uint16_t height)
{
	if (p == NULL) return -1;
	p->width = width;
	p->height = height;
	return 0;
}

int
rdp_progressive_encode(struct rdp_progressive *p,
		const uint8_t *bgr, uint16_t width, uint16_t height,
		const uint8_t **out, size_t *out_len)
{
	(void)bgr; (void)width; (void)height;
	(void)p; (void)out; (void)out_len;
	/* TODO: DWT + quantization + RLGR2 + wire format. */
	return -1;
}

void
rdp_progressive_close(struct rdp_progressive *p)
{
	if (p == NULL) return;
	free(p->out_buf);
	free(p);
}
