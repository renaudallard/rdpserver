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
 * audio_coreaudio.c -- CoreAudio capture backend for rdp-session (macOS).
 *
 * Uses AudioQueue in recording mode to capture from the default
 * input device.  PCM format: 16-bit signed LE, stereo, 44100 Hz.
 *
 * For capturing system audio output (what apps play), macOS requires
 * a loopback driver like BlackHole or Soundflower set as the default
 * input. Without one, this captures microphone input.
 */

#include "audio.h"

#include "../include/compat.h"
#include "../include/rdp_log.h"

#if HAVE_COREAUDIO

#include <AudioToolbox/AudioToolbox.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define NUM_BUFFERS    3
#define BUFFER_SIZE    17640  /* 100ms at 44100 Hz stereo 16-bit */

struct rdp_audio {
	AudioQueueRef        queue;
	AudioQueueBufferRef  buffers[NUM_BUFFERS];
	uint8_t             *ring;
	size_t               ring_size;
	size_t               ring_write;
	size_t               ring_read;
	pthread_mutex_t      lock;
	int                  running;
};

static void
input_callback(void *user_data, AudioQueueRef queue,
    AudioQueueBufferRef buf, const AudioTimeStamp *start_time,
    UInt32 num_packets, const AudioStreamPacketDescription *descs)
{
	struct rdp_audio *a = user_data;
	size_t avail, len;

	(void)start_time;
	(void)num_packets;
	(void)descs;

	len = buf->mAudioDataByteSize;
	if (len == 0) goto requeue;

	pthread_mutex_lock(&a->lock);
	avail = a->ring_size - (a->ring_write - a->ring_read);
	if (len > avail)
		len = avail;
	if (len > 0) {
		size_t wpos = a->ring_write % a->ring_size;
		size_t first = a->ring_size - wpos;
		if (first > len) first = len;
		memcpy(a->ring + wpos, buf->mAudioData, first);
		if (len > first)
			memcpy(a->ring, (uint8_t *)buf->mAudioData + first,
			    len - first);
		a->ring_write += len;
	}
	pthread_mutex_unlock(&a->lock);

requeue:
	if (a->running)
		AudioQueueEnqueueBuffer(queue, buf, 0, NULL);
}

struct rdp_audio *
rdp_audio_open(void)
{
	struct rdp_audio *a;
	AudioStreamBasicDescription fmt;
	OSStatus err;
	int i;

	a = calloc(1, sizeof *a);
	if (a == NULL) return NULL;

	a->ring_size = BUFFER_SIZE * 8;
	a->ring = malloc(a->ring_size);
	if (a->ring == NULL) { free(a); return NULL; }
	pthread_mutex_init(&a->lock, NULL);

	memset(&fmt, 0, sizeof fmt);
	fmt.mSampleRate = 44100;
	fmt.mFormatID = kAudioFormatLinearPCM;
	fmt.mFormatFlags = kLinearPCMFormatFlagIsSignedInteger
	    | kLinearPCMFormatFlagIsPacked;
	fmt.mBitsPerChannel = 16;
	fmt.mChannelsPerFrame = 2;
	fmt.mBytesPerFrame = 4;
	fmt.mFramesPerPacket = 1;
	fmt.mBytesPerPacket = 4;

	err = AudioQueueNewInput(&fmt, input_callback, a, NULL,
	    kCFRunLoopCommonModes, 0, &a->queue);
	if (err != noErr) {
		rdp_warn("coreaudio: AudioQueueNewInput failed (%d)",
		    (int)err);
		free(a->ring);
		free(a);
		return NULL;
	}

	for (i = 0; i < NUM_BUFFERS; i++) {
		AudioQueueAllocateBuffer(a->queue, BUFFER_SIZE, &a->buffers[i]);
		AudioQueueEnqueueBuffer(a->queue, a->buffers[i], 0, NULL);
	}

	a->running = 1;
	err = AudioQueueStart(a->queue, NULL);
	if (err != noErr) {
		rdp_warn("coreaudio: AudioQueueStart failed (%d)", (int)err);
		AudioQueueDispose(a->queue, true);
		free(a->ring);
		free(a);
		return NULL;
	}

	rdp_info("coreaudio: recording 44100 Hz stereo 16-bit");
	return a;
}

ssize_t
rdp_audio_read(struct rdp_audio *a, void *buf, size_t len)
{
	size_t avail, rpos, first;

	if (a == NULL) return -1;

	pthread_mutex_lock(&a->lock);
	avail = a->ring_write - a->ring_read;
	if (avail < len) len = avail;
	if (len > 0) {
		rpos = a->ring_read % a->ring_size;
		first = a->ring_size - rpos;
		if (first > len) first = len;
		memcpy(buf, a->ring + rpos, first);
		if (len > first)
			memcpy((uint8_t *)buf + first, a->ring, len - first);
		a->ring_read += len;
	}
	pthread_mutex_unlock(&a->lock);

	return len > 0 ? (ssize_t)len : 0;
}

void
rdp_audio_close(struct rdp_audio *a)
{
	if (a == NULL) return;
	a->running = 0;
	if (a->queue != NULL) {
		AudioQueueStop(a->queue, true);
		AudioQueueDispose(a->queue, true);
	}
	pthread_mutex_destroy(&a->lock);
	free(a->ring);
	free(a);
}

#else /* !HAVE_COREAUDIO */

struct rdp_audio *rdp_audio_open(void) { return NULL; }
ssize_t rdp_audio_read(struct rdp_audio *a, void *b, size_t l)
{ (void)a; (void)b; (void)l; return -1; }
void rdp_audio_close(struct rdp_audio *a) { (void)a; }

#endif
