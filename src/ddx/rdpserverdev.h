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
#ifndef RDPSERVERDEV_H
#define RDPSERVERDEV_H

#include <xorg-server.h>
#include <xf86.h>
#include <damage.h>
#include <randrstr.h>

#define RDPSERVER_DRIVER_NAME  "rdpserverdev"
#define RDPSERVER_DEFAULT_W    1024
#define RDPSERVER_DEFAULT_H    768

struct rdpserver_dev {
	int                  width;
	int                  height;
	int                  stride;

	uint8_t             *fb;
	int                  shm_fd;
	size_t               shm_size;

	int                  ctrl_fd;

	DamagePtr            damage;
	Bool                 damage_registered;

	uint16_t             resize_w;
	uint16_t             resize_h;

	CloseScreenProcPtr               saved_CloseScreen;
	CreateScreenResourcesProcPtr     saved_CreateScreenResources;
	ScreenBlockHandlerProcPtr        saved_BlockHandler;
	ScreenWakeupHandlerProcPtr       saved_WakeupHandler;
};

struct rdpserver_dev *rdpserver_dev_from_screen(ScreenPtr pScreen);

#endif
