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
 * rdpdr.h -- MS-RDPEFS device redirection (drives, printers, serial).
 *
 * Implements the RDPDR static virtual channel protocol:
 * Server Announce, Core Capabilities, Client ID Confirm,
 * Device List parsing, and IRP dispatch for drive file I/O.
 */

#ifndef RDP_RDPDR_H
#define RDP_RDPDR_H

#include "../include/compat.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* RDPDR packet header: component(u16) + packetId(u16) */
#define RDPDR_CTYP_CORE    0x4472
#define RDPDR_CTYP_PRN     0x5052

#define PAKID_CORE_SERVER_ANNOUNCE     0x496E
#define PAKID_CORE_CLIENTID_CONFIRM    0x4343
#define PAKID_CORE_CLIENT_NAME         0x434E
#define PAKID_CORE_DEVICE_LIST_ANNOUNCE 0x4441
#define PAKID_CORE_DEVICE_LIST_REMOVE  0x4452
#define PAKID_CORE_DEVICE_REPLY        0x6472
#define PAKID_CORE_DEVICE_IOREQUEST    0x4952
#define PAKID_CORE_DEVICE_IOCOMPLETION 0x4943
#define PAKID_CORE_SERVER_CAPABILITY   0x5350
#define PAKID_CORE_CLIENT_CAPABILITY   0x4350
#define PAKID_CORE_USER_LOGGEDON       0x554C

/* Device types */
#define RDPDR_DTYP_SERIAL    0x0001
#define RDPDR_DTYP_PARALLEL  0x0002
#define RDPDR_DTYP_PRINT     0x0004
#define RDPDR_DTYP_FILESYSTEM 0x0008
#define RDPDR_DTYP_SMARTCARD 0x0020

/* Capability types */
#define CAP_GENERAL_TYPE    0x0001
#define CAP_PRINTER_TYPE    0x0002
#define CAP_PORT_TYPE       0x0003
#define CAP_DRIVE_TYPE      0x0004
#define CAP_SMARTCARD_TYPE  0x0005

#define RDPDR_MAX_DEVICES 32

struct rdpdr_device {
	int      in_use;
	int      announced;   /* an FS_DEVICE was already sent to the session */
	uint32_t device_type;
	uint32_t device_id;
	char     name[9];
};

/* IRP header size: component(2)+packetId(2)+deviceId(4)+fileId(4)+
 * completionId(4)+majorFunction(4)+minorFunction(4) = 24 bytes. */
#define IRP_HDR_SIZE 24

/* IRP Major Function codes */
#define IRP_MJ_CREATE              0x00000000
#define IRP_MJ_CLOSE               0x00000002
#define IRP_MJ_READ                0x00000003
#define IRP_MJ_WRITE               0x00000004
#define IRP_MJ_QUERY_INFORMATION   0x00000005
#define IRP_MJ_SET_INFORMATION     0x00000006
#define IRP_MJ_DIRECTORY_CONTROL   0x0000000C
#define IRP_MJ_LOCK_CONTROL        0x00000011

/* IRP Minor Function codes for Directory Control */
#define IRP_MN_QUERY_DIRECTORY     0x00000001
#define IRP_MN_NOTIFY_CHANGE_DIRECTORY 0x00000002

/* File Information classes */
#define FileBasicInformation       0x00000004
#define FileStandardInformation    0x00000005
#define FileBothDirectoryInformation 0x00000003
#define FileRenameInformation      0x0000000A
#define FileDispositionInformation 0x0000000D
#define FileEndOfFileInformation   0x00000014

/* NTSTATUS codes */
#define STATUS_SUCCESS             0x00000000
#define STATUS_NO_MORE_FILES       0x80000006
#define STATUS_UNSUCCESSFUL        0xC0000001
#define STATUS_NOT_IMPLEMENTED     0xC0000002
#define STATUS_NO_SUCH_FILE        0xC000000F
#define STATUS_OBJECT_NAME_COLLISION 0xC0000035
#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034

/* CreateDisposition values */
#define FILE_SUPERSEDE             0x00000000
#define FILE_OPEN                  0x00000001
#define FILE_CREATE                0x00000002
#define FILE_OPEN_IF               0x00000003
#define FILE_OVERWRITE             0x00000004
#define FILE_OVERWRITE_IF          0x00000005

/* CreateOptions */
#define FILE_DIRECTORY_FILE        0x00000001
#define FILE_NON_DIRECTORY_FILE    0x00000040
#define FILE_DELETE_ON_CLOSE       0x00001000

/* DesiredAccess */
#define FILE_READ_DATA             0x00000001
#define FILE_WRITE_DATA            0x00000002
#define FILE_LIST_DIRECTORY        0x00000001
#define DELETE                     0x00010000

#define RDPDR_MAX_PENDING 64

struct rdpdr_pending {
	int       in_use;
	uint32_t  completion_id;
	uint32_t  device_id;
	uint32_t  major_function;
	uint32_t  be_req_id;
};

struct rdpdr_state {
	int      handshake_done;
	uint32_t client_id;
	uint16_t version_major;
	uint16_t version_minor;
	char     client_name[128];
	uint32_t device_count;
	struct rdpdr_device devices[RDPDR_MAX_DEVICES];
	uint32_t next_completion_id;
	uint32_t next_file_id;
	struct rdpdr_pending pending[RDPDR_MAX_PENDING];
};

/* Build the Server Announce Request PDU. */
ssize_t rdp_rdpdr_build_announce(uint8_t *out, size_t cap);

/* Build the Server Core Capability Request PDU. */
ssize_t rdp_rdpdr_build_caps(uint8_t *out, size_t cap);

/* Build the Server Client ID Confirm PDU. */
ssize_t rdp_rdpdr_build_clientid_confirm(uint8_t *out, size_t cap,
		uint32_t client_id);

/* Build the Server User Logged On PDU. */
ssize_t rdp_rdpdr_build_user_loggedon(uint8_t *out, size_t cap);

/* Build a Device Create Response (IRP completion). */
ssize_t rdp_rdpdr_build_device_reply(uint8_t *out, size_t cap,
		uint32_t device_id, uint32_t status);

/* Return the wire length of a single outbound RDPDR PDU. */
size_t rdp_rdpdr_pdu_len(uint16_t component, uint16_t packet_id,
		const uint8_t *pdu, size_t avail);

/* Build an IRP Create (open file) request. path is UTF-16LE. */
ssize_t rdp_rdpdr_build_irp_create(struct rdpdr_state *st,
		uint8_t *out, size_t cap,
		uint32_t device_id, const char *path,
		uint32_t desired_access, uint32_t disposition,
		uint32_t options, uint32_t *completion_id_out);

/* Build an IRP Read request. */
ssize_t rdp_rdpdr_build_irp_read(struct rdpdr_state *st,
		uint8_t *out, size_t cap,
		uint32_t device_id, uint32_t file_id,
		uint32_t length, uint64_t offset,
		uint32_t *completion_id_out);

/* Build an IRP Close request. */
ssize_t rdp_rdpdr_build_irp_close(struct rdpdr_state *st,
		uint8_t *out, size_t cap,
		uint32_t device_id, uint32_t file_id,
		uint32_t *completion_id_out);

/* Build an IRP QueryDirectory request. */
ssize_t rdp_rdpdr_build_irp_query_dir(struct rdpdr_state *st,
		uint8_t *out, size_t cap,
		uint32_t device_id, uint32_t file_id,
		const char *pattern, int initial,
		uint32_t *completion_id_out);

/* Build an IRP Write request. data points to data_len bytes written at
 * offset; both data and data_len are caller supplied. */
ssize_t rdp_rdpdr_build_irp_write(struct rdpdr_state *st,
		uint8_t *out, size_t cap,
		uint32_t device_id, uint32_t file_id,
		uint64_t offset, const uint8_t *data, size_t data_len,
		uint32_t *completion_id_out);

/* Build an IRP QueryInformation request for one FileInformation class.
 * No query buffer is sent (Length = 0). */
ssize_t rdp_rdpdr_build_irp_query_info(struct rdpdr_state *st,
		uint8_t *out, size_t cap,
		uint32_t device_id, uint32_t file_id,
		uint32_t info_class, uint32_t *completion_id_out);

/* Build an IRP SetInformation request. buf points to buf_len bytes of
 * the MS-FSCC FILE_*_INFORMATION structure for info_class; the worker
 * forwards it verbatim (the session builds it). */
ssize_t rdp_rdpdr_build_irp_set_info(struct rdpdr_state *st,
		uint8_t *out, size_t cap,
		uint32_t device_id, uint32_t file_id,
		uint32_t info_class, const uint8_t *buf, size_t buf_len,
		uint32_t *completion_id_out);

/* IO completion callback info. */
struct rdpdr_completion {
	uint32_t completion_id;
	uint32_t device_id;
	uint32_t major_function;
	uint32_t io_status;
	uint32_t be_req_id;
	const uint8_t *data;
	size_t   data_len;
};

/* Handle an inbound RDPDR PDU. Returns:
 *   0 = handled, may have response in resp_out
 *   1 = IO completion available in *comp
 *  <0 = error */
int rdp_rdpdr_handle(struct rdpdr_state *st,
		const uint8_t *pdu, size_t len,
		uint8_t *resp_out, size_t resp_cap, size_t *resp_len,
		struct rdpdr_completion *comp);

#endif
