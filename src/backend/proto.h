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
 * proto.h -- backend RPC: framing between the rdpd worker and the
 * per-user rdp-session helper.
 *
 * Transport: AF_UNIX SOCK_STREAM socket pair, set up by sessmgr at
 * SPAWN time.  We use STREAM (rather than SEQPACKET) so individual
 * messages can be larger than the kernel's SEQPACKET frame cap;
 * a full uncompressed 1280x720 frame is 2.6 MiB.
 *
 * Wire frame:
 *
 *   u32 type        (little-endian)
 *   u32 length      (little-endian, payload length excluding header)
 *   bytes payload   (length bytes)
 *
 * Messages, in conversational order:
 *
 *   HELLO_S2W   rdp-session announces its display mode to the worker
 *               (w, h, bpp).  Sent once at connect.
 *   FRAME       rdp-session -> worker.  Carries a rectangular pixel
 *               update in 24-bit BGR, bottom-up rows.  Worker tiles
 *               this into RDP fast-path bitmap updates.
 *   H264_FRAME  rdp-session -> worker.  Pre-encoded H.264 bitstream.
 *               Worker wraps it into RDPGFX AVC420 PDUs directly.
 *   INPUT_KEY   worker -> rdp-session.  Translated PC/AT scancode +
 *               down/up flag + extended flag.
 *   INPUT_MOUSE worker -> rdp-session.  Absolute pixel coordinates,
 *               button bitmap, modifier flags.
 *   BYE         either side announces clean shutdown.  No payload.
 */

#ifndef RDP_BACKEND_PROTO_H
#define RDP_BACKEND_PROTO_H

#include <stdint.h>

#define RDP_BE_HEADER 8

#define RDP_BE_HELLO_S2W    1u
#define RDP_BE_FRAME        2u
#define RDP_BE_INPUT_KEY    3u
#define RDP_BE_INPUT_MOUSE  4u
#define RDP_BE_BYE          5u
/* Clipboard.  All flow in both directions.  CLIP_OFFER announces
 * which formats are available; CLIP_REQUEST asks for one of them;
 * CLIP_DATA returns the bytes for that format.  Formats use a
 * bitmap: bit 0 = UTF-8 text. */
#define RDP_BE_CLIP_OFFER   6u
#define RDP_BE_CLIP_REQUEST 7u
#define RDP_BE_CLIP_DATA    8u
#define RDP_BE_RESIZE       9u
#define RDP_BE_AUDIO       10u

/* File system operations (session <-> worker for RDPDR drives).
 * Request: session sends FS_REQ with an rdp_be_fs_req header.
 * Response: worker sends FS_RSP with an rdp_be_fs_rsp header + data. */
#define RDP_BE_H264_FRAME  13u
#define RDP_BE_INPUT_UNICODE 14u
#define RDP_BE_CURSOR      15u   /* session -> worker */
#define RDP_BE_INPUT_SYNC  16u   /* worker -> session: lock-key state; 1..16 used */
#define RDP_BE_FS_DEVICE   17u   /* worker -> session: announce/remove a drive */

#define RDP_BE_FS_REQ      11u
#define RDP_BE_FS_RSP      12u

/* Clipboard file copy (session <-> worker).  The FileGroupDescriptorW
 * blob itself travels in a CLIP_DATA whose format is
 * RDP_BE_CLIP_FMT_FILES; these two carry the per-file content transfer.
 *   FILE_REQUEST  worker -> session: ask for one file's size or a byte
 *                 range, mirroring CB_FILECONTENTS_REQUEST.
 *   FILE_DATA     session -> worker: the requested bytes (or an 8-byte
 *                 size on a size request) with a status word. */
#define RDP_BE_CLIP_FILE_REQUEST 18u  /* worker -> session */
#define RDP_BE_CLIP_FILE_DATA    19u  /* session -> worker */

/* Printer redirection (MS-RDPEPC).
 *   PRINTER_DEVICE  worker -> session: a redirected printer was announced in
 *                   the RDPDR device list.  Carries the parsed printer/driver
 *                   names and a default flag so the session can create the
 *                   matching CUPS queue.
 *   PRINT_JOB       session -> worker: raw spool bytes to print on a
 *                   redirected printer.  The worker drives the MS-RDPEPC
 *                   CREATE/WRITE.../CLOSE IRP sequence to the device. */
#define RDP_BE_PRINTER_DEVICE 20u  /* worker -> session */
#define RDP_BE_PRINT_JOB      21u  /* session -> worker */

/* Microphone input redirection (MS-RDPEAI).
 *   AUDIO_INPUT  worker -> session: a chunk of captured microphone PCM the
 *                client sent over the AUDIO_INPUT dynamic virtual channel.
 *                The payload is the raw samples in the negotiated capture
 *                format, PCM s16le stereo 44100 Hz by default; no header.
 *                The worker caps one chunk at RDP_BE_AUDIO_INPUT_MAX. */
#define RDP_BE_AUDIO_INPUT    22u  /* worker -> session */

/* Multitouch / pen input redirection (MS-RDPEI).
 *   INPUT_TOUCH  worker -> session: one or more touch/pen contacts the client
 *                sent over the "Microsoft::Windows::RDS::Input" dynamic virtual
 *                channel.  The payload is a struct rdp_be_input_touch header
 *                followed by `count` struct rdp_be_touch_contact records.  The
 *                worker caps count at RDPEI_MAX_CONTACTS (64). */
#define RDP_BE_INPUT_TOUCH    23u  /* worker -> session */

/* RemoteApp window geometry (MS-RDPERP).
 *   WINDOW  session -> worker: a RemoteApp window was created/moved/resized
 *           (op CREATE) or closed (op DELETE).  The worker turns it into a
 *           Window Information drawing order for the client.  A CREATE
 *           payload is a struct rdp_be_window followed by title_len bytes
 *           of UTF-16LE title. */
#define RDP_BE_WINDOW          24u  /* session -> worker */
#define RDP_BE_WINDOW_OP_CREATE 0u
#define RDP_BE_WINDOW_OP_DELETE 1u

/* Upper bound on the PCM bytes the worker forwards in one AUDIO_INPUT
 * message.  A client Data PDU larger than this is split into multiple
 * AUDIO_INPUT messages so a single chunk stays bounded. */
#define RDP_BE_AUDIO_INPUT_MAX (64u * 1024u)

#define RDP_FS_OPEN        1u
#define RDP_FS_READ        2u
#define RDP_FS_WRITE       3u
#define RDP_FS_CLOSE       4u
#define RDP_FS_LIST        5u
#define RDP_FS_QUERY_INFO  6u
#define RDP_FS_SET_INFO    7u

/* Upper bound on the trailing FS_REQ payload (write data / SetBuffer /
 * path) the worker will accept from the untrusted session. */
#define RDP_BE_FS_MAX_PAYLOAD (4u * 1024u * 1024u)

/*
 * FS request header (session -> worker), followed by a per-op variable
 * payload of `payload_len` bytes.  req_id is the correlation key echoed
 * back in rdp_be_fs_rsp.req_id.  Fields used per op:
 *
 *   RDP_FS_OPEN       device_id; desired_access, disposition, options
 *                     (the worker substitutes its read defaults when a
 *                     field is 0); payload = UTF-8 path.
 *   RDP_FS_READ       device_id, file_id, length, offset; no payload.
 *   RDP_FS_WRITE      device_id, file_id, offset; payload = raw write
 *                     data (its length is payload_len, not `length`).
 *   RDP_FS_CLOSE      device_id, file_id; no payload.
 *   RDP_FS_LIST       device_id, file_id; payload = UTF-8 search
 *                     pattern (empty means "*").
 *   RDP_FS_QUERY_INFO device_id, file_id, info_class; no payload.
 *   RDP_FS_SET_INFO   device_id, file_id, info_class; payload = the
 *                     MS-FSCC SetBuffer for info_class, forwarded
 *                     verbatim (for rename this is the
 *                     FileRenameInformation including the UTF-16LE
 *                     target path, which the session builds).
 *
 * payload_len is the byte count of the trailing payload and must equal
 * the FS_REQ frame length minus sizeof(struct rdp_be_fs_req); the
 * worker bounds it against the received frame.
 */
struct rdp_be_fs_req {
	uint32_t req_id;          /* correlation key */
	uint32_t op;             /* RDP_FS_* */
	uint32_t device_id;      /* target RDPDR device */
	uint32_t file_id;        /* open handle; 0 for OPEN */
	uint32_t desired_access; /* OPEN: NT DesiredAccess (0 = default) */
	uint32_t disposition;    /* OPEN: NT CreateDisposition (0 = default) */
	uint32_t options;        /* OPEN: NT CreateOptions */
	uint32_t info_class;     /* QUERY_INFO/SET_INFO: FileInformation class */
	uint32_t length;         /* READ: bytes to read */
	uint32_t payload_len;    /* trailing payload byte count */
	uint64_t offset;         /* READ/WRITE: file offset */
};

struct rdp_be_fs_rsp {
	uint32_t req_id;
	uint32_t status;
	uint32_t file_id;
	uint32_t length;
};

/* FS_DEVICE payload (worker -> session): announce or remove one RDPDR
 * file system device.  added=1 announces a drive (the session creates a
 * top-level directory node for it); added=0 removes it.  name is the
 * 8-byte client drive label plus a NUL.  pad rounds the struct to a
 * clean 20 bytes and is sent zeroed. */
struct rdp_be_fs_device {
	uint32_t device_id;
	uint32_t device_type;
	uint8_t  added;       /* 1 = announce, 0 = remove */
	char     name[9];
	uint8_t  pad[2];
};

/* PRINTER_DEVICE payload (worker -> session): announce one redirected
 * printer parsed from the RDPDR device list.  name and driver are the
 * UTF-8 printer name and Windows driver name from the client's announce,
 * NUL terminated.  flags bit 0 (RDP_BE_PRINTER_FLAG_DEFAULT) marks the
 * client's default printer. */
#define RDP_BE_PRINTER_FLAG_DEFAULT 0x00000001u
struct rdp_be_printer_device {
	uint32_t device_id;
	uint32_t flags;
	char     name[128];
	char     driver[128];
};

/* PRINT_JOB payload (session -> worker): a small fixed header followed by
 * the raw spool bytes to print on device_id.  The spool bytes are the
 * trailing payload (frame length minus sizeof the header), bounded by the
 * worker at RDP_BE_PRINT_JOB_MAX_SPOOL.  One PRINT_JOB carries one complete
 * job; the session must keep a single job within that cap. */
struct rdp_be_print_job_hdr {
	uint32_t device_id;
};

/* Upper bound on the spool bytes the worker accepts in one PRINT_JOB, the
 * same 4 MiB ceiling the clip and FS write paths use. */
#define RDP_BE_PRINT_JOB_MAX_SPOOL (4u * 1024u * 1024u)

/* Semantic clipboard formats carried over the backend.  CLIP_OFFER is a
 * bitmap of these; CLIP_REQUEST and the CLIP_DATA header select one.  For
 * TEXT the data bytes are UTF-8; for IMAGE they are a BMP file byte
 * stream; for HTML they are the raw HTML fragment (UTF-8), not the
 * Windows CF_HTML envelope (the worker adds/strips that). */
#define RDP_BE_CLIP_FMT_TEXT  0x00000001u
#define RDP_BE_CLIP_FMT_IMAGE 0x00000002u
#define RDP_BE_CLIP_FMT_HTML  0x00000004u
/* FILES: the CLIP_DATA bytes are a FileGroupDescriptorW blob (built by the
 * session with rdp_cliprdr_build_file_list); the file contents move over
 * the FILE_REQUEST/FILE_DATA pair below. */
#define RDP_BE_CLIP_FMT_FILES 0x00000008u

/* Hello payload (8 bytes). */
struct rdp_be_hello {
	uint16_t width;
	uint16_t height;
	uint16_t bpp;
	uint16_t reserved;
};

/* Frame payload header (8 bytes) followed by w*h*3 bytes BGR. */
struct rdp_be_frame_hdr {
	uint16_t x;
	uint16_t y;
	uint16_t w;
	uint16_t h;
};

/* H.264-encoded frame payload header (12 bytes) followed by h264_len
 * bytes of compressed H.264 bitstream. */
struct rdp_be_h264_frame_hdr {
	uint16_t x;
	uint16_t y;
	uint16_t w;
	uint16_t h;
	uint32_t h264_len;
};

/* Key event payload (8 bytes). */
struct rdp_be_input_key {
	uint16_t scancode;
	uint8_t  down;       /* 1 = press, 0 = release */
	uint8_t  extended;   /* PC/AT E0 prefix */
	uint8_t  pad[4];
};

/* Unicode key event payload (8 bytes).  Carries a Unicode scalar
 * value; the session injects it by remapping a spare X keycode to the
 * matching keysym.  Only presses are forwarded (down is always 1). */
struct rdp_be_input_unicode {
	uint32_t codepoint;
	uint8_t  down;
	uint8_t  pad[3];
};

/* Lock-key sync payload (4 bytes).  flags carries the MS-RDPBCGR
 * fast-path SYNC toggle bits: SCROLL=0x01, NUM=0x02, CAPS=0x04,
 * KANA=0x08.  It is the absolute desired lock state, not a toggle. */
struct rdp_be_input_sync {
	uint32_t flags;
};

/* Mouse event payload (12 bytes). */
struct rdp_be_input_mouse {
	int32_t  x;
	int32_t  y;
	uint16_t buttons;    /* bit 0 = left, 1 = right, 2 = middle */
	uint16_t flags;      /* bit 0 = motion, 1 = down/up */
};

/* INPUT_TOUCH payload (worker -> session): a count header followed by that
 * many fixed contact records.  X11 sessions emulate the primary contact as a
 * single pointer; a Wayland session injects real wl_touch multitouch.  flags
 * carries the MS-RDPEI RDPEI_CONTACT_* bits; is_pen is 1 for a pen contact. */
struct rdp_be_touch_contact {
	uint8_t  id;
	uint8_t  is_pen;
	uint16_t flags;
	int32_t  x;
	int32_t  y;
	uint32_t pressure;
};

struct rdp_be_input_touch {
	uint32_t count;   /* followed by count struct rdp_be_touch_contact */
};

struct rdp_be_window {
	uint32_t window_id;
	int32_t  x, y;       /* window position on the virtual desktop */
	uint32_t w, h;       /* window size */
	uint16_t title_len;  /* UTF-16LE byte count, trailing for op CREATE */
	uint8_t  op;         /* RDP_BE_WINDOW_OP_* */
	uint8_t  pad;
};

/* CLIP_OFFER payload: just a u32 format bitmap. */
struct rdp_be_clip_offer {
	uint32_t formats;
};

/* CLIP_REQUEST payload: u32 format selector. */
struct rdp_be_clip_request {
	uint32_t format;
};

/* CLIP_DATA payload: u32 format, u32 status (0=ok, !=0 fail), then
 * `len - 8` bytes of UTF-8 text (for format=TEXT). */
struct rdp_be_clip_data_hdr {
	uint32_t format;
	uint32_t status;
};

/* RESIZE payload (worker -> session): new desktop dimensions. */
struct rdp_be_resize {
	uint16_t width;
	uint16_t height;
	uint16_t pad[2];
};

/* CURSOR payload: 8-byte header then width*height*4 bytes, top-down,
 * R,G,B,A per pixel (A = X cursor alpha). */
struct rdp_be_cursor_hdr {
	uint16_t width;
	uint16_t height;
	uint16_t hotspot_x;
	uint16_t hotspot_y;
};

/* CLIP_FILE_REQUEST payload (worker -> session): ask the session for one
 * file in its current FileGroupDescriptorW offer.  lindex selects the file
 * (its index in the descriptor list).  flags is CB_FILECONTENTS_SIZE (reply
 * with the 8-byte size) or CB_FILECONTENTS_RANGE (reply with cb_requested
 * bytes starting at the 64-bit offset pos_high<<32 | pos_low).  stream_id is
 * echoed back in the matching FILE_DATA so the worker can correlate. */
struct rdp_be_clip_file_req {
	uint32_t stream_id;
	uint32_t lindex;
	uint32_t flags;        /* CB_FILECONTENTS_SIZE / _RANGE */
	uint32_t pos_low;      /* RANGE: low 32 bits of the byte offset */
	uint32_t pos_high;     /* RANGE: high 32 bits of the byte offset */
	uint32_t cb_requested; /* RANGE: bytes wanted (session caps it) */
};

/* CLIP_FILE_DATA payload header (session -> worker), followed by the file
 * bytes (the requested range, or the 8-byte little-endian size for a SIZE
 * request).  stream_id echoes the request; status is 0 on success, nonzero
 * on any error (bad lindex, open/read failure), in which case no bytes
 * follow. */
struct rdp_be_clip_file_data_hdr {
	uint32_t stream_id;
	uint32_t status;       /* 0 = ok */
};

#endif /* RDP_BACKEND_PROTO_H */
