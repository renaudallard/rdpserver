#!/usr/bin/env python3
"""
connect_test.py -- integration test exercising the RDP handshake.

Starts no daemon on its own; expects rdpd already listening on
$RDPD_HOST:$RDPD_PORT (defaults 127.0.0.1:13389).  Drives the
protocol up through TLS handshake, MCS Connect Initial/Response,
Attach User, and one Channel Join.

Run from the project root:

    ./src/daemon/rdpd -f -d -p 13389 &
    PID=$!
    ./regress/integ/connect_test.py
    kill $PID
"""

import os
import socket
import ssl
import struct
import sys

HOST = os.environ.get("RDPD_HOST", "127.0.0.1")
PORT = int(os.environ.get("RDPD_PORT", "13389"))

PROTO_SSL = 0x00000001


def build_cr():
    """X.224 Connection Request with RDP_NEG_REQ asking for SSL."""
    neg_req = bytes([0x01, 0x00, 0x08, 0x00]) + struct.pack("<I", PROTO_SSL)
    x224 = bytes([14, 0xE0, 0, 0, 0, 0, 0]) + neg_req
    tpkt = bytes([3, 0]) + struct.pack(">H", 4 + len(x224)) + x224
    return tpkt


def recv_exact(sock_or_ssl, n):
    buf = b""
    while len(buf) < n:
        chunk = sock_or_ssl.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"short read: got {len(buf)} of {n}")
        buf += chunk
    return buf


def read_tpkt(rdwr):
    hdr = recv_exact(rdwr, 4)
    if hdr[0] != 3:
        raise ValueError(f"bad TPKT version {hdr[0]}")
    length = (hdr[2] << 8) | hdr[3]
    if length < 7:
        raise ValueError(f"bad TPKT length {length}")
    return hdr + recv_exact(rdwr, length - 4)


def expect_cc(frame):
    if frame[4] < 6 or (frame[5] & 0xF0) != 0xD0:
        raise ValueError(f"not a CC: {frame[:8].hex()}")
    if len(frame) < 11 + 8:
        raise ValueError("CC too short for NEG_RSP")
    if frame[11] != 0x02:
        raise ValueError(f"NEG_RSP type {frame[11]:#x}, want 0x02")
    selected = struct.unpack("<I", frame[15:19])[0]
    if selected != PROTO_SSL:
        raise ValueError(f"selected protocol {selected:#x}, want SSL")
    return True


def build_mcs_connect_initial():
    """Hand-crafted MCS Connect Initial.

    Fields encoded as BER application[101] sequence with two octet
    string selectors, a BOOLEAN, three DomainParameters, and the
    userData OCTET STRING carrying a GCC Conference Create Request
    with one Client Data Block (CS_CORE).
    """

    def ber_len(n):
        if n <= 0x7F:
            return bytes([n])
        if n <= 0xFF:
            return bytes([0x81, n])
        if n <= 0xFFFF:
            return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
        raise ValueError(f"BER length too large: {n}")

    def ber_integer(v):
        if v == 0:
            body = bytes([0])
        else:
            body = b""
            while v:
                body = bytes([v & 0xFF]) + body
                v >>= 8
        return bytes([0x02]) + ber_len(len(body)) + body

    def ber_octet_string(b):
        return bytes([0x04]) + ber_len(len(b)) + b

    def ber_boolean(v):
        return bytes([0x01, 0x01, 0xFF if v else 0x00])

    def ber_seq(body):
        return bytes([0x30]) + ber_len(len(body)) + body

    def ber_app(tag, body):
        if tag < 31:
            tag_byte = 0x40 | 0x20 | tag
            return bytes([tag_byte]) + ber_len(len(body)) + body
        return bytes([0x7F, tag]) + ber_len(len(body)) + body

    dp = ber_seq(
        ber_integer(34)
        + ber_integer(2)
        + ber_integer(0)
        + ber_integer(1)
        + ber_integer(0)
        + ber_integer(1)
        + ber_integer(0xFFFF)
        + ber_integer(2)
    )

    # GCC Conference Create Request: fixed prefix + "Duca" + length + CS_CORE.
    cs_core_body = (
        struct.pack("<I", 0x00080004)  # version
        + struct.pack("<HH", 1024, 768)  # desktopWidth/Height
        + struct.pack("<HH", 0xCA01, 0xAA03)  # colorDepth(8bpp legacy), SAS
        + struct.pack("<I", 0x0409)  # keyboardLayout = en-US
        + struct.pack("<I", 2600)  # clientBuild
        + b"\x00" * 32  # clientName UTF-16LE (zero-fill)
        + struct.pack("<I", 4)  # keyboardType
        + struct.pack("<I", 0)  # keyboardSubType
        + struct.pack("<I", 12)  # keyboardFunctionKey
        + b"\x00" * 64  # imeFileName
        + struct.pack("<H", 0x0001)  # postBeta2ColorDepth = 8bpp
        + struct.pack("<H", 1)  # clientProductId
        + struct.pack("<I", 0)  # serialNumber
        + struct.pack("<H", 32)  # highColorDepth = 32bpp
        + struct.pack("<H", 0x0007)  # supportedColorDepths
        + struct.pack("<H", 0x0001)  # earlyCapabilityFlags
        + b"\x00" * 64  # clientDigProductId
        + struct.pack("<B", 0)  # connectionType
        + struct.pack("<B", 0)  # pad1
        + struct.pack("<I", 0)  # serverSelectedProtocol
    )
    cs_core = struct.pack("<HH", 0xC001, len(cs_core_body) + 4) + cs_core_body

    gcc_prefix = bytes(
        [
            0x00,
            0x05,
            0x00,
            0x14,
            0x7C,
            0x00,
            0x01,
        ]
    )
    user_data = cs_core
    # Outer length (PER): need to surround userData with the rest of GCC.
    inner = b"\x08\x00\x10\x00\x01\xc0\x00" + b"Duca"
    # PER length determinant for user_data.
    ud_len = len(user_data)
    if ud_len < 128:
        ud_len_enc = bytes([ud_len])
    else:
        ud_len_enc = bytes([0x80 | (ud_len >> 8), ud_len & 0xFF])
    gcc = gcc_prefix + inner + ud_len_enc + user_data
    # Outer GCC length (also PER) -- we wrap once more conservatively.
    outer = bytes([0x81, len(gcc)]) if len(gcc) >= 128 else bytes([len(gcc)])

    ci_body = (
        ber_octet_string(bytes([0x01]))
        + ber_octet_string(bytes([0x01]))
        + ber_boolean(True)
        + dp
        + dp
        + dp
        + ber_octet_string(gcc)
    )
    return ber_app(101, ci_body)


def main():
    s = socket.socket()
    s.connect((HOST, PORT))

    s.sendall(build_cr())
    cc = read_tpkt(s)
    expect_cc(cc)
    print("ok: x224 CR/CC + NEG_RSP")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tls = ctx.wrap_socket(s, server_hostname=HOST)
    print("ok: TLS handshake")

    # Wrap MCS Connect Initial in X.224 DT + TPKT.
    ci = build_mcs_connect_initial()
    x224dt = bytes([0x02, 0xF0, 0x80])
    tpkt = bytes([3, 0]) + struct.pack(">H", 4 + len(x224dt) + len(ci)) + x224dt + ci
    tls.sendall(tpkt)

    cr_frame = read_tpkt(tls)
    if cr_frame[7] != 0x7F or cr_frame[8] != 0x66:
        raise ValueError(
            f"Connect Response tag wrong: {cr_frame[7]:#x} {cr_frame[8]:#x}"
        )
    print("ok: MCS Connect Response received")

    # Erect Domain Request.
    edrq = bytes([0x04, 0x01, 0x00, 0x01, 0x00])
    tls.sendall(bytes([3, 0, 0, 12, 2, 0xF0, 0x80]) + edrq)
    # Attach User Request.
    aurq = bytes([0x28])
    tls.sendall(bytes([3, 0, 0, 8, 2, 0xF0, 0x80]) + aurq)
    auc = read_tpkt(tls)
    if auc[7] & 0xFC != 0x2C:
        raise ValueError(f"AUC wrong: {auc[7]:#x}")
    user_id = ((auc[9] << 8) | auc[10]) + 1001
    print(f"ok: Attach User Confirm, user_id={user_id}")

    # Channel Join Request for I/O channel 1003.
    cjr = bytes([0x38, 0, user_id - 1001, 0x03, 0xEB])
    tls.sendall(bytes([3, 0, 0, 12, 2, 0xF0, 0x80]) + cjr)
    cjc = read_tpkt(tls)
    if cjc[7] & 0xFC != 0x3C:
        raise ValueError(f"CJC wrong: {cjc[7]:#x}")
    print("ok: Channel Join Confirm")

    tls.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"FAIL: {e}", file=sys.stderr)
        sys.exit(1)
