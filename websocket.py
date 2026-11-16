"""WebSocket frames (RFC 6455) in a decrypted HTTP/1.1 upgraded stream."""

from __future__ import annotations

import struct

OPCODES = {0: "continuation", 1: "text", 2: "binary", 8: "close", 9: "ping", 10: "pong"}


def upgraded(chunks):
    """Return chunks after a WebSocket upgrade head, None for a non-upgrade stream."""
    buf, out = b"", None
    for t, data in chunks:
        if out is not None:
            out.append((t, data))
            continue
        buf += data
        end = buf.find(b"\r\n\r\n")
        if end < 0:
            continue
        head = buf[:end].lower()
        if not (head.startswith(b"http/1.1 101") or b"\nupgrade: websocket" in head):
            return None
        out = [(t, buf[end + 4:])] if len(buf) > end + 4 else []
    return out


def frames(chunks):
    """Return [(time_ns, fin, opcode, unmasked payload)]; omit a partial final frame.

    shortcut: permessage-deflate payloads stay compressed (RSV1 set); undo it if a server agrees to it.
    """
    buf, starts, out = b"", [], []
    for t, data in chunks:
        starts.append((len(buf), t))
        buf += data
    pos, si = 0, 0
    while len(buf) - pos >= 2:
        b0, b1 = buf[pos], buf[pos + 1]
        n, j = b1 & 0x7f, pos + 2
        if n == 126:
            if len(buf) < j + 2:
                break
            n, j = struct.unpack_from(">H", buf, j)[0], j + 2
        elif n == 127:
            if len(buf) < j + 8:
                break
            n, j = struct.unpack_from(">Q", buf, j)[0], j + 8
        mask = None
        if b1 & 0x80:
            mask, j = buf[j:j + 4], j + 4
        if len(buf) < j + n:
            break
        payload = buf[j:j + n]
        if mask:
            payload = bytes(x ^ mask[k & 3] for k, x in enumerate(payload))
        while si + 1 < len(starts) and starts[si + 1][0] <= pos:
            si += 1
        out.append((starts[si][1], bool(b0 & 0x80), b0 & 0x0f, payload))
        pos = j + n
    return out
