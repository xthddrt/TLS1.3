"""TLS 1.3 record decryption and traffic-secret recovery from proxy recordings.

A connection has a handshake and an application traffic secret for each direction.
Candidate secrets are accepted only when their AEAD tag opens a recorded record.
Recovered secrets use the standard SSLKEYLOGFILE format, which Wireshark also reads.
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import os
import struct
import zlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

REPO = Path(__file__).resolve().parent

# RFC 8446 B.4: AEAD class, key length, PRF hash.
SUITES = {
    0x1301: (AESGCM, 16, hashlib.sha256),
    0x1302: (AESGCM, 32, hashlib.sha384),
    0x1303: (ChaCha20Poly1305, 32, hashlib.sha256),
}
LABELS = {
    ("c2s", True): "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    ("s2c", True): "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    ("c2s", False): "CLIENT_TRAFFIC_SECRET_0",
    ("s2c", False): "SERVER_TRAFFIC_SECRET_0",
}


def records(chunks):
    """Reassemble one direction's timestamped chunks into complete TLS records."""
    buf, out = b"", []
    for time_ns, data in chunks:
        buf += data
        while len(buf) >= 5:
            n = struct.unpack_from(">H", buf, 3)[0]
            if len(buf) < 5 + n:
                break
            out.append((time_ns, buf[0], buf[1:3], buf[5:5 + n]))
            buf = buf[5 + n:]
    return out


def tls_client_hello_sni(data):
    """Return the SNI hostname from complete TLS records in one chunk, or None."""
    data = bytes(data)
    offset = 0
    while offset + 5 <= len(data):
        content_type = data[offset]
        version, length = struct.unpack_from(">HH", data, offset + 1)
        if offset + 5 + length > len(data):
            return None
        body = data[offset + 5:offset + 5 + length]
        offset += 5 + length
        if content_type != 22 or version < 0x0300 or body[:1] != b"\x01" or len(body) < 4:
            continue
        pos = 38
        if pos >= len(body):
            return None
        pos += 1 + body[pos]
        if pos + 2 > len(body):
            return None
        cipher_len = struct.unpack_from(">H", body, pos)[0]
        pos += 2 + cipher_len
        if pos >= len(body):
            return None
        pos += 1 + body[pos]
        if pos + 2 > len(body):
            return None
        extensions_len = struct.unpack_from(">H", body, pos)[0]
        pos += 2
        end = min(pos + extensions_len, len(body))
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack_from(">HH", body, pos)
            pos += 4
            ext = body[pos:pos + ext_len]
            pos += ext_len
            if ext_type != 0 or len(ext) < 2:
                continue
            list_len = struct.unpack_from(">H", ext, 0)[0]
            cursor = 2
            while cursor + 3 <= min(2 + list_len, len(ext)):
                name_type, name_len = struct.unpack_from(">BH", ext, cursor)
                cursor += 3
                name = ext[cursor:cursor + name_len]
                cursor += name_len
                if name_type == 0 and name:
                    return name.decode("ascii", "replace")
    return None


def read_recording(path, sni=None):
    """Read TLS connections from proxy JSONL on any port, discarding non-TLS streams early."""
    conns, pending = {}, {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if '"kind":"data"' in line:
                r = json.loads(line)
                conn = conns.get(r["conn"])
                if conn is None:
                    continue
                data = bytes.fromhex(r["hex"])
                if r["direction"] == "client_to_server" and r["conn"] in pending:
                    pending[r["conn"]].append((r["time_ns"], data))
                    hello = b"".join(chunk for _, chunk in pending[r["conn"]])
                    if hello[:1] != b"\x16" or (len(hello) > 1 and hello[1] != 3):
                        del conns[r["conn"]], pending[r["conn"]]
                        continue
                    complete = records(pending[r["conn"]])
                    if not complete:
                        continue
                    _, kind, _, body = complete[0]
                    if kind != 22 or body[:1] != b"\x01":
                        del conns[r["conn"]], pending[r["conn"]]
                        continue
                    conn["c2s"].extend(pending.pop(r["conn"]))
                elif r["direction"] == "client_to_server":
                    conn["c2s"].append((r["time_ns"], data))
                elif r["conn"] in pending and not pending[r["conn"]]:
                    del conns[r["conn"]], pending[r["conn"]]
                    continue
                else:
                    conn["s2c"].append((r["time_ns"], data))
            elif '"kind":"connection_open"' in line:
                r = json.loads(line)
                conns[r["conn"]] = {"c2s": [], "s2c": [], "closed": False}
                pending[r["conn"]] = []
            elif '"kind":"connection_close"' in line:
                r = json.loads(line)
                if r["conn"] in conns:
                    conns[r["conn"]]["closed"] = True
    if sni:
        conns = {c: v for c, v in conns.items() if tls13_sni(v) == sni}
    return conns


def tls13_sni(conn):
    """Return SNI from a connection's reassembled ClientHello, or None."""
    return tls_client_hello_sni(b"".join(data for _, data in conn["c2s"]))


def private_file(path, mode="w"):
    """Open a mode-600 output, refusing repository paths outside captures/."""
    path = Path(path).resolve()
    if path.is_relative_to(REPO) and not path.is_relative_to(REPO / "captures"):
        raise SystemExit(f"{path}: secrets stay out of the repository; use captures/ or a folder outside it")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, mode)


def hkdf_expand_label(secret, label, context, length, h):
    """HKDF-Expand-Label from RFC 8446 section 7.1."""
    full = b"tls13 " + label
    info = struct.pack(">H", length) + bytes([len(full)]) + full + bytes([len(context)]) + context
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([i]), h).digest()
        out += block
        i += 1
    return out[:length]


def secret_len(suite):
    return SUITES[suite][2]().digest_size


def key_iv(secret, suite):
    """Derive a record key and IV from a traffic secret (RFC 8446 section 7.3)."""
    _, klen, h = SUITES[suite]
    return (hkdf_expand_label(secret, b"key", b"", klen, h),
            hkdf_expand_label(secret, b"iv", b"", 12, h))


def next_secret(secret, suite):
    """Derive application_traffic_secret_{N+1} after KeyUpdate."""
    _, _, h = SUITES[suite]
    return hkdf_expand_label(secret, b"traffic upd", b"", h().digest_size, h)


def open_record(key_iv_pair, suite, seq, body):
    """Return (inner content type, plaintext); a bad AEAD tag raises an exception."""
    aead, _, _ = SUITES[suite]
    key, iv = key_iv_pair
    nonce = (int.from_bytes(iv, "big") ^ seq).to_bytes(12, "big")
    aad = b"\x17\x03\x03" + struct.pack(">H", len(body))
    plain = aead(key).decrypt(nonce, body, aad)
    i = len(plain) - 1
    while i >= 0 and plain[i] == 0:
        i -= 1
    if i < 0:
        raise ValueError("record has no inner content type")
    return plain[i], plain[:i]


def client_random(conn):
    """Return the 32-byte ClientHello random, or None."""
    for _, kind, _, body in records(conn["c2s"]):
        if kind == 22 and body[:1] == b"\x01":
            return body[6:38]
    return None


def suite(conn):
    """Return the cipher suite from ServerHello, or None."""
    for _, kind, _, body in records(conn["s2c"]):
        if kind == 22 and body[:1] == b"\x02":
            sid = body[38]
            return struct.unpack_from(">H", body, 39 + sid)[0]
    return None


def app_records(conn, direction):
    """Return [(time_ns, encrypted body)] for one direction, in wire order."""
    return [(t, body) for t, kind, _, body in records(conn[direction]) if kind == 23]


def classify(secret, recs, suite_id):
    """Return ("handshake"|"app", first index) only if the secret opens a record."""
    if secret.count(0) > secret_len(suite_id) // 4:
        return None
    ks = key_iv(secret, suite_id)
    for j, (_, body) in enumerate(recs):
        try:
            open_record(ks, suite_id, 0, body)
        except Exception:
            continue
        return ("handshake" if j == 0 else "app"), j
    return None


def find_secrets(conn, blocks):
    """Find memory-window secrets, proving each against this connection's records."""
    sid = suite(conn)
    if sid is None or sid not in SUITES:
        return {}
    n = secret_len(sid)
    recs = {"c2s": app_records(conn, "c2s"), "s2c": app_records(conn, "s2c")}
    found, seen = {}, set()
    for block in blocks:
        for off in range(0, len(block) - n + 1, 4):
            cand = block[off:off + n]
            if cand in seen:
                continue
            seen.add(cand)
            for direction, rs in recs.items():
                role = classify(cand, rs, sid)
                if role:
                    found[LABELS[(direction, role[0] == "handshake")]] = cand
        if len(found) == 4:
            break
    return found


def decrypt_dir(recs, suite_id, handshake=None, app=None):
    """Return [(time_ns, inner type, plaintext or None)], including KeyUpdate rollover."""
    app_start = classify(app, recs, suite_id)[1] if app else None
    ks = key_iv(handshake, suite_id) if handshake else None
    secret, seq, out = handshake, 0, []
    for j, (t, body) in enumerate(recs):
        if app_start is not None and j == app_start:
            secret, ks, seq = app, key_iv(app, suite_id), 0
        if ks is None:
            out.append((t, None, None))
            continue
        try:
            typ, content = open_record(ks, suite_id, seq, body)
        except Exception:
            out.append((t, None, None))
            seq += 1
            continue
        out.append((t, typ, content))
        seq += 1
        if secret is app and typ == 22 and content[:1] == b"\x18":
            secret = next_secret(secret, suite_id)
            ks, seq = key_iv(secret, suite_id), 0
    return out


def app_data(dir_records):
    """Drop encrypted handshake and alert records from decrypted directional records."""
    return [(t, 23, content) for t, typ, content in dir_records if typ == 23 and content is not None]


def read_keylog(path):
    """Return {client_random: {label: secret}} from TLS 1.3 SSLKEYLOGFILE lines."""
    out = {}
    if os.path.exists(path):
        with open(path, encoding="ascii") as f:
            for line in f:
                parts = line.split()
                if len(parts) == 3 and parts[0] in LABELS.values():
                    out.setdefault(bytes.fromhex(parts[1]), {})[parts[0]] = bytes.fromhex(parts[2])
    return out


def keylog_lines(client_random, secrets):
    """Format one connection's secrets as SSLKEYLOGFILE lines."""
    return [f"{label} {client_random.hex()} {secret.hex()}\n" for label, secret in secrets.items()]


def write_keylog(path, keys):
    """Atomically write all keys with owner-only permissions."""
    tmp = f"{path}.tmp"
    with private_file(tmp) as f:
        for cr, secrets in keys.items():
            f.writelines(keylog_lines(cr, secrets))
    os.replace(tmp, path)
    if "SUDO_UID" in os.environ:
        os.chown(path, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))


def http_messages(recs):
    """Split decrypted records into HTTP/1.1 messages; stop at an undecrypted gap."""
    buf, start_t, out = b"", None, []
    for t, kind, plain in recs:
        if plain is None:
            break
        if kind != 23:
            continue
        if not buf:
            start_t = t
        buf += plain
        while (end := buf.find(b"\r\n\r\n")) >= 0:
            head = buf[:end].decode("latin1").split("\r\n")
            hdr = {k.strip().lower(): v.strip() for k, _, v in (h.partition(":") for h in head[1:])}
            rest = buf[end + 4:]
            if "content-length" in hdr:
                n = int(hdr["content-length"])
                if len(rest) < n:
                    break
                body, buf = rest[:n], rest[n:]
            elif hdr.get("transfer-encoding", "").lower() == "chunked":
                body, pos, done = b"", 0, False
                while (eol := rest.find(b"\r\n", pos)) >= 0:
                    try:
                        size = int(rest[pos:eol].split(b";")[0], 16)
                    except ValueError:
                        return out
                    if len(rest) < eol + 4 + size:
                        break
                    body += rest[eol + 2:eol + 2 + size]
                    pos = eol + 4 + size
                    if size == 0:
                        done = True
                        break
                if not done:
                    break
                buf = rest[pos:]
            else:
                body, buf = b"", rest
            enc = hdr.get("content-encoding", "").lower()
            try:
                if enc == "gzip":
                    body = gzip.decompress(body)
                elif enc == "deflate":
                    body = zlib.decompress(body)
            except (OSError, EOFError, zlib.error):
                pass
            out.append((start_t, head[0], hdr, body))
            start_t = t
    return out


def mask(v):
    """Keep value shapes and short prefixes while hiding complete sensitive values."""
    if isinstance(v, str):
        return v if len(v) <= 2 else f"{v[:min(4, len(v) // 2)]}…({len(v)})"
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, (int, float)):
        return v if abs(v) < 100000 else f"{str(v)[:4]}…({len(str(v))}d)"
    if isinstance(v, list):
        return [mask(x) for x in v[:3]] + ([f"…+{len(v) - 3}"] if len(v) > 3 else [])
    if isinstance(v, dict):
        return {k: mask(x) for k, x in v.items()}
    return type(v).__name__
