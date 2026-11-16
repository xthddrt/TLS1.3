"""NGS-X HTTP response-body cipher used inside TLS connections.

Only server-to-client responses are decoded. Client requests use a separate,
device-bound cipher and are not decoded here. A response is base64(raw), where
raw[0:2] replaces the gzip magic and every later byte is XORed with one key.
raw[2] is XOR(key, gzip deflate marker 0x08), so the key is self-describing and
the gzip CRC validates the result.
"""

import base64
import gzip
import io
import json
import zlib

GZIP_MAGIC = b"\x1f\x8b"
GZIP_CM = 0x08


def _as_raw(data):
    if isinstance(data, str):
        data = data.strip().encode()
    try:
        return base64.b64decode(data, validate=True)
    except Exception:
        return bytes(data)


def recover_key(raw):
    if len(raw) < 3:
        raise ValueError("body too short")
    return raw[2] ^ GZIP_CM


def decrypt_response(data, want="bytes"):
    """Decode raw or base64 response bytes; want="json" also parses the JSON."""
    raw = _as_raw(data)
    key = recover_key(raw)
    xored = bytes(c ^ key for c in raw)
    plain = zlib.decompress(GZIP_MAGIC + xored[2:], 16 + zlib.MAX_WBITS)
    return json.loads(plain) if want == "json" else plain


def encrypt_response(plain_bytes, key, header2=b"\x00\x00"):
    """Create a synthetic wire body for tests or authorized response research."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as f:
        f.write(plain_bytes)
    body = bytes(header2) + buf.getvalue()[2:]
    return base64.b64encode(bytes(c ^ key for c in body))
