#!/usr/bin/env python3
"""Recover, verify, and use TLS 1.3 traffic secrets from a proxy recording.

    python tools/tls13_keys.py needles captures/proxy.jsonl --keylog captures/tls13.keylog
    python tools/tls13_keys.py find captures/proxy.jsonl captures/scan.pkl --keylog captures/tls13.keylog
    python tools/tls13_keys.py decrypt captures/proxy.jsonl --keylog captures/tls13.keylog

Add --sni HOST to select one server. Decrypt prints HTTP/1.1 messages with values
masked; --plaintext FILE also writes complete messages with base64 bodies, mode 600.
Scan pickle files are trusted input: load only files produced by your own tls_memscan.py.
"""

from __future__ import annotations

import argparse
import base64
import collections
import json
import pickle
import statistics
import sys
import time
import urllib.parse
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import ngs_cipher  # noqa: E402
import tls13  # noqa: E402
import websocket  # noqa: E402


def tls13_conns(conns):
    """Return {connection: client_random} for supported TLS 1.3 connections."""
    out = {}
    for c, v in sorted(conns.items()):
        cr, sid = tls13.client_random(v), tls13.suite(v)
        if cr and sid in tls13.SUITES:
            out[c] = cr
    return out


def cmd_needles(args, conns, keylog):
    for cr in tls13_conns(conns).values():
        if "SERVER_TRAFFIC_SECRET_0" not in keylog.get(cr, {}):
            print(cr.hex())


def cmd_find(args, conns, keylog):
    todo = {c: cr for c, cr in tls13_conns(conns).items()
            if "SERVER_TRAFFIC_SECRET_0" not in keylog.get(cr, {})}
    blocks = []
    for path in args.scans:
        with open(path, "rb") as f:
            blocks += list(pickle.load(f)["blocks"].values())
    found = 0
    for c, cr in todo.items():
        secrets = tls13.find_secrets(conns[c], blocks)
        if secrets:
            keylog.setdefault(cr, {}).update(secrets)
            found += 1
            print(f"conn {c}: {len(secrets)} secret(s) ({', '.join(sorted(secrets))}) verified on its records")
    tls13.write_keylog(args.keylog, keylog)
    print(f"{found} of {len(todo)} connections without a key found; "
          f"{sum(len(s) for s in keylog.values())} secrets for {len(keylog)} connections in {args.keylog}")


def decode_reply(body):
    try:
        return json.dumps(tls13.mask(ngs_cipher.decrypt_response(body, want="json")), ensure_ascii=False)
    except Exception as e:
        return f"<not the NGS response cipher: {type(e).__name__}>"


def request_framing(body):
    try:
        raw = base64.b64decode(body, validate=True)
        return f"{len(body)} B base64 of {len(raw)} B; first bytes {raw[:4].hex()}"
    except Exception:
        return f"{len(body)} B, not base64; first bytes {bytes(body[:4]).hex()}"


def masked_line(line):
    parts = line.split(" ")
    if len(parts) > 1 and "?" in parts[1]:
        path, query = parts[1].split("?", 1)
        parts[1] = path + "?" + "&".join(f"{k}={tls13.mask(v)}"
                                               for k, v in urllib.parse.parse_qsl(query, True))
    return " ".join(parts)


def masked_body(hdr, body):
    try:
        return json.dumps(tls13.mask(json.loads(body)), ensure_ascii=False)
    except ValueError:
        pass
    if "form-urlencoded" in hdr.get("content-type", ""):
        return json.dumps({k: tls13.mask(v) for k, v in urllib.parse.parse_qsl(body.decode("latin1"), True)})
    return f"<{hdr.get('content-type', '?')}, {len(body)} B>"


def masked_headers(hdr):
    out = tls13.mask(hdr)
    for h in ("cookie", "set-cookie"):
        if h in hdr:
            out[h] = "names: " + ", ".join(c.split("=")[0].strip() for c in hdr[h].split(";") if "=" in c)
    return json.dumps(out, ensure_ascii=False)


def frame_summary(frames):
    groups = collections.defaultdict(list)
    for t, _, op, payload in frames:
        try:
            obj = json.loads(payload)
            kind = obj.get("headers", {}).get("eventType") if isinstance(obj, dict) else None
            kind = kind or (",".join(sorted(obj)) if isinstance(obj, dict) else type(obj).__name__)
            shown = json.dumps(tls13.mask(obj), ensure_ascii=False)
        except (ValueError, AttributeError):
            kind, shown = f"{len(payload)} B", f"<{len(payload)} B>"
        groups[(websocket.OPCODES.get(op, op), kind)].append((t, len(payload), shown))
    for (op, kind), rows in groups.items():
        gaps = [(b[0] - a[0]) / 1e9 for a, b in zip(rows, rows[1:])]
        gap = (f", median gap {statistics.median(gaps):.0f} s "
               f"(min {min(gaps):.0f}, max {max(gaps):.0f})") if gaps else ""
        yield f"{len(rows)} x {op} {kind} ({rows[0][1]} B{gap}): {rows[0][2]}"


def cmd_decrypt(args, conns, keylog):
    out = tls13.private_file(args.plaintext) if args.plaintext else None
    for c, cr in tls13_conns(conns).items():
        secrets = keylog.get(cr, {})
        if not secrets:
            continue
        sid = tls13.suite(conns[c])
        dirs = {}
        for d, hs, ap in (("c2s", "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0"),
                          ("s2c", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "SERVER_TRAFFIC_SECRET_0")):
            recs = tls13.app_records(conns[c], d)
            dirs[d] = tls13.decrypt_dir(recs, sid, handshake=secrets.get(hs), app=secrets.get(ap))
        failed = sum(pl is None for d in dirs.values() for _, _, pl in d)
        print(f"== conn {c}: secrets {sorted(secrets)}; {failed} record(s) without a key")
        for d in ("c2s", "s2c"):
            data = tls13.app_data(dirs[d])
            for t, line, hdr, body in tls13.http_messages(data):
                clock = time.strftime("%H:%M:%S", time.localtime(t / 1e9))
                print(f"{clock} {d} {masked_line(line)} body {len(body)} B")
                print("   headers", masked_headers(hdr))
                if body:
                    if d == "s2c" and args.decode:
                        print("   body   ", decode_reply(body))
                    elif d == "c2s" and args.decode:
                        print("   body   ", request_framing(body))
                    else:
                        print("   body   ", masked_body(hdr, body))
                if out:
                    out.write(json.dumps({"conn": c, "direction": d, "time_ns": t, "start": line,
                                          "headers": hdr, "body_b64": base64.b64encode(body).decode()},
                                         ensure_ascii=False) + "\n")
            ws = websocket.upgraded([(t, p) for t, _, p in data])
            if ws:
                for line in frame_summary(websocket.frames(ws)):
                    print(f"   ws {d} {line}")
    if out:
        out.close()
        print("plaintext written to", args.plaintext)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("needles", "find", "decrypt"):
        p = sub.add_parser(name)
        p.add_argument("recording")
        if name == "find":
            p.add_argument("scans", nargs="+")
        p.add_argument("--keylog", required=name in ("find", "decrypt"), default="/dev/null")
        p.add_argument("--sni", help="only this TLS server name (default: every supported connection)")
        if name == "decrypt":
            p.add_argument("--decode", action="store_true", help="decode NGS response bodies and request framing")
            p.add_argument("--plaintext", help="write complete HTTP messages to this mode-600 JSONL file")
    args = ap.parse_args()
    conns = tls13.read_recording(args.recording, args.sni)
    globals()["cmd_" + args.cmd](args, conns, tls13.read_keylog(args.keylog))


if __name__ == "__main__":
    main()
