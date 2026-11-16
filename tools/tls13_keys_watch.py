#!/usr/bin/env python3
"""Catch TLS 1.3 secrets from a running OpenSSL process while connections are open.

    sudo python -I tools/tls13_keys_watch.py PID captures/proxy.jsonl captures/tls13.keylog [--sni HOST ...]

The watcher follows ClientHello records, reads writable process memory with rb only,
and accepts only secrets that open the matching recorded records. OpenSSL can erase
secrets as soon as a connection closes, so offline scans cannot recover closed sessions.
The keylog is mode 600 and is refused inside the repository except under captures/.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import tls13  # noqa: E402

WINDOW = 16384
FRESH_S = 3.0


def writable_maps(pid):
    maps = []
    with open(f"/proc/{pid}/maps", "rb") as f:
        for line in f:
            p = line.split()
            lo, hi = (int(x, 16) for x in p[0].split(b"-"))
            name = p[5] if len(p) > 5 else b""
            if p[1].startswith(b"rw") and name not in (b"[vvar]", b"[vsyscall]", b"[vvar_vclock]"):
                maps.append((lo, hi))
    return maps


def watch_recording(path, sni, needles, stop):
    """Fill {client_random: (connection, seen_time)} from new matching ClientHellos."""
    f = open(path, encoding="utf-8", errors="replace")
    f.seek(0, 2)
    crand, chunks, ignored = {}, {}, set()
    while not stop.is_set():
        line = f.readline()
        if not line:
            time.sleep(0.01)
            continue
        if '"conn"' not in line:
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        kind, conn = r.get("kind"), r.get("conn")
        if (kind == "data" and r.get("direction") == "client_to_server"
                and conn not in crand and conn not in ignored):
            chunks[conn] = chunks.get(conn, b"") + bytes.fromhex(r["hex"])
            hello = chunks[conn]
            if hello[:1] != b"\x16" or (len(hello) > 1 and hello[1] != 3):
                ignored.add(conn)
                del chunks[conn]
                continue
            complete = tls13.records([(0, hello)])
            if complete:
                _, record_type, _, body = complete[0]
                if record_type == 22 and body[:1] == b"\x01":
                    crand[conn] = body[6:38]
                else:
                    ignored.add(conn)
                del chunks[conn]
        elif kind == "tls_client_hello" and (sni is None or r.get("sni") in sni) and conn in crand:
            needles.setdefault(crand[conn], (conn, time.time()))
    f.close()


def save_keys(recording, blocks, cr, conn, keylog_path):
    """Verify memory-window secrets against one recorded connection and save them."""
    conns = tls13.read_recording(recording)
    if conn not in conns:
        return False
    secrets = tls13.find_secrets(conns[conn], blocks)
    if not secrets:
        return False
    existing = tls13.read_keylog(keylog_path)
    existing.setdefault(cr, {}).update(secrets)
    tls13.write_keylog(keylog_path, existing)
    print(f"{time.strftime('%T')} conn {conn} {cr.hex()[:8]}: {', '.join(sorted(secrets))} verified and written",
          flush=True)
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("pid", type=int)
    ap.add_argument("recording")
    ap.add_argument("keylog")
    ap.add_argument("--sni", nargs="+", help="server names to catch (default: all)")
    ap.add_argument("--seconds", type=float, default=0, help="stop after this long (0 = until Ctrl-C)")
    args = ap.parse_args()
    os.umask(0o077)

    needles, hit, stop = {}, {}, threading.Event()
    threading.Thread(target=watch_recording, args=(args.recording, args.sni, needles, stop), daemon=True).start()
    maps = writable_maps(args.pid)
    deadline = args.seconds and time.time() + args.seconds
    print(f"{time.strftime('%T')} watching {args.sni or 'all SNIs'} on pid {args.pid}; sweeping fresh connections",
          flush=True)
    with open(f"/proc/{args.pid}/mem", "rb", buffering=0) as mem:
        def rd(a, n):
            try:
                mem.seek(a)
                return mem.read(n)
            except OSError:
                return b""
        try:
            while not (deadline and time.time() > deadline):
                fresh = {cr: v for cr, v in list(needles.items()) if time.time() - v[1] < FRESH_S}
                if not fresh:
                    time.sleep(0.05)
                    continue
                for lo, hi in maps:
                    a = lo
                    while a < hi:
                        chunk = rd(a, min(16 << 20, hi - a))
                        if chunk:
                            for cr, (conn, _) in list(fresh.items()):
                                j = chunk.find(cr)
                                if j >= 0 and cr not in hit:
                                    base = max(a + j - WINDOW // 2, 0) & ~7
                                    hit[cr] = rd(base, WINDOW)
                                    save_keys(args.recording, [hit[cr]], cr, conn, args.keylog)
                        a += 16 << 20
        except KeyboardInterrupt:
            pass
    stop.set()


if __name__ == "__main__":
    main()
