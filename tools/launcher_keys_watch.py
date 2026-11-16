#!/usr/bin/env python3
"""Catch TLS 1.3 keys from the Nexon launcher's Chromium/BoringSSL processes in Wine.

    sudo python -I tools/launcher_keys_watch.py captures/proxy.jsonl captures/launcher.keylog [--seconds 0]

The watcher selects only Wine Chromium/nexon_client connections from connection_open
records; native Linux Chrome is always excluded. It retries open connections until both
application secrets are verified and written. Decrypt the result with tls13_keys.py.
Memory access is read-only; the keylog is mode 600 and private.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import pickle
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import tls13  # noqa: E402

RETRY_S = 2.0
AFTER_CLOSE_S = 10
CONN_ID = re.compile(r'"conn":(\d+)')


def launcher(proc):
    """Select the launcher's Wine Chromium processes, never native sign-in Chrome."""
    return bool(proc) and "wine" in (proc.get("path") or "") and \
        (proc.get("name") or "").startswith(("Cr", "nexon_client"))


def follow(f, conns, part=""):
    """Consume complete new JSONL lines, returning an unfinished trailing line."""
    while True:
        line = f.readline()
        if not line:
            return part
        line, part = part + line, ""
        if not line.endswith("\n"):
            return line
        m = CONN_ID.search(line)
        if not m:
            continue
        c = int(m.group(1))
        if '"kind":"connection_open"' in line:
            r = json.loads(line)
            if r["destination"][1] == 443 and launcher(r.get("process")):
                conns[c] = {"pid": r["process"]["pid"], "c2s": [], "s2c": [], "closed": None}
        elif c in conns and '"kind":"data"' in line:
            r = json.loads(line)
            conns[c]["c2s" if r["direction"] == "client_to_server" else "s2c"].append(
                (r["time_ns"], bytes.fromhex(r["hex"])))
        elif c in conns and '"kind":"connection_close"' in line:
            conns[c]["closed"] = time.time()


def complete(keys):
    return {"CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"} <= keys.keys()


def scan(pid, needles, out):
    """Read memory around needles with tls_memscan.py; return [] if the process is gone."""
    r = subprocess.run([sys.executable, "-I", str(REPO / "tools/tls_memscan.py"), str(pid), out]
                       + [n.hex() for n in needles], capture_output=True, text=True)
    if r.returncode or not os.path.exists(out):
        return []
    try:
        with open(out, "rb") as f:
            return list(pickle.load(f)["blocks"].values())
    finally:
        os.remove(out)


def ready(conn):
    """Both directions need an encrypted handshake record and an application record."""
    return (tls13.suite(conn) in tls13.SUITES
            and len(tls13.app_records(conn, "c2s")) >= 2
            and len(tls13.app_records(conn, "s2c")) >= 2)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("recording")
    ap.add_argument("keylog")
    ap.add_argument("--seconds", type=float, default=0, help="stop after this long (0 = until Ctrl-C)")
    args = ap.parse_args()
    os.umask(0o077)
    keys, conns, part, tried, crs = tls13.read_keylog(args.keylog), {}, "", {}, {}
    deadline = args.seconds and time.time() + args.seconds
    f = open(args.recording, encoding="utf-8", errors="replace")
    print(f"{time.strftime('%T')} watching launcher TLS 1.3 connections in {args.recording}", flush=True)
    try:
        while not (deadline and time.time() > deadline):
            part = follow(f, conns, part)
            todo = collections.defaultdict(dict)
            for c, v in conns.items():
                cr = crs.get(c) or crs.setdefault(c, tls13.client_random(v))
                if not cr or complete(keys.get(cr, {})) or time.time() - tried.get(c, 0) < RETRY_S:
                    continue
                if v["closed"] and time.time() - v["closed"] > AFTER_CLOSE_S:
                    continue
                if ready(v):
                    todo[v["pid"]][c] = cr
            for pid, cs in todo.items():
                blocks = scan(pid, cs.values(), f"{args.keylog}.scan-{pid}.pkl")
                for c, cr in cs.items():
                    tried[c] = time.time()
                    found = tls13.find_secrets(conns[c], blocks)
                    if found and not found.items() <= keys.get(cr, {}).items():
                        keys.setdefault(cr, {}).update(found)
                        tls13.write_keylog(args.keylog, keys)
                        sni = tls13.tls_client_hello_sni(conns[c]["c2s"][0][1])
                        print(f"{time.strftime('%T')} conn {c} {sni}: {', '.join(sorted(found))} verified and written",
                              flush=True)
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
