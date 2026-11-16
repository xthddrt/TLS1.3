#!/usr/bin/env python3
"""Read-only process-memory search for TLS handshake bytes; save surrounding windows.

    sudo python -I tools/tls_memscan.py PID captures/scan.pkl @captures/needles.txt
    sudo python -I tools/tls_memscan.py PID captures/scan.pkl HEX_NEEDLE [HEX_NEEDLE ...]

Needles must contain at least 16 bytes; TLS client_random values are suitable. The
scanner opens /proc/PID/maps and /proc/PID/mem with rb only: no ptrace, writes, stops,
or signals. Its mode-600 pickle contains sensitive memory and must be treated as trusted,
private input. OpenSSL may erase secrets when a connection closes.
"""

import os
import pickle
import struct
import sys

CHUNK, OVERLAP, WINDOW, POINTED = 16 << 20, 64, 16384, 2048


def main():
    pid, out = int(sys.argv[1]), os.path.realpath(sys.argv[2])
    repo = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    if out.startswith(repo + os.sep) and not out.startswith(os.path.join(repo, "captures") + os.sep):
        sys.exit(f"{out}: memory contents stay out of the repository; use captures/ or a folder outside it")
    needles = [bytes.fromhex(h) for a in sys.argv[3:]
               for h in (open(a[1:]).read().split() if a.startswith("@") else [a])]
    needles = [n for n in needles if len(n) >= 16]
    if not needles:
        sys.exit("no needles of 16 bytes or more")

    maps = []
    with open(f"/proc/{pid}/maps", "rb") as f:
        for line in f:
            parts = line.split()
            lo, hi = (int(x, 16) for x in parts[0].split(b"-"))
            name = parts[5].decode(errors="replace") if len(parts) > 5 else ""
            if parts[1][:1] == b"r" and name not in ("[vvar]", "[vsyscall]", "[vvar_vclock]"):
                maps.append((lo, hi, parts[1].decode(), name))

    def readable(a):
        return any(lo <= a < hi for lo, hi, _, _ in maps)

    hits, blocks, scanned = [], {}, 0
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
        def read(a, n):
            try:
                mem.seek(a)
                return mem.read(n)
            except OSError:
                return b""

        for lo, hi, perms, name in maps:
            for a in range(lo, hi, CHUNK):
                data = read(a, min(CHUNK + OVERLAP, hi - a))
                if not data:
                    continue
                scanned += len(data)
                for i, n in enumerate(needles):
                    j = data.find(n)
                    while j >= 0:
                        if j < CHUNK:
                            hits.append((i, a + j, perms, name))
                        j = data.find(n, j + 1)
        for _, addr, _, _ in hits:
            base = max(addr - WINDOW // 2, 0) & ~7
            if base in blocks:
                continue
            window = blocks[base] = read(base, WINDOW)
            for off in range(0, len(window) - 7, 8):
                p = struct.unpack_from("<Q", window, off)[0]
                if 0x10000 <= p < 1 << 47 and readable(p) and (p - 256) & ~7 not in blocks:
                    blocks[(p - 256) & ~7] = read((p - 256) & ~7, POINTED)

    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        pickle.dump({"needles": needles, "hits": hits, "blocks": blocks}, f)
    if "SUDO_UID" in os.environ:
        os.chown(out, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
    print(f"scanned {scanned >> 20} MiB in {len(maps)} mappings; {len(hits)} hits; {len(blocks)} blocks saved to {out}")


if __name__ == "__main__":
    main()
