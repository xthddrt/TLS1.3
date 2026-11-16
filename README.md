# TLS 1.3 connection analysis

A self-contained toolkit for live Wine/game TCP capture, TLS 1.3 record decryption,
read-only traffic-secret recovery, and HTTP/1.1, NGS-response, and WebSocket decoding.
All code, decoders, tests, and documentation are in this repository; no sibling checkout
or external repository is required. Game opcodes, TLS 1.2, and unrelated protocols are excluded.

## Included

| Path | Purpose |
|---|---|
| `tools/game_proxy.sh` | Adopt the selected Wine prefixes, redirect their TCP connections with `nftables`, and force Chromium QUIC to TCP fallback. |
| `tools/tls13_proxy.py` | Forward every byte unchanged, identify ClientHello/SNI on any TCP port, attribute processes, and write mode-600 JSONL recordings. |
| `tls13.py` | TLS record reassembly, RFC 8446 HKDF key schedule, AEAD decryption, KeyUpdate, secret verification, SSLKEYLOGFILE I/O, and HTTP/1.1 splitting. |
| `tools/tls13_keys.py` | List ClientHello randoms, verify memory-scan secrets, and decrypt HTTP, WebSocket, and optionally NGS response bodies. |
| `tools/tls_memscan.py` | Read-only Linux `/proc/<pid>/mem` scanner for open connections. |
| `tools/tls13_keys_watch.py` | Catch short-lived OpenSSL connections before their secrets are erased. |
| `tools/launcher_keys_watch.py` | Catch Nexon launcher TLS 1.3 keys from BoringSSL in Wine; native Linux Chrome is excluded from key reads. |
| `ngs_cipher.py`, `websocket.py` | NGS response-body and upgraded WebSocket connection decoders. |
| `tests/test_tls13.py` | Synthetic unit tests and real loopback proxy-to-decryption tests; no real credentials or captures. |

Supported cipher suites are `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, and
`TLS_CHACHA20_POLY1305_SHA256`. Each candidate secret is accepted only after it
successfully opens an AEAD record from the same connection and direction.

## Setup and verification

Python 3.9+ is required. Live capture and memory tools require Linux. Live capture also
requires `sudo`, `nft`, `systemd-run`, `setpriv`, `ss`, and Wine.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
mkdir -p captures
.venv/bin/python -m unittest discover -s tests -v
bash -n tools/game_proxy.sh
```

The tests create a real local client/proxy/server connection, verify that bytes pass
unchanged, and feed the resulting recording through key recovery and decryption. They
do not change host networking or require root.

## Live game capture

Start the proxy before the launcher or game:

```bash
tools/game_proxy.sh
```

It writes `captures/proxy-<timestamp>.jsonl`. By default it adopts Wine processes from
`~/.wine-nexon` and `~/.wine-nexon-2`, forwards all their TCP connections on any port,
and additionally redirects TCP port 443 from other processes to catch early launcher
connections. For different prefixes:

```bash
CS_WINEPREFIX="$HOME/.wine-nexon" tools/game_proxy.sh
```

Every proxied byte is forwarded unchanged and recorded. Non-TLS TCP is forwarded but not
decoded. UDP 443 is refused for adopted processes so Chromium falls back to TCP TLS;
`CS_ALLOW_QUIC=1` permits QUIC, but QUIC is not decrypted. The first Ctrl-C removes
redirection and drains open connections; a second Ctrl-C cuts them.

**Capture alone does not decrypt TLS.** Start the applicable key watcher while the game
or launcher connections are open. In another terminal, select the current recording:

```bash
RECORDING=$(ls -t captures/proxy-*.jsonl | head -1)
```

For the launcher, start this before launcher startup where possible:

```bash
sudo .venv/bin/python -I tools/launcher_keys_watch.py \
  "$RECORDING" captures/launcher.keylog
```

For a running game process, find its PID and start the OpenSSL watcher immediately:

```bash
pgrep -af 'MapleStory|nexon_client'
sudo .venv/bin/python -I tools/tls13_keys_watch.py GAME_PID \
  "$RECORDING" captures/tls13.keylog
# Optionally restrict hosts: --sni x-csauth.ngs.nexon.com x-config.ngs.nexon.com
```

Startup connections that close before their watcher starts cannot be recovered later.
The periodic OpenSSL connections can still be caught after startup. After capture:

```bash
.venv/bin/python tools/tls13_keys.py decrypt "$RECORDING" \
  --keylog captures/tls13.keylog --decode
.venv/bin/python tools/tls13_keys.py decrypt "$RECORDING" \
  --keylog captures/launcher.keylog --sni www.nexon.com
```

`--decode` adds NGS response decoding and request-body framing. WebSocket upgrades and
frames are decoded automatically. Console values are masked; add `--plaintext
captures/plaintext.jsonl` to write complete HTTP messages, including base64 bodies.

## Offline recovery and decryption

With an existing standard SSLKEYLOGFILE, no memory access is needed:

```bash
.venv/bin/python tools/tls13_keys.py decrypt captures/proxy.jsonl \
  --keylog captures/tls13.keylog
```

For individual OpenSSL connections that are still open, the manual equivalent of the
watcher is:

```bash
.venv/bin/python tools/tls13_keys.py needles captures/proxy.jsonl \
  --keylog captures/tls13.keylog > captures/needles.txt
sudo .venv/bin/python -I tools/tls_memscan.py PID captures/scan.pkl @captures/needles.txt
.venv/bin/python tools/tls13_keys.py find captures/proxy.jsonl captures/scan.pkl \
  --keylog captures/tls13.keylog
```

OpenSSL may erase handshake secrets first and all secrets at close, so partial recovery
is normal. Closed connections cannot be decrypted retroactively without an existing key
log. Wireshark can read the generated SSLKEYLOGFILE directly.

## Security and limits

- Use only on your own processes and captures, or in an environment you are authorized to inspect.
- Memory scans, key logs, recordings, and plaintext can contain credentials and private data. Keep them private; `captures/` is Git-ignored and generated secret files are mode 600.
- Memory access is read-only: no `ptrace`, process writes, stops, or signals. Reading another process normally requires root.
- Memory-scan pickle files are trusted input. Never load a pickle from an untrusted source.
- The proxy handles TCP, not QUIC/HTTP/3. The CLI formats HTTP/1.1 and WebSocket; `tls13.py` exposes decrypted application bytes for other protocols.
- NGS client requests use a separate device-bound cipher and remain undecoded; only their framing and the server responses are available.
- A recording without the correct traffic secrets remains encrypted. This code does not derive TLS secrets from the wire alone.
- Automated tests do not prove compatibility with a future game/Wine/OpenSSL build. Confirm a real session by checking for `tls_client_hello`, verified key-log entries, and decrypted messages while playing.
