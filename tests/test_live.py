"""Live proxy and TLS-carried decoder checks on local synthetic connections."""

from __future__ import annotations

import asyncio
import json
import os
import pickle
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

import ngs_cipher
import test_tls13 as t13
import tls13
import websocket
from tools.tls13_proxy import Recorder, TlsDecoder, TlsProxy
from tools.tls13_keys_watch import watch_recording

REPO = Path(__file__).resolve().parents[1]


def write_recording(path, c2s, s2c, port=443, process=None):
    lines = [{"kind": "connection_open", "conn": 3, "destination": ["127.0.0.1", port],
              "process": process or t13.WINE},
             {"kind": "data", "conn": 3, "direction": "client_to_server", "hex": c2s.hex()},
             {"kind": "data", "conn": 3, "direction": "server_to_client", "hex": s2c.hex()},
             {"kind": "connection_close", "conn": 3}]
    with open(path, "w") as f:
        for i, line in enumerate(lines):
            f.write(json.dumps({**line, "time_ns": i}, separators=(",", ":")) + "\n")


def ws_frame(payload, opcode=1, mask=None):
    n = len(payload)
    head = bytes([0x80 | opcode]) + (bytes([n | (0x80 if mask else 0)]) if n < 126
                                    else bytes([126 | (0x80 if mask else 0)]) + struct.pack(">H", n))
    if mask:
        return head + mask + bytes(x ^ mask[i & 3] for i, x in enumerate(payload))
    return head + payload


class TlsDecoderTest(unittest.TestCase):
    def test_split_client_hello(self):
        decoder = TlsDecoder()
        wire = t13.client_hello()
        out = []
        for i in range(0, len(wire), 7):
            out += decoder.feed("client_to_server", wire[i:i + 7], i)
        self.assertEqual([(r["kind"], r["sni"]) for r in out], [("tls_client_hello", t13.HOST.decode())])
        self.assertEqual(decoder.summary()["client_to_server"]["status"], "tls")

    def test_non_tls_is_forwarded_without_a_hello_event(self):
        decoder = TlsDecoder()
        self.assertEqual(decoder.feed("client_to_server", b"ping\n", 0), [])
        self.assertEqual(decoder.status, "not_tls")


class ProxyPipelineTest(unittest.TestCase):
    def test_proxy_recording_to_ngs_decryption(self):
        response = {"emergency_stop": 0, "auth_cycle": 60, "token": "sensitive-token"}
        encoded = ngs_cipher.encrypt_response(json.dumps(response).encode(), 0x5A)
        reply = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                 + str(len(encoded)).encode() + b"\r\n\r\n" + encoded)
        c = t13.conn()
        c2s = c["c2s"][0][1]
        s2c = (t13.server_hello() + t13.record(20, b"\x01")
               + t13.seal(t13.SHS, [(22, t13.FINISHED)]) + t13.seal(t13.SAP, [(23, reply)]))
        received = bytearray()

        async def run(recording):
            async def server(reader, writer):
                received.extend(await reader.readexactly(len(c2s)))
                for i in range(0, len(s2c), 31):
                    writer.write(s2c[i:i + 31])
                    await writer.drain()
                writer.close()

            upstream = await asyncio.start_server(server, "127.0.0.1", 0)
            address = upstream.sockets[0].getsockname()[:2]
            recorder = Recorder(recording)
            proxy = TlsProxy(recorder, resolve=lambda sock: address, owner=lambda client: t13.WINE)
            listener = await proxy.serve("127.0.0.1", 0)
            reader, writer = await asyncio.open_connection(*listener.sockets[0].getsockname()[:2])
            for i in range(0, len(c2s), 11):
                writer.write(c2s[i:i + 11])
                await writer.drain()
            got = await reader.readexactly(len(s2c))
            writer.close()
            await asyncio.sleep(0.05)
            listener.close()
            upstream.close()
            recorder.close()
            return got, address[1]

        with tempfile.TemporaryDirectory() as d:
            recording = os.path.join(d, "proxy.jsonl")
            got, port = asyncio.run(run(recording))
            self.assertEqual(got, s2c)
            self.assertEqual(bytes(received), c2s)
            records = [json.loads(line) for line in Path(recording).read_text().splitlines()]
            opened = next(r for r in records if r["kind"] == "connection_open")
            self.assertEqual(opened["destination"][1], port)
            self.assertNotEqual(port, 443)
            self.assertEqual(next(r for r in records if r["kind"] == "tls_client_hello")["sni"],
                             t13.HOST.decode())
            conns = tls13.read_recording(recording, t13.HOST.decode())
            self.assertEqual(list(conns), [1])
            self.assertEqual(tls13.read_recording(recording, "wrong.example"), {})

            block = os.urandom(16) + t13.CHS + os.urandom(8) + t13.SHS + os.urandom(8) + t13.CAP + os.urandom(8) + t13.SAP
            scan, keylog = os.path.join(d, "scan.pkl"), os.path.join(d, "keys.log")
            with open(scan, "wb") as f:
                pickle.dump({"blocks": {0x1000: block}}, f)
            tool = [sys.executable, str(REPO / "tools/tls13_keys.py")]
            subprocess.run(tool + ["find", recording, scan, "--keylog", keylog],
                           capture_output=True, text=True, check=True)
            out = subprocess.run(tool + ["decrypt", recording, "--keylog", keylog, "--decode"],
                                 capture_output=True, text=True, check=True).stdout
            self.assertIn("POST /v2", out)
            self.assertIn('"emergency_stop": 0', out)
            self.assertIn('"auth_cycle": 60', out)
            self.assertNotIn("sensitive-token", out)


class WatcherTest(unittest.TestCase):
    def test_watcher_reassembles_split_client_hello(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "proxy.jsonl")
            Path(path).touch()
            needles, stop = {}, threading.Event()
            thread = threading.Thread(target=watch_recording, args=(path, [t13.HOST.decode()], needles, stop))
            thread.start()
            wire = t13.client_hello()
            with open(path, "a") as f:
                for i in range(0, len(wire), 9):
                    r = {"kind": "data", "conn": 8, "direction": "client_to_server",
                         "time_ns": i, "hex": wire[i:i + 9].hex()}
                    f.write(json.dumps(r, separators=(",", ":")) + "\n")
                    f.flush()
                f.write(json.dumps({"kind": "tls_client_hello", "conn": 8, "sni": t13.HOST.decode()},
                                   separators=(",", ":")) + "\n")
                f.flush()
                for _ in range(100):
                    if needles:
                        break
                    time.sleep(0.01)
            stop.set()
            thread.join(1)
            self.assertEqual(list(needles), [t13.CLIENT_RANDOM])


class ApplicationDecoderTest(unittest.TestCase):
    def test_ngs_roundtrip(self):
        plain = b'{"detected":[],"emergency_stop":0}'
        wire = ngs_cipher.encrypt_response(plain, 0xA7)
        self.assertEqual(ngs_cipher.decrypt_response(wire), plain)
        self.assertEqual(ngs_cipher.decrypt_response(wire, want="json")["emergency_stop"], 0)

    def test_websocket_cli_decryption_and_masking(self):
        upgrade = (b"GET /socket?product=12345&token=abcdefgh HTTP/1.1\r\nHost: ws.example\r\n"
                   b"Upgrade: websocket\r\nCookie: sid=secretvalue; other=1\r\n\r\n")
        switch = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n"
        ping = json.dumps({"headers": {"eventType": "Ping"}, "body": {}}).encode()
        pong = json.dumps({"headers": {"eventType": "Pong"}, "body": {"accountNo": 123456789}}).encode()
        s2c = (t13.server_hello() + t13.record(20, b"\x01") + t13.seal(t13.SHS, [(22, t13.FINISHED)])
               + t13.seal(t13.SAP, [(23, switch), (23, ws_frame(pong)), (23, ws_frame(pong))]))
        c2s = (t13.client_hello() + t13.seal(t13.CHS, [(22, t13.FINISHED)])
               + t13.seal(t13.CAP, [(23, upgrade), (23, ws_frame(ping, mask=b"\x01\x02\x03\x04")),
                                    (23, ws_frame(ping, mask=b"\x05\x06\x07\x08"))]))
        with tempfile.TemporaryDirectory() as d:
            recording, keylog = os.path.join(d, "proxy.jsonl"), os.path.join(d, "keys.log")
            write_recording(recording, c2s, s2c)
            tls13.write_keylog(keylog, {t13.CLIENT_RANDOM: {"CLIENT_TRAFFIC_SECRET_0": t13.CAP,
                                                            "SERVER_TRAFFIC_SECRET_0": t13.SAP}})
            out = subprocess.run([sys.executable, str(REPO / "tools/tls13_keys.py"), "decrypt", recording,
                                  "--keylog", keylog], capture_output=True, text=True, check=True).stdout
        self.assertIn("GET /socket?product=12…(5)&token=abcd…(8) HTTP/1.1", out)
        self.assertIn('"cookie": "names: sid, other"', out)
        self.assertNotIn("secretvalue", out)
        self.assertIn("ws c2s 2 x text Ping", out)
        self.assertIn("ws s2c 2 x text Pong", out)
        self.assertIn('"accountNo": "1234…(9d)"', out)

    def test_websocket_frame_boundaries(self):
        big = b"x" * 300
        stream = ws_frame(b"one", mask=b"\xaa\xbb\xcc\xdd") + ws_frame(big, opcode=2) + b"\x81"
        chunks = [(1, stream[:7]), (2, stream[7:100]), (3, stream[100:])]
        self.assertEqual(websocket.frames(chunks), [(1, True, 1, b"one"), (2, True, 2, big)])


if __name__ == "__main__":
    unittest.main()
