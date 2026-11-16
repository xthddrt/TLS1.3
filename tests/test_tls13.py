"""End-to-end TLS 1.3 checks using synthetic records and made-up secrets only."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import pickle
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import tls13

REPO = Path(__file__).resolve().parents[1]
SUITE = 0x1301
CLIENT_RANDOM = hashlib.sha256(b"synthetic client random").digest()
SERVER_RANDOM = hashlib.sha256(b"synthetic server random").digest()
SESSION_ID = hashlib.sha256(b"synthetic session id").digest()
HOST = b"x-test.example"
CHS = hashlib.sha256(b"client handshake").digest()
SHS = hashlib.sha256(b"server handshake").digest()
CAP = hashlib.sha256(b"client app 0").digest()
SAP = hashlib.sha256(b"server app 0").digest()
REQUEST = b"POST /v2 HTTP/1.1\r\nHost: x-test.example\r\nContent-Length: 5\r\n\r\nhello"
REPLY = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
FINISHED = b"\x14\x00\x00\x20" + bytes(32)
TICKET = b"\x04\x00\x00\x04" + bytes(4)
KEY_UPDATE = b"\x18\x00\x00\x01\x00"

spec = importlib.util.spec_from_file_location("launcher_keys_watch", REPO / "tools/launcher_keys_watch.py")
launcher_watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher_watch)
WINE = {"pid": 4242, "name": "CrUtilityMain", "path": "/opt/wine-stable/lib/wine/i386-unix/wine-preloader"}
NATIVE = {"pid": 4343, "name": "CrUtilityMain", "path": "/opt/google/chrome/chrome"}


def record(kind, body):
    return bytes([kind]) + b"\x03\x03" + struct.pack(">H", len(body)) + body


def seal(secret, items, suite=SUITE, start=0):
    aead, _, _ = tls13.SUITES[suite]
    key, iv = tls13.key_iv(secret, suite)
    out = b""
    for i, (typ, content) in enumerate(items):
        plain = content + bytes([typ])
        nonce = (int.from_bytes(iv, "big") ^ (start + i)).to_bytes(12, "big")
        aad = b"\x17\x03\x03" + struct.pack(">H", len(plain) + 16)
        out += record(23, aead(key).encrypt(nonce, plain, aad))
    return out


def client_hello():
    name = b"\x00" + struct.pack(">H", len(HOST)) + HOST
    sni = struct.pack(">HHH", 0, len(name) + 2, len(name)) + name
    body = (b"\x03\x03" + CLIENT_RANDOM + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
            + struct.pack(">H", len(sni)) + sni)
    return record(22, b"\x01" + len(body).to_bytes(3, "big") + body)


def server_hello():
    body = (b"\x03\x03" + SERVER_RANDOM + bytes([len(SESSION_ID)]) + SESSION_ID
            + struct.pack(">H", SUITE) + b"\x00")
    return record(22, b"\x02" + len(body).to_bytes(3, "big") + body)


def conn():
    s2c = (server_hello() + record(20, b"\x01")
           + seal(SHS, [(22, b"\x08\x00\x00\x02\x00\x00"), (22, b"\x0b\x00\x00\x01\x00"), (22, FINISHED)])
           + seal(SAP, [(22, TICKET), (23, REPLY)]))
    c2s = client_hello() + seal(CHS, [(22, FINISHED)]) + seal(CAP, [(23, REQUEST)])
    return {"c2s": [(0, c2s)], "s2c": [(0, s2c)]}


class Tls13Test(unittest.TestCase):
    def test_structure_and_suite(self):
        c = conn()
        self.assertEqual(tls13.client_random(c), CLIENT_RANDOM)
        self.assertEqual(tls13.tls_client_hello_sni(c["c2s"][0][1]), HOST.decode())
        self.assertEqual(tls13.suite(c), SUITE)
        self.assertEqual(len(tls13.app_records(c, "s2c")), 5)
        self.assertEqual(len(tls13.app_records(c, "c2s")), 2)

    def test_read_recording_discards_non_tls_and_reassembles_hello(self):
        c = conn()
        hello = c["c2s"][0][1]
        lines = [
            {"kind": "connection_open", "conn": 1, "destination": ["192.0.2.1", 8484]},
            {"kind": "data", "conn": 1, "direction": "client_to_server", "hex": (b"ping\n" * 100).hex()},
            {"kind": "connection_open", "conn": 2, "destination": ["192.0.2.1", 9443]},
            {"kind": "data", "conn": 2, "direction": "client_to_server", "hex": hello[:13].hex()},
            {"kind": "data", "conn": 2, "direction": "client_to_server", "hex": hello[13:].hex()},
            {"kind": "data", "conn": 2, "direction": "server_to_client", "hex": c["s2c"][0][1].hex()},
            {"kind": "connection_open", "conn": 3, "destination": ["192.0.2.1", 8484]},
            {"kind": "data", "conn": 3, "direction": "server_to_client", "hex": (b"game" * 100).hex()},
        ]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "proxy.jsonl")
            with open(path, "w") as f:
                for i, line in enumerate(lines):
                    f.write(json.dumps({**line, "time_ns": i}, separators=(",", ":")) + "\n")
            self.assertEqual(list(tls13.read_recording(path)), [2])
            self.assertEqual(list(tls13.read_recording(path, HOST.decode())), [2])
            self.assertEqual(tls13.read_recording(path, "wrong.example"), {})

    def test_classify(self):
        c = conn()
        srv, cli = tls13.app_records(c, "s2c"), tls13.app_records(c, "c2s")
        self.assertEqual(tls13.classify(SHS, srv, SUITE), ("handshake", 0))
        self.assertEqual(tls13.classify(SAP, srv, SUITE), ("app", 3))
        self.assertEqual(tls13.classify(CHS, cli, SUITE), ("handshake", 0))
        self.assertEqual(tls13.classify(CAP, cli, SUITE), ("app", 1))
        self.assertIsNone(tls13.classify(bytes(32), srv, SUITE))
        self.assertIsNone(tls13.classify(SAP, cli, SUITE))

    def test_find_secrets(self):
        block = os.urandom(32) + CHS + os.urandom(24) + SHS + os.urandom(8) + CAP + os.urandom(16) + SAP
        found = tls13.find_secrets(conn(), [block])
        self.assertEqual(found, {
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET": CHS,
            "SERVER_HANDSHAKE_TRAFFIC_SECRET": SHS,
            "CLIENT_TRAFFIC_SECRET_0": CAP,
            "SERVER_TRAFFIC_SECRET_0": SAP,
        })

    def test_decrypt_full_and_app_only(self):
        c = conn()
        full = tls13.decrypt_dir(tls13.app_records(c, "s2c"), SUITE, handshake=SHS, app=SAP)
        self.assertEqual([typ for _, typ, _ in full], [22, 22, 22, 22, 23])
        self.assertEqual(full[-1][2], REPLY)
        app_only = tls13.decrypt_dir(tls13.app_records(c, "s2c"), SUITE, app=SAP)
        self.assertEqual([typ for _, typ, _ in app_only], [None, None, None, 22, 23])
        (_, _, _, body), = tls13.http_messages(tls13.app_data(app_only))
        self.assertEqual(body, b"hi")
        cli = tls13.decrypt_dir(tls13.app_records(c, "c2s"), SUITE, app=CAP)
        (_, line, _, body), = tls13.http_messages(tls13.app_data(cli))
        self.assertEqual((line, body), ("POST /v2 HTTP/1.1", b"hello"))

    def test_key_update(self):
        recs = tls13.records([(0, seal(SAP, [(23, b"before")])
                               + seal(SAP, [(22, KEY_UPDATE)], start=1)
                               + seal(tls13.next_secret(SAP, SUITE), [(23, b"after")]))])
        recs = [(t, b) for t, k, _, b in recs if k == 23]
        out = tls13.decrypt_dir(recs, SUITE, app=SAP)
        self.assertEqual([(typ, pl) for _, typ, pl in out],
                         [(23, b"before"), (22, KEY_UPDATE), (23, b"after")])

    def test_keylog_roundtrip(self):
        secrets = {"SERVER_TRAFFIC_SECRET_0": SAP, "CLIENT_TRAFFIC_SECRET_0": CAP}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "keys.log")
            tls13.write_keylog(path, {CLIENT_RANDOM: secrets})
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(tls13.read_keylog(path), {CLIENT_RANDOM: secrets})


class Tls13CliTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.rec = os.path.join(self.dir.name, "proxy.jsonl")
        c = conn()
        lines = [
            {"kind": "connection_open", "conn": 3, "destination": ["192.0.2.9", 443]},
            {"kind": "data", "conn": 3, "direction": "client_to_server", "hex": c["c2s"][0][1].hex()},
            {"kind": "data", "conn": 3, "direction": "server_to_client", "hex": c["s2c"][0][1].hex()},
            {"kind": "connection_close", "conn": 3},
        ]
        with open(self.rec, "w") as f:
            for i, line in enumerate(lines):
                f.write(json.dumps({**line, "time_ns": i}, separators=(",", ":")) + "\n")

    def tearDown(self):
        self.dir.cleanup()

    def test_find_and_decrypt(self):
        tool = [sys.executable, str(REPO / "tools/tls13_keys.py")]
        run = dict(capture_output=True, text=True, check=True)
        out = subprocess.run(tool + ["needles", self.rec, "--sni", HOST.decode()], **run).stdout
        self.assertEqual(out.split(), [CLIENT_RANDOM.hex()])
        scan = os.path.join(self.dir.name, "scan.pkl")
        block = os.urandom(16) + CHS + os.urandom(8) + SHS + os.urandom(8) + CAP + os.urandom(8) + SAP
        with open(scan, "wb") as f:
            pickle.dump({"blocks": {0x1000: block}}, f)
        keylog = os.path.join(self.dir.name, "keys.log")
        subprocess.run(tool + ["find", self.rec, scan, "--keylog", keylog, "--sni", HOST.decode()], **run)
        self.assertEqual(os.stat(keylog).st_mode & 0o777, 0o600)
        self.assertEqual(tls13.read_keylog(keylog), {CLIENT_RANDOM: {
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET": CHS,
            "SERVER_HANDSHAKE_TRAFFIC_SECRET": SHS,
            "CLIENT_TRAFFIC_SECRET_0": CAP,
            "SERVER_TRAFFIC_SECRET_0": SAP,
        }})
        plaintext = os.path.join(self.dir.name, "plain.jsonl")
        out = subprocess.run(tool + ["decrypt", self.rec, "--keylog", keylog, "--sni", HOST.decode(),
                                     "--plaintext", plaintext], **run).stdout
        self.assertIn("POST /v2", out)
        self.assertIn("HTTP/1.1 200 OK", out)
        self.assertEqual(os.stat(plaintext).st_mode & 0o777, 0o600)
        bad = subprocess.run(tool + ["decrypt", self.rec, "--keylog", keylog,
                                     "--plaintext", str(REPO / "plain13.jsonl")], capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0)
        self.assertFalse((REPO / "plain13.jsonl").exists())


class LauncherWatchTest(unittest.TestCase):
    def test_launcher_filter(self):
        self.assertTrue(launcher_watch.launcher(WINE))
        self.assertFalse(launcher_watch.launcher(NATIVE))
        self.assertFalse(launcher_watch.launcher(None))

    def test_follow_keeps_a_partial_line(self):
        rec = io.StringIO()
        conns = {}
        rec.write(json.dumps({"kind": "connection_open", "conn": 1, "destination": ["192.0.2.1", 443],
                              "process": WINE, "time_ns": 0}, separators=(",", ":")) + "\n")
        line = json.dumps({"kind": "data", "conn": 1, "direction": "client_to_server", "hex": "aabb",
                           "time_ns": 5}, separators=(",", ":")) + "\n"
        rec.write(line[:20])
        rec.seek(0)
        part = launcher_watch.follow(rec, conns)
        self.assertEqual((conns[1]["pid"], conns[1]["c2s"], part), (4242, [], line[:20]))
        pos = rec.tell()
        rec.write(line[20:])
        rec.seek(pos)
        self.assertEqual(launcher_watch.follow(rec, conns, part), "")
        self.assertEqual(conns[1]["c2s"], [(5, b"\xaa\xbb")])

    def test_ready_and_complete(self):
        self.assertTrue(launcher_watch.ready(conn()))
        self.assertTrue(launcher_watch.complete({"CLIENT_TRAFFIC_SECRET_0": CAP, "SERVER_TRAFFIC_SECRET_0": SAP}))
        self.assertFalse(launcher_watch.complete({"CLIENT_TRAFFIC_SECRET_0": CAP}))


if __name__ == "__main__":
    unittest.main()
