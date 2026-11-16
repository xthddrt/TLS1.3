#!/usr/bin/env python3
"""Transparent TCP proxy that records TLS connections without changing any bytes.

Usually started by tools/game_proxy.sh. For local testing, --listen and --file can be
used directly; redirected connections obtain their real destination with SO_ORIGINAL_DST.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import signal
import socket
import struct
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import tls13  # noqa: E402

SO_ORIGINAL_DST = 80
BROKERS = {"wine", "wine64", "wine-preloader", "wine64-preloader", "wineserver", "wineserver64"}


def original_destination(sock):
    raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    port, address = struct.unpack_from("!2xH4s", raw)
    return socket.inet_ntoa(address), port


class Recorder:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = open(self.path, "a", encoding="utf-8", buffering=1)
        os.chmod(self.path, 0o600)
        self.failed = None

    def write(self, record):
        """A recording failure never interrupts forwarding."""
        if self.failed:
            return
        record.setdefault("time_ns", time.time_ns())
        try:
            self.handle.write(json.dumps(record, separators=(",", ":")) + "\n")
        except (OSError, ValueError) as error:
            self.failed = str(error)
            print(f"RECORDING STOPPED: {error}; connections are still forwarded", file=sys.stderr, flush=True)

    def close(self):
        self.handle.close()


class TlsDecoder:
    """Recognize a complete ClientHello even when TCP splits its first record."""

    def __init__(self):
        self.buffer = bytearray()
        self.status = "waiting"

    def feed(self, direction, data, time_ns):
        if direction != "client_to_server" or self.status != "waiting":
            return []
        self.buffer.extend(data)
        if self.buffer[:1] != b"\x16" or (len(self.buffer) > 1 and self.buffer[1] != 3):
            self.status = "not_tls"
            return []
        complete = tls13.records([(time_ns, bytes(self.buffer))])
        if not complete:
            return []
        _, kind, _, body = complete[0]
        if kind != 22 or body[:1] != b"\x01":
            self.status = "not_tls"
            return []
        self.status = "tls"
        return [{"kind": "tls_client_hello", "time_ns": time_ns,
                 "sni": tls13.tls_client_hello_sni(bytes(self.buffer))}]

    def summary(self):
        return {"client_to_server": {"status": self.status}}


def _table_address(text, ipv6):
    try:
        raw = bytearray.fromhex(text)
    except ValueError:
        return None
    if ipv6:
        if len(raw) != 16:
            return None
        for offset in range(0, 16, 4):
            raw[offset:offset + 4] = raw[offset:offset + 4][::-1]
    else:
        if len(raw) != 4:
            return None
        raw.reverse()
    try:
        return str(ipaddress.ip_address(bytes(raw)))
    except ValueError:
        return None


def _start_time(path):
    try:
        fields = (path / "stat").read_text(encoding="utf-8", errors="replace").rsplit(")", 1)[1].split()
        return int(fields[19])
    except (OSError, IndexError, ValueError):
        return None


class SocketOwnerResolver:
    """Attribute a local TCP endpoint to a process through its socket inode."""

    def __init__(self, proc=Path("/proc")):
        self.proc = Path(proc)
        self.cache = {}

    def inodes(self, address, port):
        try:
            wanted = ipaddress.ip_address(address)
        except ValueError:
            return set()
        found = set()
        for name, ipv6 in (("tcp", False), ("tcp6", True)):
            try:
                lines = (self.proc / "net" / name).read_text(encoding="utf-8", errors="replace").splitlines()[1:]
            except OSError:
                continue
            for line in lines:
                fields = line.split()
                if len(fields) < 10:
                    continue
                address_hex, separator, port_hex = fields[1].partition(":")
                if not separator:
                    continue
                try:
                    if int(port_hex, 16) != int(port):
                        continue
                except ValueError:
                    continue
                decoded = _table_address(address_hex, ipv6)
                if decoded is None:
                    continue
                try:
                    if ipaddress.ip_address(decoded) == wanted:
                        found.add(int(fields[9]))
                except ValueError:
                    continue
        return found

    def lookup(self, address):
        """Return unique application attribution, or all candidates when ambiguous."""
        if not address or len(address) < 2:
            return {"pid": None, "name": None, "path": None, "evidence": "client_address_unavailable"}
        host, port = str(address[0]), int(address[1])
        key = (host, port)
        if key in self.cache:
            return self.cache[key]
        inodes = self.inodes(host, port)
        candidates = []
        if inodes:
            try:
                processes = [entry for entry in self.proc.iterdir() if entry.name.isdecimal()]
            except OSError:
                processes = []
            for process in processes:
                try:
                    fds = list((process / "fd").iterdir())
                except OSError:
                    continue
                for fd in fds:
                    try:
                        target = os.readlink(fd)
                    except OSError:
                        continue
                    if target.startswith("socket:[") and target[8:-1].isdigit():
                        inode = int(target[8:-1])
                        if inode not in inodes:
                            continue
                        try:
                            name = (process / "comm").read_text(encoding="utf-8", errors="replace").strip()
                        except OSError:
                            name = None
                        try:
                            path = os.readlink(process / "exe")
                        except OSError:
                            path = None
                        candidates.append({"pid": int(process.name), "name": name, "path": path,
                                           "start_time_ticks": _start_time(process), "socket_inode": inode,
                                           "evidence": "proc_fd_socket_inode"})
                        break
        applications = [c for c in candidates if (c.get("name") or "").lower() not in BROKERS]
        if len(applications) == 1:
            result = dict(applications[0])
            result["candidates"] = candidates
            result["attribution"] = "unique_non_broker" if len(candidates) > 1 else "unique_owner"
        else:
            result = {"pid": None, "name": None, "path": None, "candidates": candidates,
                      "socket_inode": sorted(inodes)[0] if len(inodes) == 1 else None,
                      "evidence": "ambiguous_socket_owners" if applications else "application_owner_not_found"}
        self.cache[key] = result
        return result


class TlsProxy:
    HALF_CLOSE_IDLE_S = 300

    def __init__(self, recorder, mark=None, resolve=original_destination, owner=None):
        self.recorder = recorder
        self.mark = mark
        self.resolve = resolve
        self.owner = owner or (lambda address: SocketOwnerResolver().lookup(address))
        self.listen_address = None
        self.next_id = 1
        self.active = set()

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        self.active.add(task)
        try:
            await self._handle(reader, writer)
        finally:
            self.active.discard(task)

    async def _handle(self, reader, writer):
        conn = self.next_id
        self.next_id += 1
        client_sock = writer.get_extra_info("socket")
        client = writer.get_extra_info("peername")[:2]
        record = {"conn": conn, "client": list(client)}
        try:
            destination = self.resolve(client_sock)
        except OSError as error:
            self.recorder.write({"kind": "connection_refused", **record,
                                 "reason": f"no original destination: {error}"})
            writer.close()
            return
        if tuple(destination) == tuple(self.listen_address or ()):
            self.recorder.write({"kind": "connection_refused", **record,
                                 "reason": "connection made to the proxy itself"})
            writer.close()
            return
        process = await asyncio.get_running_loop().run_in_executor(None, self.owner, client)
        record.update(destination=list(destination), process=process)
        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            upstream.setblocking(False)
            if self.mark is not None:
                upstream.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, self.mark)
            await asyncio.get_running_loop().sock_connect(upstream, tuple(destination))
            up_reader, up_writer = await asyncio.open_connection(sock=upstream)
        except OSError as error:
            upstream.close()
            self.recorder.write({"kind": "connection_failed", **record, "error": str(error)})
            writer.transport.abort()
            return
        for sock in (client_sock, upstream):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.recorder.write({"kind": "connection_open", **record})
        decoder = TlsDecoder()
        observing = [True]

        def observe(direction, data, time_ns):
            try:
                for item in decoder.feed(direction, data, time_ns):
                    item["conn"] = conn
                    self.recorder.write(item)
            except Exception as error:
                self.recorder.write({"kind": "decode_notice", "conn": conn, "direction": direction,
                                     "status": "decoder_error", "detail": repr(error)})
                observing[0] = False

        half_closed = asyncio.Event()
        last_data = [time.monotonic()]

        async def pump(src, dst, direction):
            try:
                while data := await src.read(65536):
                    dst.write(data)
                    last_data[0] = time.monotonic()
                    time_ns = time.time_ns()
                    self.recorder.write({"kind": "data", "conn": conn, "direction": direction,
                                         "time_ns": time_ns, "hex": data.hex()})
                    if observing[0]:
                        observe(direction, data, time_ns)
                    await dst.drain()
                if dst.can_write_eof():
                    dst.write_eof()
            except Exception:
                dst.transport.abort()
            finally:
                half_closed.set()

        async def end_idle_half_close():
            await half_closed.wait()
            while time.monotonic() - last_data[0] < self.HALF_CLOSE_IDLE_S:
                await asyncio.sleep(min(10, self.HALF_CLOSE_IDLE_S))
            for side in (writer, up_writer):
                side.transport.abort()

        guard = asyncio.ensure_future(end_idle_half_close())
        await asyncio.gather(pump(reader, up_writer, "client_to_server"),
                             pump(up_reader, writer, "server_to_client"))
        guard.cancel()
        for side in (writer, up_writer):
            side.close()
        self.recorder.write({"kind": "connection_close", "conn": conn, "decode": decoder.summary()})

    async def serve_until_stopped(self, host, port, stop, say=print):
        """On the first stop, drain open connections; a second stop cuts them."""
        server = await self.serve(host, port)
        say(f"LISTENING {host}:{port} RECORDING {self.recorder.path}")
        await stop.wait()
        server.close()
        if self.active:
            stop.clear()
            self.recorder.write({"kind": "proxy_draining", "open": len(self.active)})
            say(f"DRAINING {len(self.active)} open connection(s); stop again to cut them")
            drained = asyncio.ensure_future(asyncio.gather(*self.active, return_exceptions=True))
            second = asyncio.ensure_future(stop.wait())
            await asyncio.wait([drained, second], return_when=asyncio.FIRST_COMPLETED)
            second.cancel()
        return len(self.active)

    async def serve(self, host, port):
        server = await asyncio.start_server(self.handle, host, port)
        self.listen_address = server.sockets[0].getsockname()[:2]
        self.recorder.write({"kind": "proxy_start", "listen": list(self.listen_address), "mark": self.mark})
        return server


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--listen", default="127.0.0.1:18400", metavar="HOST:PORT")
    ap.add_argument("--file", default=str(Path("captures") / time.strftime("proxy-%Y%m%d-%H%M%S.jsonl")))
    ap.add_argument("--mark", metavar="N", help="SO_MARK for upstream connections, for example 0x1313")
    args = ap.parse_args()
    host, _, port = args.listen.rpartition(":")
    recorder = Recorder(args.file)
    proxy = TlsProxy(recorder, mark=int(args.mark, 0) if args.mark else None)
    cut = []

    async def run():
        stop = asyncio.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            asyncio.get_running_loop().add_signal_handler(sig, stop.set)
        cut.append(await proxy.serve_until_stopped(host, int(port), stop,
                                                   say=lambda text: print(text, flush=True)))

    try:
        asyncio.run(run())
    finally:
        recorder.write({"kind": "proxy_stop", "connections_cut": cut[0] if cut else None})
        recorder.close()


if __name__ == "__main__":
    main()
