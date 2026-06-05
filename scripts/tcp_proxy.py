#!/usr/bin/env python3
"""Small TCP proxy for exposing a loopback-only service on a LAN address."""

from __future__ import annotations

import argparse
import selectors
import socket
import sys
from typing import Tuple


def parse_host_port(value: str) -> Tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep or not host or not port:
        raise argparse.ArgumentTypeError(f"expected HOST:PORT, got {value!r}")
    return host, int(port)


def relay(client: socket.socket, target_addr: Tuple[str, int]) -> None:
    upstream = socket.create_connection(target_addr)
    upstream.setblocking(False)
    client.setblocking(False)

    selector = selectors.DefaultSelector()
    selector.register(client, selectors.EVENT_READ, upstream)
    selector.register(upstream, selectors.EVENT_READ, client)

    try:
        while True:
            events = selector.select()
            if not events:
                continue
            for key, _ in events:
                source = key.fileobj
                dest = key.data
                data = source.recv(65536)
                if not data:
                    return
                dest.sendall(data)
    finally:
        selector.close()
        upstream.close()
        client.close()


def serve(listen_addr: Tuple[str, int], target_addr: Tuple[str, int]) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(listen_addr)
    server.listen()
    print(f"proxy listening on {listen_addr[0]}:{listen_addr[1]} -> {target_addr[0]}:{target_addr[1]}")
    sys.stdout.flush()

    while True:
        client, _ = server.accept()
        pid = None
        try:
            pid = __import__("os").fork()
        except OSError:
            client.close()
            continue

        if pid == 0:
            server.close()
            relay(client, target_addr)
            raise SystemExit(0)

        client.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", required=True, type=parse_host_port)
    parser.add_argument("--target", required=True, type=parse_host_port)
    args = parser.parse_args()
    serve(args.listen, args.target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
