#!/usr/bin/env python3

import hashlib
import random
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

MAINNET_PORT = 8333
MAGIC = b"\xf9\xbe\xb4\xd9"
PROTOCOL_VERSION = 70015
USER_AGENT = b"/Satoshi:24.0.1/"

BLOCK_HASH = "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"

OUT_FILE = Path(__file__).resolve().parent.parent / "out.txt"

DNS_SEEDS = [
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr.org",
    "seed.bitcoinstats.com",
    "seed.bitnodes.io",
]

FALLBACK_NODES = [
    "23.95.85.62",
    "142.93.224.149",
    "104.131.17.47",
    "46.166.138.124",
    "188.166.89.69",
]


def create_message(command, payload=b""):
    cmd = command.ljust(12, "\x00").encode("ascii")
    length = struct.pack("<I", len(payload))
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return MAGIC + cmd + length + checksum + payload


def create_version_payload():
    payload = struct.pack("<i", PROTOCOL_VERSION)
    payload += struct.pack("<Q", 0)
    payload += struct.pack("<Q", int(time.time()))
    payload += struct.pack("<Q", 0)
    payload += b"\x00" * 16 + struct.pack(">H", MAINNET_PORT)
    payload += struct.pack("<Q", 0)
    payload += b"\x00" * 16 + struct.pack(">H", MAINNET_PORT)
    payload += struct.pack("<Q", random.getrandbits(64))
    payload += struct.pack("<B", len(USER_AGENT)) + USER_AGENT
    payload += struct.pack("<i", 0)
    payload += struct.pack("<?", True)
    return payload


def recv_all(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def recv_message(sock):
    header = recv_all(sock, 24)
    if not header:
        return None, None
    if header[:4] != MAGIC:
        raise ValueError(f"bad magic: {header[:4].hex()}")
    command = header[4:16].decode("ascii", errors="ignore").strip("\x00")
    length = struct.unpack("<I", header[16:20])[0]
    payload = recv_all(sock, length) if length else b""
    return command, payload or b""


def parse_varint(data, offset):
    first = data[offset]
    if first < 0xfd:
        return first, offset + 1
    if first == 0xfd:
        return struct.unpack("<H", data[offset + 1:offset + 3])[0], offset + 3
    if first == 0xfe:
        return struct.unpack("<I", data[offset + 1:offset + 5])[0], offset + 5
    return struct.unpack("<Q", data[offset + 1:offset + 9])[0], offset + 9


def resolve_seeds():
    ips = []
    for seed in DNS_SEEDS:
        try:
            out = subprocess.run(
                ["dig", "+short", seed, "A"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            for line in out.strip().split("\n"):
                line = line.strip()
                if line and line[0].isdigit() and "." in line:
                    ips.append(line)
            if ips:
                break
        except Exception:
            continue
    return ips


def test_node(ip, port=MAINNET_PORT, timeout=3):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
        return True
    except OSError:
        return False


def handshake(ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(20)
    sock.connect((ip, MAINNET_PORT))
    sock.send(create_message("version", create_version_payload()))

    got_version = got_verack = False
    for _ in range(20):
        cmd, _ = recv_message(sock)
        if cmd == "version":
            got_version = True
            sock.send(create_message("verack"))
        elif cmd == "verack":
            got_verack = True
        if got_version and got_verack:
            return sock
    raise TimeoutError(f"handshake with {ip} did not complete")


def get_block(sock):
    hash_le = bytes.fromhex(BLOCK_HASH)[::-1]
    payload = struct.pack("<B", 1) + struct.pack("<I", 2) + hash_le
    sock.send(create_message("getdata", payload))
    for _ in range(60):
        cmd, data = recv_message(sock)
        if cmd == "block":
            return data
        if cmd == "notfound":
            raise LookupError("peer reported block not found")
    raise TimeoutError("block not received")


def parse_block(raw):
    header = raw[:80]
    header_hex = header.hex()
    block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()

    offset = 80
    tx_count, offset = parse_varint(raw, offset)

    # coinbase transaction
    offset += 4
    _, offset = parse_varint(raw, offset)
    offset += 32 + 4
    slen, offset = parse_varint(raw, offset)
    coinbase_script = raw[offset:offset + slen]
    offset += slen
    offset += 4

    out_count, offset = parse_varint(raw, offset)
    total_value = 0
    for _ in range(out_count):
        value = struct.unpack("<Q", raw[offset:offset + 8])[0]
        total_value += value
        offset += 8
        slen, offset = parse_varint(raw, offset)
        offset += slen

    subsidy = 312_500_000  # 3.125 BTC post-2024 halving
    total_fees = total_value - subsidy

    miner_info = "Unknown"
    try:
        text = coinbase_script[1:].decode("ascii", errors="ignore")
        text = "".join(c for c in text if 32 <= ord(c) <= 126)
        if text and len(text) > 2:
            miner_info = text[:100]
    except Exception:
        pass

    known_pools = {
        b"antpool": "AntPool",
        b"f2pool": "F2Pool",
        b"viabtc": "ViaBTC",
        b"btc.com": "BTC.com",
        b"foundry": "Foundry USA",
        b"marathon": "Marathon Digital",
        b"binance": "Binance Pool",
        b"slush": "Slush Pool",
        b"braiins": "Braiins Pool",
    }
    low = coinbase_script.lower()
    for key, name in known_pools.items():
        if key in low:
            miner_info = name
            break

    return header_hex, block_hash, total_fees, miner_info


def main():
    candidates = resolve_seeds()
    for ip in FALLBACK_NODES:
        if ip not in candidates:
            candidates.append(ip)
    if not candidates:
        sys.exit("no candidate nodes found")

    working = next((ip for ip in candidates if test_node(ip)), None)
    if not working:
        sys.exit("no reachable node found")

    sock = handshake(working)
    raw = get_block(sock)
    sock.close()

    header_hex, block_hash, total_fees, miner_info = parse_block(raw)

    with open(OUT_FILE, "w") as f:
        f.write(f"{header_hex}\n")
        f.write(f"{block_hash}\n")
        f.write(f"{total_fees}\n")
        f.write(f"{miner_info}\n")

    print(f"hash={block_hash} fees={total_fees} miner={miner_info}")
    print(f"written to {OUT_FILE}")


if __name__ == "__main__":
    main()
