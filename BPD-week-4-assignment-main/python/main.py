#!/usr/bin/env python3
"""
Exercise 4: Bitcoin P2P — retrieve and parse block 840000 without RPC.

Steps:
  1. Discover mainnet Bitcoin nodes via DNS seeds
  2. Connect on port 8333
  3. Perform version/verack handshake
  4. Request block 840000 via getdata
  5. Parse header, hash, total fees, and miner info
  6. Write out.txt with 4 lines
"""

import socket
import struct
import hashlib
import time
import random
import subprocess
import sys
from pathlib import Path

# ---------- Configuration ----------
MAINNET_PORT = 8333
MAGIC = b'\xf9\xbe\xb4\xd9'
PROTOCOL_VERSION = 70015
USER_AGENT = b"/Satoshi:24.0.1/"

BLOCK_HASH = "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"

# Write out.txt to the parent of python/ (as the assignment runner expects)
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


# ---------- Message helpers ----------
def create_message(command, payload=b""):
    """Build a Bitcoin P2P message: magic || cmd(12) || len(4) || checksum(4) || payload."""
    cmd = command.ljust(12, "\x00").encode("ascii")
    length = struct.pack("<I", len(payload))
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return MAGIC + cmd + length + checksum + payload


def create_version_payload():
    """Build the version message payload."""
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
    """Read exactly n bytes or return None on EOF."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def recv_message(sock):
    """Read one full Bitcoin message; return (command, payload)."""
    header = recv_all(sock, 24)
    if not header:
        return None, None
    if header[:4] != MAGIC:
        raise Exception(f"Bad magic: {header[:4].hex()}")
    command = header[4:16].decode("ascii", errors="ignore").strip("\x00")
    length = struct.unpack("<I", header[16:20])[0]
    payload = recv_all(sock, length) if length else b""
    return command, payload or b""


def parse_varint(data, offset):
    """Parse a Bitcoin CompactSize (varint)."""
    first = data[offset]
    if first < 0xfd:
        return first, offset + 1
    if first == 0xfd:
        return struct.unpack("<H", data[offset+1:offset+3])[0], offset + 3
    if first == 0xfe:
        return struct.unpack("<I", data[offset+1:offset+5])[0], offset + 5
    return struct.unpack("<Q", data[offset+1:offset+9])[0], offset + 9


# ---------- Discovery ----------
def resolve_seeds():
    """Ask DNS seeds for mainnet node IPs."""
    ips = []
    for seed in DNS_SEEDS:
        try:
            out = subprocess.run(["dig", "+short", seed, "A"],
                                 capture_output=True, text=True, timeout=5).stdout
            for line in out.strip().split("\n"):
                line = line.strip()
                if line and line[0].isdigit() and "." in line:
                    ips.append(line)
            if ips:
                print(f"[INFO] Resolved {len(ips)} nodes from {seed}")
                break
        except Exception as e:
            print(f"[WARN] {seed}: {e}")
    return ips


def test_node(ip, port=MAINNET_PORT, timeout=3):
    """Quick TCP reachability check."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return True
    except Exception:
        return False


# ---------- Handshake + block fetch ----------
def handshake(ip):
    """Connect and perform version/verack handshake."""
    print(f"[INFO] Connecting to {ip}:{MAINNET_PORT}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(20)
    sock.connect((ip, MAINNET_PORT))
    print("[INFO] TCP connected. Sending version...")
    sock.send(create_message("version", create_version_payload()))

    got_version = got_verack = False
    for _ in range(20):
        cmd, _ = recv_message(sock)
        if cmd == "version":
            print("[INFO] Received version")
            got_version = True
            sock.send(create_message("verack"))
        elif cmd == "verack":
            print("[INFO] Received verack")
            got_verack = True
        if got_version and got_verack:
            print("[INFO] Handshake complete")
            return sock
    raise Exception("Handshake failed")


def get_block(sock):
    """Request the block via getdata and wait for the block message."""
    hash_le = bytes.fromhex(BLOCK_HASH)[::-1]
    payload = struct.pack("<B", 1) + struct.pack("<I", 2) + hash_le
    print(f"[INFO] Requesting block {BLOCK_HASH[:16]}...")
    sock.send(create_message("getdata", payload))
    for _ in range(60):
        cmd, data = recv_message(sock)
        if cmd == "block":
            print(f"[INFO] Got block ({len(data)} bytes)")
            return data
        if cmd == "notfound":
            raise Exception("Block not found")
    raise Exception("Block not received")


# ---------- Parsing ----------
def parse_block(raw):
    """Return (header_hex, block_hash, total_fees, miner_info)."""
    header = raw[:80]
    header_hex = header.hex()
    block_hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()

    offset = 80
    tx_count, offset = parse_varint(raw, offset)
    print(f"[INFO] {tx_count} transactions")

    # coinbase tx
    offset += 4
    _, offset = parse_varint(raw, offset)
    offset += 32 + 4
    slen, offset = parse_varint(raw, offset)
    coinbase_script = raw[offset:offset+slen]
    offset += slen
    offset += 4

    out_count, offset = parse_varint(raw, offset)
    total_value = 0
    for _ in range(out_count):
        value = struct.unpack("<Q", raw[offset:offset+8])[0]
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

    known = {
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
    for key, name in known.items():
        if key in low:
            miner_info = name
            break

    return header_hex, block_hash, total_fees, miner_info


# ---------- Main ----------
def main():
    print("=" * 60)
    print(" Exercise 4: P2P Block 840000 Retrieval")
    print("=" * 60)

    print("\n[1/4] Discovering nodes via DNS seeds...")
    candidates = resolve_seeds()
    for ip in FALLBACK_NODES:
        if ip not in candidates:
            candidates.append(ip)
    if not candidates:
        print("[ERROR] No candidates")
        sys.exit(1)

    print(f"[INFO] Testing {len(candidates)} nodes...")
    working = None
    for ip in candidates:
        print(f"[INFO]  {ip}...", end=" ")
        if test_node(ip):
            print("ALIVE")
            working = ip
            break
        print("dead")
    if not working:
        print("[ERROR] No reachable node")
        sys.exit(1)

    print(f"\n[2/4] Handshake with {working}")
    sock = handshake(working)

    print(f"\n[3/4] Retrieving block")
    raw = get_block(sock)
    sock.close()

    print(f"\n[4/4] Parsing block")
    header_hex, block_hash, total_fees, miner_info = parse_block(raw)

    with open(OUT_FILE, "w") as f:
        f.write(f"{header_hex}\n")
        f.write(f"{block_hash}\n")
        f.write(f"{total_fees}\n")
        f.write(f"{miner_info}\n")

    print("\n" + "=" * 60)
    print(" DONE")
    print("=" * 60)
    print(f"Header   : {header_hex[:64]}...")
    print(f"Hash     : {block_hash}")
    print(f"Fees     : {total_fees} sats")
    print(f"Miner    : {miner_info}")
    print(f"Written to {OUT_FILE}")


if __name__ == "__main__":
    main()
