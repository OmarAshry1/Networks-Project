#!/usr/bin/env python3
import socket
import struct
import time
import argparse
import random

# =========================
# Protocol constants
# =========================
MAGIC = 0x54
VERSION = 1

MT_INIT = 0x0
MT_INIT_ACK = 0x1
MT_DATA = 0x2
MT_HEARTBEAT = 0x3
# MT_ACK exists but Phase2 typically does NOT use it

HEADER_FMT = "!BBHII"
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 12

MAX_PAYLOAD_BYTES = 200
MAX_BODY_BYTES = MAX_PAYLOAD_BYTES - HEADER_SIZE
READING_SIZE = 6  # sid(1) + fmt(1) + float32(4)

def pack_header(msg_type: int, device_id: int, seq: int, ts: int):
    ver_type = ((VERSION & 0x0F) << 4) | (msg_type & 0x0F)
    return struct.pack(HEADER_FMT, MAGIC, ver_type, device_id & 0xFFFF, seq & 0xFFFFFFFF, ts & 0xFFFFFFFF)

def build_init(device_id: int, seq: int, ts: int):
    return pack_header(MT_INIT, device_id, seq, ts)

def build_heartbeat(device_id: int, seq: int, ts: int):
    return pack_header(MT_HEARTBEAT, device_id, seq, ts)

def build_data(device_id: int, seq: int, ts: int, readings):
    header = pack_header(MT_DATA, device_id, seq, ts)
    body = bytearray()
    for sid, val in readings:
        body.append(sid & 0xFF)
        body.append(0x01)  # float32
        body.extend(struct.pack("!f", float(val)))
    return header + bytes(body)

def try_recv_init_ack(sock):
    try:
        sock.settimeout(1.0)
        data, _ = sock.recvfrom(2048)
        if len(data) < HEADER_SIZE:
            return False
        magic, ver_type, _, _, _ = struct.unpack(HEADER_FMT, data[:HEADER_SIZE])
        msg_type = ver_type & 0x0F
        version = (ver_type >> 4) & 0x0F
        return magic == MAGIC and version == VERSION and msg_type == MT_INIT_ACK
    except socket.timeout:
        return False
    finally:
        sock.settimeout(None)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server-host", default="127.0.0.1")
    ap.add_argument("--server-port", type=int, default=9999)
    ap.add_argument("--device-id", type=int, default=1)
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--duration", type=int, default=60)

    # Phase2-friendly defaults: deterministic DATA, 1 reading per tick
    ap.add_argument("--fixed-readings", type=int, default=1,
                    help="Phase2: exactly N readings per interval (default=1).")
    ap.add_argument("--randomize", action="store_true",
                    help="Extra experiments: randomize readings count/value (NOT for Phase2 acceptance).")
    ap.add_argument("--heartbeat-every", type=int, default=0,
                    help="Send heartbeat every N reports (0 disables).")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    server = (args.server_host, args.server_port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    start_wall = time.time()
    seq = 0

    # Best-effort INIT handshake (Phase2 doesn’t rely on it, but it’s harmless)
    init_pkt = build_init(args.device_id, seq, ts=0)
    sock.sendto(init_pkt, server)
    if args.verbose:
        print(f"[INIT] sent device={args.device_id} seq={seq}")
    got_ack = try_recv_init_ack(sock)
    if args.verbose:
        print("[INIT_ACK]" if got_ack else "[INIT_ACK] not received (continuing)")

    last_send = start_wall
    report_index = 0

    while (time.time() - start_wall) < args.duration:
        now = time.time()
        if (now - last_send) < args.interval:
            time.sleep(0.001)
            continue

        report_index += 1
        seq = (seq + 1) & 0xFFFFFFFF
        ts = int(now - start_wall)  # sender timestamp (seconds since sensor start)

        # heartbeat schedule (optional)
        force_hb = (args.heartbeat_every > 0 and (report_index % args.heartbeat_every) == 0)

        if force_hb:
            pkt = build_heartbeat(args.device_id, seq, ts)
            sock.sendto(pkt, server)
            if args.verbose:
                print(f"[HB] sent device={args.device_id} seq={seq} ts={ts}")
        else:
            # determine number of readings
            if args.randomize:
                count = random.randint(1, max(1, args.fixed_readings))
            else:
                count = max(1, args.fixed_readings)

            # enforce payload size
            max_readings = MAX_BODY_BYTES // READING_SIZE
            count = min(count, max_readings)

            readings = []
            for _ in range(count):
                sid = 1
                val = random.uniform(0, 100) if args.randomize else 42.0
                readings.append((sid, val))

            pkt = build_data(args.device_id, seq, ts, readings)
            sock.sendto(pkt, server)
            if args.verbose:
                print(f"[DATA] sent device={args.device_id} seq={seq} ts={ts} readings={len(readings)}")

        last_send = now

    sock.close()
    if args.verbose:
        print("Sensor finished.")

if __name__ == "__main__":
    main()
