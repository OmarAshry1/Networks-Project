#!/usr/bin/env python3
import socket
import struct
import time
import argparse
import random

# Protocol constants (must match collector)
MAGIC = 0x54
MT_INIT = 0x0
MT_INIT_ACK = 0x1
MT_DATA = 0x2
MT_HEARTBEAT = 0x3
MT_ACK = 0x4

HEADER_FMT = "!BBHII"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

MAX_PAYLOAD_BYTES = 200
MAX_BODY_BYTES = MAX_PAYLOAD_BYTES - HEADER_SIZE

parser = argparse.ArgumentParser()
parser.add_argument("--server-host", default="127.0.0.1")
parser.add_argument("--server-port", type=int, default=9999)
parser.add_argument("--device-id", type=int, default=100)
parser.add_argument("--interval", type=float, default=1.0)
parser.add_argument("--batch", type=int, default=1)
parser.add_argument("--duration", type=int, default=60)
parser.add_argument("--seed", type=int, default=None)
parser.add_argument("--retries", type=int, default=3, help="retries for DATA in reliable mode")
parser.add_argument("--ack-timeout", type=float, default=0.5, help="seconds to wait for ACK")
parser.add_argument("--reliable", action="store_true", help="enable stop-and-wait reliable mode for DATA")
parser.add_argument("--random-batch", action="store_true", help="randomize readings count (legacy/extra testing)")
parser.add_argument("--fixed-readings", type=int, default=None, help="force exactly N readings per interval (Phase 2 friendly)")
parser.add_argument("--heartbeat-every", type=int, default=0, help="send a heartbeat every N reports (0 disables)")
parser.add_argument("--phase2", action="store_true", help="Phase 2 mode: deterministic DATA each interval, no reliability")
args = parser.parse_args()

# Phase 2 defaults: deterministic sending and no retransmissions
if args.phase2:
    args.random_batch = False
    args.reliable = False
    args.heartbeat_every = 0
    if args.fixed_readings is None:
        args.fixed_readings = max(1, args.batch)

def build_header(msg_type, device_id, seq):
    ver_type = (1 << 4) | (msg_type & 0x0F)
    ts = int(time.time() - START_TIME)
    return struct.pack(HEADER_FMT, MAGIC, ver_type, device_id & 0xFFFF, seq & 0xFFFFFFFF, ts & 0xFFFFFFFF)

def build_init(device_id, seq):
    return build_header(MT_INIT, device_id, seq)

def build_data(device_id, seq, readings):
    h = build_header(MT_DATA, device_id, seq)
    body = bytearray()
    for sid, val in readings:
        body.append(sid & 0xFF)
        body.append(0x01)  # float32 format
        body.extend(struct.pack("!f", float(val)))
    return h + bytes(body)

def build_heartbeat(device_id, seq):
    return build_header(MT_HEARTBEAT, device_id, seq)

def parse_header_simple(packet):
    if len(packet) < HEADER_SIZE:
        return None
    magic, ver_type, device_id, seq, ts = struct.unpack(HEADER_FMT, packet[:HEADER_SIZE])
    msg_type = ver_type & 0x0F
    return magic, msg_type, device_id, seq, ts

if args.seed is not None:
    random.seed(args.seed)
else:
    random.seed(time.time())

server = (args.server_host, args.server_port)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2.0)

START_TIME = time.time()
seq = 0

# INIT handshake (best-effort)
init_pkt = build_init(args.device_id, seq)
sock.sendto(init_pkt, server)
print(f"Sent INIT seq={seq}")
try:
    data, addr = sock.recvfrom(2048)
    hdr = parse_header_simple(data)
    if hdr and hdr[0] == MAGIC and hdr[1] == MT_INIT_ACK:
        print("Received INIT_ACK")
except socket.timeout:
    print("No INIT_ACK (continuing anyway)")

start_time = time.time()
last_send = 0
send_index = 0

while time.time() - start_time < args.duration:
    now = time.time()
    if now - last_send >= args.interval:
        seq = (seq + 1) & 0xFFFFFFFF
        send_index += 1

        # Phase-2 friendly: deterministic by default (1..batch readings each interval)
        if args.fixed_readings is not None:
            count = max(1, int(args.fixed_readings))
        elif args.random_batch:
            count = random.randint(0, max(1, args.batch))
        else:
            count = max(1, args.batch)

        force_hb = (args.heartbeat_every > 0 and (send_index % args.heartbeat_every) == 0)
        readings = []
        body_bytes = 0
        for _ in range(count):
            sid = 1
            val = random.uniform(0.0, 100.0)
            reading_size = 6
            if body_bytes + reading_size > MAX_BODY_BYTES:
                break
            readings.append((sid, val))
            body_bytes += reading_size

        if (not force_hb) and count > 0:
            pkt = build_data(args.device_id, seq, readings)
            if args.reliable:
                # stop-and-wait: optional/experimental (OFF by default)
                tries = 1
                acked = False
                while tries <= args.retries and not acked:
                    sock.sendto(pkt, server)
                    print(f"Sent DATA seq={seq} readings={len(readings)} (try {tries})")
                    sock.settimeout(args.ack_timeout)
                    try:
                        ack_pkt, _ = sock.recvfrom(2048)
                        hdr = parse_header_simple(ack_pkt)
                        if hdr and hdr[0] == MAGIC and hdr[1] == MT_ACK:
                            _, _, _, ack_seq, _ = hdr
                            if ack_seq == seq:
                                acked = True
                                print(f"Received ACK for seq={seq}")
                                break
                    except socket.timeout:
                        print(f"ACK timeout for seq={seq} (try {tries}/{args.retries})")
                    finally:
                        sock.settimeout(2.0)
                    tries += 1
                if not acked:
                    print(f"Gave up on seq={seq} after {tries-1} retries")
            else:
                sock.sendto(pkt, server)
                print(f"Sent DATA seq={seq} readings={len(readings)}")
        else:
            # heartbeat (explicit or when count==0 in random mode)
            pkt = build_heartbeat(args.device_id, seq)
            sock.sendto(pkt, server)
            print(f"Sent HEARTBEAT seq={seq}")

        last_send = now

sock.close()
print("Sensor finished.")
