#!/usr/bin/env python3
import socket
import struct
import time
import csv
import argparse
from collections import deque
import pandas as pd
import os

# Protocol constants
MAGIC = 0x54  # note: use 0x54 (decimal 84)
MT_INIT = 0x0
MT_INIT_ACK = 0x1
MT_DATA = 0x2
MT_HEARTBEAT = 0x3
MT_ACK = 0x4

HEADER_FMT = "!BBHII"  # magic(1), ver_type(1), device_id(2), seq(4), ts(4)
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # should be 12

# reorder and buffer settings
REORDER_WINDOW = 1.0  # seconds to wait before flushing based on sensor timestamp
REORDER_BUFFER_MAX = 64
OFFLINE_TIMEOUT = 5.0  # seconds after which device considered offline (heartbeat missing)

parser = argparse.ArgumentParser()
parser.add_argument("--host", default="0.0.0.0")
parser.add_argument("--port", type=int, default=9999)
parser.add_argument("--csv", default="telemetry_log.csv")
parser.add_argument("--send-ack", action="store_true", help="(debug) send MT_ACK for received DATA/HEARTBEAT")
parser.add_argument("--seen-window", type=int, default=4096, help="max seq numbers kept per device for duplicate detection")
args = parser.parse_args()

# per-device state
devices = {}

# prepare CSV
csv_fields = ["device_id", "seq", "timestamp", "arrival_time", "duplicate_flag", "gap_flag"]
os.makedirs(os.path.dirname(args.csv) or ".", exist_ok=True)
if not os.path.exists(args.csv):
    pd.DataFrame(columns=csv_fields).to_csv(args.csv, index=False)

RUN_START = time.time()

def now_rel_seconds():
    return time.time() - RUN_START

def parse_header(packet):
    if len(packet) < HEADER_SIZE:
        raise ValueError("Short header")
    magic, ver_type, device_id, seq, ts = struct.unpack(HEADER_FMT, packet[:HEADER_SIZE])
    version = ver_type >> 4
    msg_type = ver_type & 0x0F
    return magic, version, msg_type, device_id, seq, ts

def send_init_ack(sock, addr, device_id, seq):
    ver_type = (1 << 4) | MT_INIT_ACK
    header = struct.pack(HEADER_FMT, MAGIC, ver_type, device_id, seq, int(now_rel_seconds()))
    sock.sendto(header, addr)

def send_data_ack(sock, addr, device_id, seq):
    ver_type = (1 << 4) | MT_ACK
    header = struct.pack(HEADER_FMT, MAGIC, ver_type, device_id, seq, int(now_rel_seconds()))
    sock.sendto(header, addr)

def process_data_row(device_id, seq, ts, arrival_time, duplicate_flag, gap_flag):
    row = {
        "device_id": device_id,
        "seq": seq,
        "timestamp": ts,
        "arrival_time": arrival_time,
        "duplicate_flag": int(bool(duplicate_flag)),
        "gap_flag": int(bool(gap_flag)),
    }
    pd.DataFrame([row]).to_csv(args.csv, mode="a", header=False, index=False)

def flush_reorder_buffer(device_id, state, force=False, current_ts=None):
    buffer = state['reorder_buffer']
    if not buffer:
        return

    ordered = sorted(buffer, key=lambda item: (item['timestamp'], item['seq']))
    state['reorder_buffer'] = deque(ordered)

    while state['reorder_buffer']:
        candidate = state['reorder_buffer'][0]
        should_flush = force

        if not should_flush and current_ts is not None:
            if (current_ts - candidate['timestamp']) >= REORDER_WINDOW:
                should_flush = True

        if not should_flush and len(state['reorder_buffer']) > REORDER_BUFFER_MAX:
            should_flush = True

        if not should_flush:
            break

        entry = state['reorder_buffer'].popleft()

        # compute gap in *timestamp order* (after reordering), not on arrival
        gap = False
        last_logged = state.get('last_logged_seq')
        if last_logged is not None:
            expected = (last_logged + 1) & 0xFFFFFFFF
            if entry['seq'] != expected:
                gap = True
                state['gap_count'] = state.get('gap_count', 0) + 1
        state['last_logged_seq'] = entry['seq']
        process_data_row(
            device_id,
            entry['seq'],
            entry['timestamp'],
            entry['arrival_time'],
            False,
            gap,
        )

def handle_init(sock, addr, payload, device_id, seq, ts):
    print(f"[INIT] from {device_id} seq={seq} ts={ts} addr={addr}")
    devices.setdefault(device_id, {
        'last_logged_seq': None,
        'seen_seqs': set(),
        'seen_queue': deque(),
        'reorder_buffer': deque(),
        'last_ts': None,
        'dup_count': 0,
        'gap_count': 0,
        'last_seen': time.time()
    })
    devices[device_id]['last_seen'] = time.time()
    send_init_ack(sock, addr, device_id, seq)

def handle_data(sock, addr, device_id, seq, ts, payload):
    arrival_time = int(now_rel_seconds())
    st = devices.setdefault(device_id, {
        'last_logged_seq': None,
        'seen_seqs': set(),
        'seen_queue': deque(),
        'reorder_buffer': deque(),
        'last_ts': None,
        'dup_count': 0,
        'gap_count': 0,
        'last_seen': time.time()
    })

    # update last seen
    st['last_seen'] = time.time()

    # duplicate detection
    if seq in st['seen_seqs']:
        st['dup_count'] += 1
        # log duplicate immediately
        process_data_row(device_id, seq, ts, arrival_time, True, False)
        print(f"[DUP] device={device_id} seq={seq} ts={ts}")
        if args.send_ack:
            send_data_ack(sock, addr, device_id, seq)
        return

    # best-effort payload parse (optional, not logged)
    readings = []
    i = 0
    while i + 6 <= len(payload):
        sensor_id = payload[i]
        fmt = payload[i+1]
        if fmt == 0x01 and i + 6 <= len(payload):
            val = struct.unpack("!f", payload[i+2:i+6])[0]
            readings.append((sensor_id, val))
            i += 6
        elif fmt == 0x02 and i + 4 <= len(payload):
            val = struct.unpack("!h", payload[i+2:i+4])[0]
            readings.append((sensor_id, val))
            i += 4
        else:
            break

    # NOTE: gap detection must be done AFTER reordering (in flush_reorder_buffer).
    # Here we only track duplicates and buffer the packet for timestamp-based ordering.
    st['seen_seqs'].add(seq)
    st.setdefault('seen_queue', deque()).append(seq)
    # prune duplicate-tracking window to avoid unbounded growth
    while len(st['seen_queue']) > args.seen_window:
        old = st['seen_queue'].popleft()
        st['seen_seqs'].discard(old)
    st['last_ts'] = ts

    st['reorder_buffer'].append({
        'seq': seq,
        'timestamp': ts,
        'arrival_time': arrival_time,
    })
    flush_reorder_buffer(device_id, st, current_ts=ts)

    # optional ACK (OFF by default)
    if args.send_ack:
        send_data_ack(sock, addr, device_id, seq)

    print(f"[DATA] device={device_id} seq={seq} ts={ts} dup=False queued=True readings={len(readings)}")

def handle_heartbeat(sock, addr, device_id, seq, ts):
    arrival_time = int(now_rel_seconds())
    st = devices.setdefault(device_id, {
        'last_logged_seq': None,
        'seen_seqs': set(),
        'seen_queue': deque(),
        'reorder_buffer': deque(),
        'last_ts': None,
        'dup_count': 0,
        'gap_count': 0,
        'last_seen': time.time()
    })

    st['last_seen'] = time.time()

    # duplicate detection (heartbeats can also duplicate)
    if seq in st['seen_seqs']:
        st['dup_count'] += 1
        process_data_row(device_id, seq, ts, arrival_time, True, False)
        print(f"[DUP-HB] device={device_id} seq={seq} ts={ts}")
        if args.send_ack:
            send_data_ack(sock, addr, device_id, seq)
        return

    st['seen_seqs'].add(seq)
    st.setdefault('seen_queue', deque()).append(seq)
    while len(st['seen_queue']) > args.seen_window:
        old = st['seen_queue'].popleft()
        st['seen_seqs'].discard(old)

    # buffer heartbeat and force-flush so ordering is by sensor timestamp
    st['reorder_buffer'].append({
        'seq': seq,
        'timestamp': ts,
        'arrival_time': arrival_time,
    })
    flush_reorder_buffer(device_id, st, force=True, current_ts=ts)
    print(f"[HEARTBEAT] device={device_id} seq={seq} ts={ts}")

def mark_offline_devices():
    now_t = time.time()
    for d, st in devices.items():
        last = st.get('last_seen', 0)
        if (now_t - last) > OFFLINE_TIMEOUT:
            print(f"[OFFLINE] device={d} last_seen={(now_t - last):.1f}s ago")

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, args.port))
    sock.settimeout(1.0)
    print(f"Collector listening on {args.host}:{args.port} (csv={args.csv})")

    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                mark_offline_devices()
                continue
            except Exception as e:
                print("Recv error:", e)
                continue

            try:
                magic, version, msg_type, device_id, seq, ts = parse_header(data)
            except Exception as e:
                print("Malformed packet from", addr, e)
                continue

            if magic != MAGIC:
                print("Invalid magic from", addr)
                continue

            payload = data[HEADER_SIZE:]

            if msg_type == MT_INIT:
                handle_init(sock, addr, payload, device_id, seq, ts)
            elif msg_type == MT_DATA:
                handle_data(sock, addr, device_id, seq, ts, payload)
            el
