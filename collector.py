#!/usr/bin/env python3
import socket
import struct
import time
import argparse
import os
import csv
from collections import deque

# ======================
# Protocol constants
# ======================
MAGIC = 0x54  # 'T'
MT_INIT = 0x0
MT_INIT_ACK = 0x1
MT_DATA = 0x2
MT_HEARTBEAT = 0x3
MT_ACK = 0x4

HEADER_FMT = "!BBHII"   # magic(1), ver_type(1), device_id(2), seq(4), ts(4)
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 12

# ======================
# Collector behavior
# ======================
REORDER_WINDOW_SEC = 1.0     # reorder wait window based on sender timestamp
REORDER_BUFFER_MAX = 256     # safety cap
OFFLINE_TIMEOUT_SEC = 5.0    # if no packets/heartbeats for X sec => offline
SEEN_WINDOW = 10000          # how many seqs we remember per device to detect duplicates

CSV_FIELDS = ["device_id", "seq", "timestamp", "arrival_time", "duplicate_flag", "gap_flag"]

# ======================
# Helpers
# ======================
def unpack_header(packet: bytes):
    if len(packet) < HEADER_SIZE:
        raise ValueError("Packet too short")
    magic, ver_type, device_id, seq, ts = struct.unpack(HEADER_FMT, packet[:HEADER_SIZE])
    version = ver_type >> 4
    msg_type = ver_type & 0x0F
    return magic, version, msg_type, device_id, seq, ts

def pack_header(msg_type: int, device_id: int, seq: int, ts: int):
    ver_type = (1 << 4) | (msg_type & 0x0F)
    return struct.pack(HEADER_FMT, MAGIC, ver_type, device_id & 0xFFFF, seq & 0xFFFFFFFF, ts & 0xFFFFFFFF)

class DeviceState:
    def __init__(self):
        self.reorder = []  # list of dicts: {seq, ts, arrival_time}
        self.last_logged_seq = None  # last seq written to CSV (in reordered stream)
        self.seen_set = set()
        self.seen_queue = deque()
        self.last_seen_wall = time.time()
        self.dup_count = 0
        self.gap_count = 0

    def seen_add(self, seq: int):
        self.seen_set.add(seq)
        self.seen_queue.append(seq)
        while len(self.seen_queue) > SEEN_WINDOW:
            old = self.seen_queue.popleft()
            self.seen_set.discard(old)

def ensure_csv(path: str):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            w.writeheader()

def write_row(writer, file_handle, device_id, seq, ts, arrival_time, dup, gap):
    writer.writerow({
        "device_id": device_id,
        "seq": seq,
        "timestamp": ts,
        "arrival_time": arrival_time,
        "duplicate_flag": 1 if dup else 0,
        "gap_flag": 1 if gap else 0,
    })
    # IMPORTANT: force it to actually write to disk
    file_handle.flush()

def flush_device(state: DeviceState, writer, fhandle, *, current_ts=None, force=False):
    """
    Flush reorder buffer in sender-timestamp order.
    Gap detection happens HERE (after reorder).
    """
    if not state.reorder:
        return

    # sort by (timestamp, seq) to approximate correct ordering
    state.reorder.sort(key=lambda x: (x["ts"], x["seq"]))

    # flush as many as allowed
    i = 0
    while i < len(state.reorder):
        entry = state.reorder[i]
        can_flush = force

        if not can_flush and current_ts is not None:
            if (current_ts - entry["ts"]) >= REORDER_WINDOW_SEC:
                can_flush = True

        if not can_flush and len(state.reorder) > REORDER_BUFFER_MAX:
            can_flush = True

        if not can_flush:
            break

        # pop earliest
        entry = state.reorder.pop(i)

        # gap detection based on *last_logged_seq*
        gap = False
        if state.last_logged_seq is not None:
            expected = (state.last_logged_seq + 1) & 0xFFFFFFFF
            if entry["seq"] != expected:
                gap = True
                state.gap_count += 1

        state.last_logged_seq = entry["seq"]
        write_row(writer, fhandle,
                  entry["device_id"], entry["seq"], entry["ts"], entry["arrival_time"],
                  dup=False, gap=gap)

    # done

def mark_offline(devices: dict):
    now = time.time()
    for dev_id, st in devices.items():
        if (now - st.last_seen_wall) > OFFLINE_TIMEOUT_SEC:
            print(f"[OFFLINE] device={dev_id} last_seen={(now - st.last_seen_wall):.1f}s ago")
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--csv", default="telemetry_log.csv")
    ap.add_argument("--send-ack", action="store_true", help="debug only (NOT recommended for Phase2)")
    args = ap.parse_args()

    ensure_csv(args.csv)

    # open CSV ONCE, append mode
    f = open(args.csv, "a", newline="", encoding="utf-8")
    writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, args.port))
    sock.settimeout(1.0)

    devices = {}  # device_id -> DeviceState

    print(f"Collector listening on {args.host}:{args.port}")
    print(f"Logging to: {args.csv}")

    try:
        while True:
            try:
                packet, addr = sock.recvfrom(4096)
            except socket.timeout:
                # periodic offline reporting
                mark_offline(devices)
                continue

            try:
                magic, version, msg_type, device_id, seq, ts = unpack_header(packet)
            except Exception as e:
                print("[DROP] bad packet:", e)
                continue

            if magic != MAGIC:
                print("[DROP] bad magic")
                continue

            arrival_time = int(time.time())  # absolute seconds (fine), or switch to relative if you want

            st = devices.get(device_id)
            if st is None:
                st = DeviceState()
                devices[device_id] = st

            st.last_seen_wall = time.time()

            # INIT: reply INIT_ACK
            if msg_type == MT_INIT:
                print(f"[INIT] device={device_id} seq={seq} ts={ts} from={addr}")
                init_ack = pack_header(MT_INIT_ACK, device_id, seq, ts)
                sock.sendto(init_ack, addr)
                continue

            # Optional ACK support (OFF by default)
            if args.send_ack and msg_type in (MT_DATA, MT_HEARTBEAT):
                ack = pack_header(MT_ACK, device_id, seq, ts)
                sock.sendto(ack, addr)

            # Duplicate detection (log duplicates immediately)
            if seq in st.seen_set:
                st.dup_count += 1
                write_row(writer, f, device_id, seq, ts, arrival_time, dup=True, gap=False)
                if msg_type == MT_HEARTBEAT:
                    print(f"[DUP-HB] device={device_id} seq={seq} ts={ts}")
                else:
                    print(f"[DUP] device={device_id} seq={seq} ts={ts}")
                continue

            st.seen_add(seq)

            # DATA / HEARTBEAT handling:
            if msg_type == MT_DATA:
                # buffer for reorder; do NOT do gap checks here
                st.reorder.append({
                    "device_id": device_id,
                    "seq": seq,
                    "ts": ts,
                    "arrival_time": arrival_time
                })
                flush_device(st, writer, f, current_ts=ts, force=False)
                print(f"[DATA] device={device_id} seq={seq} ts={ts} buffered={len(st.reorder)}")

            elif msg_type == MT_HEARTBEAT:
                # heartbeats also go through reorder pipeline; we can force flush if you want
                st.reorder.append({
                    "device_id": device_id,
                    "seq": seq,
                    "ts": ts,
                    "arrival_time": arrival_time
                })
                flush_device(st, writer, f, current_ts=ts, force=True)
                print(f"[HB] device={device_id} seq={seq} ts={ts}")

            else:
                print(f"[INFO] unknown/ignored msg_type={msg_type} device={device_id} seq={seq}")

    except KeyboardInterrupt:
        print("\nShutting down... flushing buffers")

        # Force flush ALL reorder buffers on exit
        for dev_id, st in devices.items():
            flush_device(st, writer, f, current_ts=10**9, force=True)

        print("Done.")

    finally:
        try:
            f.flush()
        except:
            pass
        try:
            f.close()
        except:
            pass
        try:
            sock.close()
        except:
            pass

if __name__ == "__main__":
    main()
