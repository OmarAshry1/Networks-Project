#!/usr/bin/env python3
import socket
import struct
import time
import argparse
import os
import csv
from collections import deque

# Protocol constants
MAGIC = 0x54  
VERSION = 1

MT_INIT = 0x0
MT_INIT_ACK = 0x1
MT_DATA = 0x2
MT_HEARTBEAT = 0x3
MT_ACK = 0x4 

HEADER_FMT = "!BBHII"  # magic(1), ver_type(1), device_id(2), seq(4), ts(4)
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 12 bytes

CSV_FIELDS = [
    "device_id",
    "seq",
    "timestamp",
    "arrival_time",
    "duplicate_flag",
    "gap_flag",
]


REORDER_WINDOW_SEC = 1       # hold packets for up to 1s based on sender timestamp
REORDER_BUFFER_MAX = 64      # keep bounded
SEEN_WINDOW = 10000          # dedup window size
OFFLINE_TIMEOUT_SEC = 5      # offline detection


def pack_header(msg_type: int, device_id: int, seq: int, ts: int):
    ver_type = ((VERSION & 0x0F) << 4) | (msg_type & 0x0F)
    return struct.pack(
        HEADER_FMT,
        MAGIC,
        ver_type,
        device_id & 0xFFFF,
        seq & 0xFFFFFFFF,
        ts & 0xFFFFFFFF
    )


def ensure_csv_header(path: str):
    exists = os.path.exists(path)
    if not exists:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            w.writeheader()


def write_row(writer, fhandle, device_id, seq, ts, arrival_time, dup, gap):
    writer.writerow({
        "device_id": device_id,
        "seq": seq,
        "timestamp": ts,                
        "arrival_time": arrival_time,   
        "duplicate_flag": 1 if dup else 0,
        "gap_flag": 1 if gap else 0,
    })
    fhandle.flush()  


class DeviceState:
    def __init__(self):
  
        self.reorder = []
        self.last_logged_seq = None  
        self.seen_set = set()
        self.seen_queue = deque()
        self.last_seen_wall = time.time()
        self.capabilities = None  
        self.dup_count = 0
        self.gap_count = 0
        self.logged_seqs = set()  

    def seen_add(self, seq: int):
        self.seen_set.add(seq)
        self.seen_queue.append(seq)
        while len(self.seen_queue) > SEEN_WINDOW:
            old = self.seen_queue.popleft()
            if old in self.seen_set:
                self.seen_set.remove(old)


def flush_reorder(state: DeviceState, writer, fhandle, *, current_ts=None, force=False, wall_time=None):
    """
    Flush reorder buffer IN SENDER TIMESTAMP ORDER.
    Gap detection happens here (after reorder), not on arrival.
    """
    if not state.reorder:
        return

 
    state.reorder.sort(key=lambda e: (e["ts"], e["seq"]))

    # Track if this is the first packet ever (before we start flushing)
    is_first_packet = (state.last_logged_seq is None)

    idx = 0
    while idx < len(state.reorder):
        entry = state.reorder[idx]

        can_flush = force
        

        if not can_flush and is_first_packet and idx == 0:
            can_flush = True
        

        if not can_flush and wall_time is not None and "arrival_time" in entry:
            time_since_arrival = wall_time - entry["arrival_time"]
            if time_since_arrival >= REORDER_WINDOW_SEC:
                can_flush = True
        
        # Legacy check: if current_ts (sender timestamp) indicates enough time passed
        if not can_flush and current_ts is not None:

            if current_ts > entry["ts"] and (current_ts - entry["ts"]) >= REORDER_WINDOW_SEC:
                can_flush = True

        if not can_flush and len(state.reorder) > REORDER_BUFFER_MAX:
            can_flush = True

        if not can_flush:
            break

        entry = state.reorder.pop(idx)

        if entry["seq"] in state.logged_seqs:
            continue  
        gap = False
        if state.last_logged_seq is not None:
            expected = (state.last_logged_seq + 1) & 0xFFFFFFFF
            if entry["seq"] != expected:
                gap = True
                state.gap_count += 1

        state.last_logged_seq = entry["seq"]
        state.logged_seqs.add(entry["seq"])

        write_row(
            writer, fhandle,
            entry["device_id"], entry["seq"], entry["ts"], entry["arrival_time"],
            dup=False, gap=gap
        )


def mark_offline(devices: dict):
    now = time.time()
    for dev_id, st in devices.items():
        if (now - st.last_seen_wall) > OFFLINE_TIMEOUT_SEC:
            print(f"[OFFLINE] device={dev_id} last_seen={(now - st.last_seen_wall):.1f}s ago")


def main():
    ap = argparse.ArgumentParser()
 
    ap.add_argument("--bind-host", "--host", dest="bind_host", default="0.0.0.0")
    ap.add_argument("--bind-port", "--port", dest="bind_port", type=int, default=9999)
    ap.add_argument("--csv-out", "--csv", dest="csv_out", default="telemetry_log.csv")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--send-ack", action="store_true", help="Send MT_ACK for DATA/HB (debug only).")
    args = ap.parse_args()

    ensure_csv_header(args.csv_out)
    f = open(args.csv_out, "a", newline="")
    writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind_host, args.bind_port))

    print(f"Collector listening on {args.bind_host}:{args.bind_port} -> {args.csv_out}")

    devices = {}
    start_wall = time.time()

    try:
        while True:
            data, addr = sock.recvfrom(4096)
            if len(data) < HEADER_SIZE:
                continue

            magic, ver_type, device_id, seq, ts = struct.unpack(HEADER_FMT, data[:HEADER_SIZE])
            msg_type = ver_type & 0x0F
            version = (ver_type >> 4) & 0x0F

            if magic != MAGIC or version != VERSION:
                continue

            arrival_time = round(time.time() - start_wall, 6)  

            st = devices.get(device_id)
            if st is None:
                st = DeviceState()
                devices[device_id] = st
            st.last_seen_wall = time.time()

         
            if msg_type == MT_INIT:
        
                st = DeviceState()
                devices[device_id] = st
                st.last_seen_wall = time.time()

              
                cap_bytes = data[HEADER_SIZE:]
                if cap_bytes:
                    st.capabilities = cap_bytes.decode("ascii", errors="replace")

                if args.verbose:
                    cap_preview = (st.capabilities[:80] + "…") if (st.capabilities and len(st.capabilities) > 80) else st.capabilities
                    print(f"[INIT] device={device_id} seq={seq} ts={ts} from={addr} caps={cap_preview}")

               
                fresh_ts = int(time.time() - start_wall)
                init_ack = pack_header(MT_INIT_ACK, device_id, seq, fresh_ts)
                sock.sendto(init_ack, addr)
                continue

           
            if args.send_ack and msg_type in (MT_DATA, MT_HEARTBEAT):
                ack = pack_header(MT_ACK, device_id, seq, ts)
                sock.sendto(ack, addr)

         
            if seq in st.seen_set:
                st.dup_count += 1
                write_row(writer, f, device_id, seq, ts, arrival_time, dup=True, gap=False)
                if args.verbose:
                    print(f"[DUP] device={device_id} seq={seq} ts={ts}")
                continue

            st.seen_add(seq)

         
            if msg_type == MT_DATA:
             
                payload_len = len(data) - HEADER_SIZE
                if payload_len < 0:
                    payload_len = 0
                if (payload_len % 6) != 0 and args.verbose:
                    print(f"[WARN] device={device_id} seq={seq} payload_len={payload_len} not multiple of 6")

                st.reorder.append({
                    "device_id": device_id,
                    "seq": seq,
                    "ts": ts,
                    "arrival_time": arrival_time
                })
                flush_reorder(st, writer, f, current_ts=ts, force=False, wall_time=arrival_time)
                if args.verbose:
                    print(f"[DATA] device={device_id} seq={seq} ts={ts} buf={len(st.reorder)}")

            elif msg_type == MT_HEARTBEAT:
                st.reorder.append({
                    "device_id": device_id,
                    "seq": seq,
                    "ts": ts,
                    "arrival_time": arrival_time
                })
                flush_reorder(st, writer, f, current_ts=ts, force=True, wall_time=arrival_time)
                if args.verbose:
                    print(f"[HB] device={device_id} seq={seq} ts={ts}")

            else:
                if args.verbose:
                    print(f"[INFO] ignored msg_type={msg_type} device={device_id} seq={seq}")

            mark_offline(devices)

    except KeyboardInterrupt:
        print("\nShutting down. flushing buffers")
        final_wall_time = time.time() - start_wall
        for _, st in devices.items():
            flush_reorder(st, writer, f, current_ts=10**9, force=True, wall_time=final_wall_time)
        print("Done.")
    finally:
        try:
            f.flush()
            f.close()
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
