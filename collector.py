import socket
import struct
import time
import csv
import argparse
from collections import defaultdict, deque
import pandas as pd

# shewayet protocol constants
# n3mel identify lel packets that belong to protocol - 
# 3ashan UDP byb2a unreliable we momken ysend random garbage packets we ehna 3ayzeen n3mel record lel packets eli leh 3alaka bel protocol 
MAGIC = 0x054 # hn2ool law el magic != 0x54 nrfod el packet deh

# types lel messages 
MT_INIT = 0x0 # by3mel initialize lel handshake so that collector create or refresh state abl data arriving
MT_INIT_ACK = 0x1 #confirms to the sensor en el handshake is successful
MT_DATA = 0x2 # data packet from sensor
MT_HEARTBEAT = 0x3 # heartbeat packet from sensor to keep connection alive - prevents timeout

# header eli homa 12 bytes
HEADER_FMT = "!BBHII"  # 1+1+2+4+4 = 12 bytes - magic(1) + version + type (1) + device_id(2) + sequence(4) + timestamp(4)
HEADER_SIZE = 12
REORDER_WINDOW = 1.0  # seconds of slack before we flush buffered packets
REORDER_BUFFER_MAX = 64

def parse_header(packet):
    if len(packet) < HEADER_SIZE: # law el packet size < 12 bytes n3ml error
        raise ValueError("Short header")
    magic , ver_type ,device_id , seq , ts = struct.unpack(HEADER_FMT, packet[:HEADER_SIZE] )
    version = ver_type >> 4 ## ver_type bytb3t 8 bits 0->3  byb2o version w 4->7 byb2o type  , fa hena 3amalna shift 4 bits 3ashan ngeb el version
    msg_type = ver_type & 0x0F ## w hena 3amalna and 0x0F 3ashan ngeb el type (masking)
    return magic, version, msg_type, device_id, seq, ts


# lel demo 3ashan n3mel kaza configuration , change el parameters lama n3mel run 
parser = argparse.ArgumentParser() # standard fe python 3ashan 3ashan n3mel command-line options
parser.add_argument("--host", default="0.0.0.0") # collector listens to all network ports/interfaces ela law 3amalna confiig
parser.add_argument("--port", type=int, default=9999) # accepts integres and dafaults to 9999 to let switch port easily
parser.add_argument("--csv", default="telemetry_log.csv") # choose where to store data csv 
args = parser.parse_args() # 

#state le kol device 
devices = {}

columns = ["device_id", "seq", "timestamp", "arrival_time", "duplicate_flag", "gap_flag"]
df = pd.DataFrame(columns=columns)
df.to_csv(args.csv, index=False)

RUN_START = time.time() # i want to log everything relative to when the collector booted

def handle_init(sock, addr, payload, device_id, seq, ts):
    print(f"from {device_id} seq={seq} ts={ts} addr={addr}") # for the demo , creates log for troubleshooting
    
    ver_type = (1 << 4) | MT_INIT_ACK
    header = struct.pack("!BBHII", MAGIC, ver_type, device_id, seq, int(time.time() - RUN_START)) # pack the header with the magic, version, device_id, sequence, and timestamp
    sock.sendto(header, addr) # send the header back to the sensor, 3ashan tb2a 3arfa el collector is ready to receive data
    # record le kol device state eli b3mel initialize lel handshake , makes sure its reset every time
    devices.setdefault(device_id, {
        'last_seq': None, # the most recent sequence number processed 
        'seen_seqs': set(), # 
        'reorder_buffer': deque(), #a queue for packets that are out of order, to be reordered
        'last_ts': None, # the most recent timestamp processed
        'dup_count': 0, # number of duplicate packets
        'gap_count': 0 # number of gap packets
    })

## n3mel csv be pandas
def process_data(device_id, seq, ts, arrival_time, duplicate_flag, gap_flag):
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
        process_data(
            device_id,
            entry['seq'],
            entry['timestamp'],
            entry['arrival_time'],
            False,
            entry['gap'],
        )

## handle le data packets
def handle_data(device_id, seq, ts, payload):
    arrival_time = int(time.time() - RUN_START) # seconds since collector started
    st = devices.setdefault(device_id, {
        'last_seq': None,
        'seen_seqs': set(),
        'reorder_buffer': deque(),
        'last_ts': None,
        'dup_count': 0,
        'gap_count': 0
    })

    if seq in st['seen_seqs']:
        st['dup_count'] += 1
        process_data(device_id, seq, ts, arrival_time, True, False)
        print(f"device={device_id} seq={seq} ts={ts} dup=True gap=False readings=0") # duplicate packet logged
        return

    gap = False
    if st['last_seq'] is not None and seq != ((st['last_seq'] + 1) & 0xFFFFFFFF):
        gap = True
        st['gap_count'] += 1

    st['seen_seqs'].add(seq)
    st['last_seq'] = seq
    st['last_ts'] = ts

    # parse payload: sequence of readings. Each reading: sensor_id(1), format(1), value(float32)
    readings = [] # list to store the readings
    i = 0
    while i + 6 <= len(payload):
        sensor_id = payload[i] # get the sensor id
        fmt = payload[i+1] # get the format
        if fmt == 0x01:  # float32
            val = struct.unpack("!f", payload[i+2:i+6])[0] # unpack the value
            readings.append((sensor_id, val))
            i += 6
        elif fmt == 0x02:  # int16
            val = struct.unpack("!h", payload[i+2:i+4])[0] # unpack the value
            readings.append((sensor_id, val))
            i += 4
        else:
            # unknown format -> stop
            break # stop the loop

    st['reorder_buffer'].append({
        'seq': seq,
        'timestamp': ts,
        'arrival_time': arrival_time,
        'gap': gap,
    })
    flush_reorder_buffer(device_id, st, current_ts=ts)

    print(f"device={device_id} seq={seq} ts={ts} dup=False gap={gap} readings={len(readings)}") # for the demo , creates log for troubleshooting

## run el server
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((args.host, args.port))
print(f"Collector listening on {args.host}:{args.port}")  # simple status print

while True:
    data, addr = sock.recvfrom(4096)  # wait for any udp packet

    
    magic, version, msg_type, device_id, seq, ts = parse_header(data)

    if magic != MAGIC:
        print("Invalid magic from", addr)
        continue

    payload = data[HEADER_SIZE:]  # the rest is the payload i need

    if msg_type == MT_INIT:
        handle_init(sock, addr, payload, device_id, seq, ts)
    elif msg_type == MT_DATA:
        handle_data(device_id, seq, ts, payload)
    elif msg_type == MT_HEARTBEAT:
        print(f"[HEARTBEAT] device={device_id} seq={seq} ts={ts}")
        process_data(device_id, seq, ts, int(time.time() - RUN_START), False, False)
        st = devices.setdefault(device_id, {
            'last_seq': None,
            'seen_seqs': set(),
            'reorder_buffer': deque(),
            'last_ts': None,
            'dup_count': 0,
            'gap_count': 0
        })
        flush_reorder_buffer(device_id, st, force=True, current_ts=ts)
    else:
        print("Unknown msg type", msg_type)