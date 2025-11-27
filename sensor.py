import socket
import struct
import time
import argparse
import random

# shewayet protocol constants
# n3mel identify lel packets that belong to protocol -
# 3ashan UDP byb2a unreliable we momken ysend random garbage pac...na 3ayzeen n3mel record lel packets eli leh 3alaka bel protocol
MAGIC = 0x054  # hn2ool law el magic != 0x54 nrfod el packet deh

# types lel messages
MT_INIT = 0x0
MT_INIT_ACK = 0x1  # confirms to the sensor en el handshake is successful
MT_DATA = 0x2      # data packet from sensor
MT_HEARTBEAT = 0x3 # heartbeat packet from sensor to keep connection alive - prevents timeout

HEADER_SIZE = 12  # header eli homa 12 bytes
MAX_PAYLOAD_BYTES = 200
MAX_BODY_BYTES = MAX_PAYLOAD_BYTES - HEADER_SIZE

parser = argparse.ArgumentParser()  # standard fe python 3ashan n3mel command-line options
parser.add_argument("--server-host", default="127.0.0.1")  # collector address
parser.add_argument("--server-port", type=int, default=9999)  # collector port
parser.add_argument("--device-id", type=int, default=100)  # device id
parser.add_argument("--interval", type=float, default=1.0)  # interval between data packets (seconds)
parser.add_argument("--batch", type=int, default=1)  # max readings per packet
parser.add_argument("--duration", type=int, default=60)  # run duration
parser.add_argument("--seed", type=int, default=None)  # optional seed
args = parser.parse_args()  # parse the arguments

if args.seed is not None:
    random.seed(args.seed)  # sometimes i need deterministic behavior so i added this switch
else:
    random.seed(time.time())  # otherwise i just seed with current time so every run feels fresh

RUN_START = time.time()  # i want timestamps relative to when i launched the script


def build_header(msg_type, device_id, seq, ts=None):
    if ts is None:
        ts = int(time.time() - RUN_START)  # relative seconds since start
    ver = 1  # version is 1
    ver_type = ((ver & 0x0F) << 4) | (msg_type & 0x0F)  # combine version and message type
    return struct.pack("!BBHII", MAGIC, ver_type, device_id, seq, ts)
    # magic, version, message type, device id, sequence, and timestamp


def build_init(device_id, seq):
    h = build_header(MT_INIT, device_id, seq)  # build the header
    payload = b"capabilities:float32"  # small ascii payload allowed
    return h + payload  # return the header and payload


def build_data(device_id, seq, readings):
    h = build_header(MT_DATA, device_id, seq)
    # readings: list of (sensor_id, float_value)
    body = bytearray()
    for sid, val in readings:
        body.append(sid & 0xFF)
        body.append(0x01)  # format float32
        body.extend(struct.pack("!f", float(val)))
    return h + bytes(body)


def build_heartbeat(device_id, seq):
    return build_header(MT_HEARTBEAT, device_id, seq)  # build the header


# i know i should wrap this in a main() but i'm going straight procedural here
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # create a socket
sock.settimeout(2.0)  # set a timeout of 2 seconds

server = (args.server_host, args.server_port)
seq = 0

# send INIT
seq += 1  # increment the sequence number
init_pkt = build_init(args.device_id, seq)
print("Sending INIT")  # for the demo , creates log for troubleshooting
sock.sendto(init_pkt, server)

try:
    data, _ = sock.recvfrom(1024)  # receive the INIT_ACK
    try:
        magic, version, msg_type, device_id, rseq, rts = struct.unpack("!BBHII", data[:12])
        if magic == MAGIC and msg_type == MT_INIT_ACK and device_id == args.device_id:
            print("Received INIT_ACK")
        else:
            print("Unexpected response")
    except Exception as e:
        print("Malformed INIT_ACK", e)
except socket.timeout:
    print("No INIT_ACK received (continuing anyway)")

start = time.time()
last_send = 0  # last time we sent a packet
reading_seq = 0  # sequence number for the readings i didn't end up using but leaving it

while time.time() - start < args.duration:
    now = time.time()
    if now - last_send >= args.interval:  # if the interval has passed, send a packet
        seq = (seq + 1) & 0xFFFFFFFF  # increment the sequence number
        count = random.randint(0, max(1, args.batch))  # random number of readings between 0 and batch

        readings = []
        for _ in range(count):
            # mock one sensor with id 1, random float reading
            sensor_id = 1
            val = random.uniform(0.0, 100.0)
            readings.append((sensor_id, val))

        if readings:
            pkt = build_data(args.device_id, seq, readings)
            if len(pkt) > MAX_PAYLOAD_BYTES:
                print("WARNING: packet too large, truncating body")
                # naive truncation: just shrink body
                pkt = pkt[:MAX_PAYLOAD_BYTES]
            sock.sendto(pkt, server)  # send the packet to the server
            print(f"Sent DATA seq={seq} readings={len(readings)}")  # for the demo , creates log for troubleshooting
        else:
            # no new data, so send a heartbeat instead
            sock.sendto(build_heartbeat(args.device_id, seq), server)
            print(f"Sent HEARTBEAT seq={seq} (no readings)")
        last_send = now  # update the last time we sent a packet
    time.sleep(0.01)

# send final heartbeat
seq = (seq + 1) & 0xFFFFFFFF
sock.sendto(build_heartbeat(args.device_id, seq), server)
print("Sent HEARTBEAT; done.")
sock.close()
