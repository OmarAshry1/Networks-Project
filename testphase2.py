#!/usr/bin/env python3
import subprocess
import sys
import time
from pathlib import Path
from datetime import datetime

PYTHON = sys.executable
PROJECT_ROOT = Path(__file__).resolve().parent
RESULTS_DIR = PROJECT_ROOT / "results"
RESULTS_DIR.mkdir(exist_ok=True)

COLLECTOR_SCRIPT = "collector.py"
SENSOR_SCRIPT = "sensor.py"

PORT = 9999
DURATION = 60
INTERVAL = 1.0
BATCH = 1
DEVICE_ID = 100

SCENARIOS = {
    "baseline": None,
    "loss_5": "sudo tc qdisc add dev lo root netem loss 5%",
    "delay_jitter": "sudo tc qdisc add dev lo root netem delay 100ms 10ms"
}

CLEAR_NETEM = "sudo tc qdisc del dev lo root || true"


def run_cmd(cmd, **kwargs):
    if isinstance(cmd, list):
        print("$ " + " ".join(cmd))
    else:
        print("$ " + cmd)
    return subprocess.run(cmd, shell=isinstance(cmd, str), **kwargs)


def start_collector(csv_path):
    collector_cmd = [
        PYTHON, COLLECTOR_SCRIPT,
        "--host", "127.0.0.1",
        "--port", str(PORT),
        "--csv", str(csv_path)
    ]
    return subprocess.Popen(collector_cmd, cwd=PROJECT_ROOT)


def build_sensor_cmd(seed):
    return [
        PYTHON, SENSOR_SCRIPT,
        "--server-host", "127.0.0.1",
        "--server-port", str(PORT),
        "--device-id", str(DEVICE_ID),
        "--interval", str(INTERVAL),
        "--batch", str(BATCH),
        "--duration", str(DURATION),
        "--seed", str(seed)
    ]


def start_pcap_capture(output_path):
    return subprocess.Popen([
        "sudo", "tcpdump", "-i", "lo", f"udp port {PORT}",
        "-w", str(output_path)
    ])


def run_one_scenario(name, netem_command):
    print(f"\n=== Running Scenario: {name.upper()} ===")
    for run_index in range(1, 6):
        print(f"\n--- Run {run_index} of 5 ---")
        run_folder = RESULTS_DIR / f"{name}_run{run_index}"
        run_folder.mkdir(exist_ok=True)
        csv_path = run_folder / "telemetry_log.csv"
        pcap_path = run_folder / "trace.pcap"
        run_cmd(CLEAR_NETEM)
        if netem_command:
            print(f"Applying network impairment: {netem_command}")
            run_cmd(netem_command)
        collector_proc = start_collector(csv_path)
        time.sleep(1)
        tcpdump_proc = start_pcap_capture(pcap_path)
        time.sleep(1)
        seed = int(time.time()) + run_index
        sensor_cmd = build_sensor_cmd(seed)
        print(f"Starting sensor (seed={seed}) ...")
        result = run_cmd(sensor_cmd, cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Sensor exited with code {result.returncode}")
        print("Stopping collector and capture ...")
        tcpdump_proc.terminate()
        collector_proc.terminate()
        try:
            tcpdump_proc.wait(timeout=5)
            collector_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tcpdump_proc.kill()
            collector_proc.kill()
        run_cmd(CLEAR_NETEM)
        print(f"Completed {name} run #{run_index}")
    print(f"\n=== Finished Scenario: {name.upper()} ===\n")


def main():
    print("======================================")
    print("Telemetry Protocol Experimental Runner")
    print("======================================")
    print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Results will be saved in: {RESULTS_DIR}\n")
    for scenario, netem_cmd in SCENARIOS.items():
        run_one_scenario(scenario, netem_cmd)
    print("\nAll scenarios completed successfully.")
    print(f"End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Results available in: {RESULTS_DIR}")


if __name__ == "__main__":
    try:
        main()
    finally:
        run_cmd(CLEAR_NETEM)