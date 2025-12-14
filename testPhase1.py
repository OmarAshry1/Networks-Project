import subprocess
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable



collector_cmd = [PYTHON, "collector.py", "--host", "127.0.0.1", "--port", "9999", "--csv", "telemetry_log.csv"]
sensor_cmd = [
        PYTHON,
        "sensor.py",
        "--server-host",
        "127.0.0.1",
        "--server-port",
        "9999",
        "--device-id",
        "100",
        "--interval",
        "1",
        "--batch",
        "1",
        "--duration",
        "60",
]

print("Starting collector for baseline run...")
collector = subprocess.Popen(collector_cmd, cwd=PROJECT_ROOT)
time.sleep(2)

try:
    print("Starting sensor for baseline run (60s)...")
    result = subprocess.run(sensor_cmd, cwd=PROJECT_ROOT, check=False)
    if result.returncode != 0:
        print(f"Sensor exited with code {result.returncode}")
finally:
    print("Stopping collector...")
    collector.terminate()
    try:
        collector.wait(timeout=5)
    except subprocess.TimeoutExpired:
        collector.kill()
        collector.wait()
    print("Baseline scenario completed.")




