#!/usr/bin/env python3
"""
Comprehensive test runner for IoT Telemetry Protocol
Runs all required test scenarios with proper metrics collection
"""
import subprocess
import sys
import time
import os
import csv
import statistics
from pathlib import Path
from datetime import datetime
import psutil

PROJECT_ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable


PORT = 9999
DURATION = 60  
DEVICE_ID = 100
NUM_RUNS = 5  


REPORTING_INTERVALS = [1.0, 5.0, 30.0]


SCENARIOS = {
    "baseline": {
        "name": "Baseline (no impairment)",
        "netem_cmd": None,
        "description": "No network impairment"
    },
    "loss_5pct": {
        "name": "Loss 5%",
        "netem_cmd": "sudo tc qdisc add dev lo root netem loss 5%",
        "description": "5% random packet loss"
    },
    "delay_jitter": {
        "name": "Delay + Jitter (100ms ±10ms)",
        "netem_cmd": "sudo tc qdisc add dev lo root netem delay 100ms 10ms",
        "description": "100ms delay with 10ms jitter"
    }
}

CLEAR_NETEM = "sudo tc qdisc del dev lo root 2>/dev/null || true"


def run_cmd(cmd, check=True, capture_output=False):
    """Run a shell command"""
    if isinstance(cmd, str):
        print(f"$ {cmd}")
        result = subprocess.run(cmd, shell=True, check=check, capture_output=capture_output)
    else:
        print(f"$ {' '.join(cmd)}")
        result = subprocess.run(cmd, check=check, capture_output=capture_output)
    return result


def clear_netem():
    """Remove any existing netem rules"""
    run_cmd(CLEAR_NETEM, check=False)


def apply_netem(cmd):
    """Apply netem network impairment"""
    if cmd:
        clear_netem()
        run_cmd(cmd)
        print(f"  Applied: {cmd}")
    else:
        clear_netem()


def start_collector(csv_path, verbose=False):
    """Start the collector server"""
    cmd = [
        PYTHON, "collector.py",
        "--host", "127.0.0.1",
        "--port", str(PORT),
        "--csv", str(csv_path)
    ]
    if verbose:
        cmd.append("--verbose")
    proc = subprocess.Popen(cmd, cwd=PROJECT_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(2)  # Give collector time to start
    return proc


def start_sensor(interval, duration, seed=None, batch=1, verbose=False):
    """Start the sensor client"""
    cmd = [
        PYTHON, "sensor.py",
        "--server-host", "127.0.0.1",
        "--server-port", str(PORT),
        "--device-id", str(DEVICE_ID),
        "--interval", str(interval),
        "--duration", str(duration),
        "--batch", str(batch)
    ]
    if seed is not None:
        cmd.extend(["--seed", str(seed)])
    if verbose:
        cmd.append("--verbose")
    return subprocess.Popen(cmd, cwd=PROJECT_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def start_pcap_capture(pcap_path):
    """Start tcpdump to capture packets"""
    cmd = [
        "sudo", "tcpdump", "-i", "lo",
        f"udp port {PORT}",
        "-w", str(pcap_path),
        "-q"  # Quiet mode
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1)  # Give tcpdump time to start
    return proc


def analyze_csv(csv_path):
    """Analyze CSV log and compute metrics"""
    if not csv_path.exists():
        return None
    
    metrics = {
        "packets_received": 0,
        "duplicate_count": 0,
        "gap_count": 0,
        "bytes_per_report": 0,
        "cpu_ms_per_report": 0,
        "duplicate_rate": 0.0,
        "sequence_gap_count": 0
    }
    
    try:
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            
        if not rows:
            return metrics
        
        metrics["packets_received"] = len(rows)
        metrics["duplicate_count"] = sum(1 for r in rows if r.get("duplicate_flag") == "1")
        metrics["gap_count"] = sum(1 for r in rows if r.get("gap_flag") == "1")
        metrics["sequence_gap_count"] = metrics["gap_count"]
        
        if metrics["packets_received"] > 0:
            metrics["duplicate_rate"] = metrics["duplicate_count"] / metrics["packets_received"]
        

        metrics["bytes_per_report"] = 12 + 6  # Header + average reading
        
    except Exception as e:
        print(f"  Warning: Could not analyze CSV: {e}")
    
    return metrics


def run_single_test(scenario_key, scenario, interval, run_num):
    """Run a single test scenario"""
    scenario_name = scenario["name"]
    netem_cmd = scenario["netem_cmd"]
    
    print(f"\n  {'='*60}")
    print(f"  Test: {scenario_name} | Interval: {interval}s | Run: {run_num}/{NUM_RUNS}")
    print(f"  {'='*60}")
    

    results_dir = PROJECT_ROOT / "test_results" / f"{scenario_key}_interval{interval}s"
    results_dir.mkdir(parents=True, exist_ok=True)
    
    csv_path = results_dir / f"run{run_num}_telemetry_log.csv"
    pcap_path = results_dir / f"run{run_num}_trace.pcap"
    

    clear_netem()
    

    if netem_cmd:
        apply_netem(netem_cmd)
    

    print("  Starting packet capture...")
    tcpdump_proc = start_pcap_capture(pcap_path)
    

    print("  Starting collector...")
    collector_proc = start_collector(csv_path)
    

    time.sleep(2)
    

    seed = int(time.time()) + run_num
    print(f"  Starting sensor (seed={seed}, interval={interval}s, duration={DURATION}s)...")
    sensor_proc = start_sensor(interval, DURATION, seed=seed)
    

    collector_pid = collector_proc.pid
    cpu_samples = []
    start_time = time.time()
    
    try:

        sensor_proc.wait()
        sensor_duration = time.time() - start_time
        

        try:
            proc = psutil.Process(collector_pid)
            cpu_samples = [proc.cpu_percent(interval=0.1) for _ in range(10)]
        except:
            pass
        
    except KeyboardInterrupt:
        print("\n  Test interrupted!")
        sensor_proc.terminate()
    

    print("  Stopping processes...")
    tcpdump_proc.terminate()
    collector_proc.terminate()
    
    try:
        tcpdump_proc.wait(timeout=5)
        collector_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        tcpdump_proc.kill()
        collector_proc.kill()
    

    clear_netem()
    

    print("  Analyzing results...")
    metrics = analyze_csv(csv_path)
    
    if metrics:
        avg_cpu = statistics.mean(cpu_samples) if cpu_samples else 0
        metrics["cpu_ms_per_report"] = avg_cpu / 1000.0  # Convert to ms
        print(f"  Results: {metrics['packets_received']} packets, "
              f"{metrics['duplicate_rate']*100:.2f}% duplicates, "
              f"{metrics['gap_count']} gaps")
    
    return metrics


def run_all_scenarios():
    """Run all test scenarios"""
    print("="*70)
    print("IoT Telemetry Protocol - Comprehensive Test Suite")
    print("="*70)
    print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Project Root: {PROJECT_ROOT}")
    print(f"Number of runs per scenario: {NUM_RUNS}")
    print(f"Test duration per run: {DURATION} seconds")
    print("="*70)
    
    all_results = {}
    
    try:
        for scenario_key, scenario in SCENARIOS.items():
            print(f"\n\n{'#'*70}")
            print(f"# SCENARIO: {scenario['name']}")
            print(f"# {scenario['description']}")
            print(f"{'#'*70}")
            
            scenario_results = {}
            
            for interval in REPORTING_INTERVALS:
                print(f"\n\nTesting reporting interval: {interval}s")
                interval_results = []
                
                for run_num in range(1, NUM_RUNS + 1):
                    metrics = run_single_test(scenario_key, scenario, interval, run_num)
                    if metrics:
                        interval_results.append(metrics)
                    time.sleep(2)  # Brief pause between runs
                
                # Compute statistics across runs
                if interval_results:
                    scenario_results[interval] = {
                        "runs": interval_results,
                        "stats": compute_statistics(interval_results)
                    }
            
            all_results[scenario_key] = scenario_results
        

        print("\n\n" + "="*70)
        print("TEST SUMMARY")
        print("="*70)
        generate_summary_report(all_results)
        
    finally:

        clear_netem()
        print("\n\nAll tests completed!")
        print(f"Results saved in: {PROJECT_ROOT / 'test_results'}")


def compute_statistics(results_list):
    """Compute median, min, max for metrics across runs"""
    stats = {}
    
    metrics_to_analyze = [
        "packets_received",
        "duplicate_rate",
        "sequence_gap_count",
        "bytes_per_report",
        "cpu_ms_per_report"
    ]
    
    for metric in metrics_to_analyze:
        values = [r.get(metric, 0) for r in results_list if metric in r]
        if values:
            stats[metric] = {
                "min": min(values),
                "median": statistics.median(values),
                "max": max(values),
                "mean": statistics.mean(values)
            }
    
    return stats


def generate_summary_report(all_results):
    """Generate and print summary report"""
    print("\nSummary Statistics (min / median / max across 5 runs):\n")
    
    for scenario_key, scenario_data in all_results.items():
        scenario_name = SCENARIOS[scenario_key]["name"]
        print(f"\n{scenario_name}:")
        print("-" * 60)
        
        for interval, data in scenario_data.items():
            stats = data["stats"]
            print(f"\n  Interval: {interval}s")
            
            if "packets_received" in stats:
                pr = stats["packets_received"]
                print(f"    Packets Received: {pr['min']:.0f} / {pr['median']:.0f} / {pr['max']:.0f}")
            
            if "duplicate_rate" in stats:
                dr = stats["duplicate_rate"]
                print(f"    Duplicate Rate: {dr['min']*100:.2f}% / {dr['median']*100:.2f}% / {dr['max']*100:.2f}%")
            
            if "sequence_gap_count" in stats:
                sg = stats["sequence_gap_count"]
                print(f"    Sequence Gaps: {sg['min']:.0f} / {sg['median']:.0f} / {sg['max']:.0f}")
            
            if "bytes_per_report" in stats:
                bp = stats["bytes_per_report"]
                print(f"    Bytes/Report: {bp['min']:.1f} / {bp['median']:.1f} / {bp['max']:.1f}")


if __name__ == "__main__":
    try:
        run_all_scenarios()
    except KeyboardInterrupt:
        print("\n\nTest suite interrupted by user")
        clear_netem()
        sys.exit(1)

