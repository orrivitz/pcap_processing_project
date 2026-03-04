#!/usr/bin/env python
"""Benchmark script to measure parser performance."""

import sys
import time
from pathlib import Path

from pcap_parser.parser import parse_pcap


def benchmark(pcap_file: str, runs: int = 5):
    """Measure parse time for a PCAP file over multiple runs."""
    if not Path(pcap_file).exists():
        print(f"Error: File not found: {pcap_file}")
        return

    times = []
    print(f"\nBenchmarking: {pcap_file}")
    print(f"Running {runs} iterations...\n")

    for i in range(runs):
        start = time.perf_counter()
        df = parse_pcap(pcap_file)
        elapsed = time.perf_counter() - start
        times.append(elapsed)
        print(f"  Run {i+1}: {elapsed*1000:.2f}ms ({len(df)} packets)")

    avg_time = sum(times) / len(times)
    min_time = min(times)
    max_time = max(times)

    print(f"\nResults:")
    print(f"  Average: {avg_time*1000:.2f}ms")
    print(f"  Min:     {min_time*1000:.2f}ms")
    print(f"  Max:     {max_time*1000:.2f}ms")
    print(
        f"  Std Dev: {(sum((t - avg_time)**2 for t in times) / len(times))**0.5 * 1000:.2f}ms"
    )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python benchmark.py <pcap_file> [runs]")
        print("Example: python benchmark.py 5.pcap 5")
        sys.exit(1)

    pcap_file = sys.argv[1]
    runs = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    benchmark(pcap_file, runs)
