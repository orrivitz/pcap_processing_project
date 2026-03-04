"""Command-line utility for PCAP parsing."""

import argparse
import json
import os
import socket
import subprocess
import sys
from datetime import datetime
from urllib.parse import urlencode

from pcap_parser.parser import parse_pcap


def serialize_packet(row):
    """Serialize a packet row to JSON for Kafka."""
    data = row.to_dict()
    ts = data.get("timestamp")
    if isinstance(ts, datetime):
        data["timestamp"] = ts.isoformat()
    elif isinstance(ts, (int, float)):
        # Convert Unix epoch seconds to ISO format
        data["timestamp"] = datetime.fromtimestamp(ts).isoformat()
    return json.dumps(data).encode("utf-8")


def send_to_kafka(df, kafka_bootstrap, topic):
    """Send packets to Kafka."""
    from kafka import KafkaProducer
    from kafka.errors import KafkaTimeoutError, NoBrokersAvailable

    try:
        producer = KafkaProducer(
            bootstrap_servers=kafka_bootstrap,
            retries=5,
            linger_ms=10,
            acks="all",
            api_version=(2, 0, 0),
            metadata_max_age_ms=5000,
            max_block_ms=10000,
        )
    except NoBrokersAvailable:
        print(f"Error: No Kafka broker available at {kafka_bootstrap}")
        print("Make sure Kafka is running or port-forwarded.")
        return 0, 0

    count = 0
    total_bytes = 0
    try:
        for _, row in df.iterrows():
            msg = serialize_packet(row)
            producer.send(topic, msg)
            count += 1
            total_bytes += row.get("packet_length", 0)

        producer.flush()
    except KafkaTimeoutError:
        print(f"Error: Kafka send timed out after sending {count} packets.")
        print("Make sure Kafka is running or port-forwarded.")
    finally:
        producer.close()
    return count, total_bytes


def _port_is_open(port: int) -> bool:
    """Check if a local port is already listening."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _ensure_port_forward(service: str, local_port: int, remote_port: int):
    """Start kubectl port-forward as a background process if the port isn't already open."""
    if _port_is_open(local_port):
        return  # already forwarded
    try:
        # Use CREATE_NEW_PROCESS_GROUP + CREATE_NO_WINDOW on Windows to fully
        # detach the child so it doesn't inherit parent pipe handles (prevents
        # subprocess.run() in tests from hanging on pipe read).
        flags = 0
        if sys.platform == "win32":
            flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
        subprocess.Popen(
            [
                "kubectl",
                "port-forward",
                f"svc/{service}",
                f"{local_port}:{remote_port}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=flags,
        )
    except FileNotFoundError:
        pass  # kubectl not installed – skip silently


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Parse PCAP and send to Kafka")
    parser.add_argument(
        "pcap_file",
        nargs="?",
        default=os.getenv("PCAP_FILE"),
        help="Path to the input PCAP file (or set PCAP_FILE env var)",
    )
    parser.add_argument(
        "--bootstrap",
        "-b",
        default="localhost:9094",
        help="Kafka bootstrap servers (default: localhost:9094)",
    )
    parser.add_argument(
        "--topic",
        "-t",
        default="pcap-packets",
        help="Kafka topic (default: pcap-packets)",
    )
    args = parser.parse_args(argv)

    if not args.pcap_file:
        parser.error("pcap_file is required (provide as argument or set PCAP_FILE env var)")

    if not os.path.isfile(args.pcap_file):
        print(f"Error: File not found: {args.pcap_file}", file=sys.stderr)
        return 1

    # Parse the pcap file
    print(f"Parsing {args.pcap_file}...")
    df = parse_pcap(args.pcap_file)
    print(f"Parsed {len(df)} packets")

    # Send to Kafka
    print(f"Sending to Kafka ({args.bootstrap}) topic '{args.topic}'...")
    count, total_bytes = send_to_kafka(df, args.bootstrap, args.topic)
    print(f"Sent {count} packets ({total_bytes} bytes) to Kafka")

    # Start port-forwards so dashboard URLs are accessible
    print("\nStarting port-forwards...")
    _ensure_port_forward("redpanda-console", 8080, 8080)
    _ensure_port_forward("prometheus", 9090, 9090)
    _ensure_port_forward("kibana", 5601, 5601)

    # Print dashboard URLs
    print("\n--- Dashboard URLs ---")

    # Kafka – Redpanda Console topics view
    print(f"Kafka Topics (Redpanda Console): http://localhost:8080/topics")

    # Prometheus – one graph panel per metric
    prom_metrics = [
        "pcap_packets_total",
        "pcap_bytes_total",
        "pcap_file_processing_seconds_bucket",
        "pcap_elastic_write_total",
        "pcap_consumer_lag",
        "pcap_dlq_messages_total",
    ]
    prom_params = {}
    for i, expr in enumerate(prom_metrics):
        prom_params[f"g{i}.expr"] = expr
        prom_params[f"g{i}.tab"] = "0"  # 0 = graph view
        prom_params[f"g{i}.range_input"] = "1h"
    prom_url = "http://localhost:9090/graph?" + urlencode(prom_params)
    print(f"Prometheus Dashboard: {prom_url}")

    # Kibana – Dev Tools console (no data-view required, queries all pcap indices)
    kibana_url = "http://localhost:5601/app/dev_tools#/console"
    print(f"Kibana Dev Tools: {kibana_url}")
    print("  Run: GET pcap-*/_search?size=100")

    return 0


if __name__ == "__main__":
    sys.exit(main())
