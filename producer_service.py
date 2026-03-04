"""Kafka producer service that watches for PCAP files and sends packets to Kafka."""

import json
import logging
import os
import sys
import time
from datetime import datetime

from kafka import KafkaProducer

from config import config
from metrics import (
    bytes_total,
    file_processing_duration,
    packets_total,
    start_metrics_server,
)
from pcap_parser.parser import parse_pcap

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

TOPIC = "pcap-packets"
WATCH_DIR = os.environ.get("PCAP_WATCH_DIR", "/data/pcap")
PROCESSED_DIR = os.environ.get("PCAP_PROCESSED_DIR", "/data/processed")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "5"))


def serialize_packet(row):
    """Serialize a DataFrame row to a JSON-encoded byte string for Kafka."""
    data = row.to_dict()
    ts = data.get("timestamp")
    if isinstance(ts, datetime):
        data["timestamp"] = ts.isoformat()
    elif isinstance(ts, (int, float)):
        # Convert Unix epoch seconds to ISO format
        data["timestamp"] = datetime.fromtimestamp(ts).isoformat()
    return json.dumps(data).encode("utf-8")


def process_pcap_file(pcap_file, producer):
    """Process a single pcap file and send packets to Kafka."""
    start_time = time.time()
    df = parse_pcap(pcap_file)
    count = 0
    total_bytes = 0
    for _, row in df.iterrows():
        protocol = row["l4_protocol"]
        length = row["packet_length"]
        packets_total.labels(protocol=protocol).inc()
        bytes_total.labels(protocol=protocol).inc(length)
        msg = serialize_packet(row)
        producer.send(TOPIC, msg)
        count += 1
        total_bytes += length
    producer.flush()
    duration = time.time() - start_time
    file_processing_duration.observe(duration)
    logging.info(
        f"Sent {count} packets ({total_bytes} bytes) from {pcap_file} in {duration:.2f}s"
    )
    return count, total_bytes


def watch_directory(producer):
    """Watch directory for new pcap files and process them."""
    os.makedirs(WATCH_DIR, exist_ok=True)
    os.makedirs(PROCESSED_DIR, exist_ok=True)

    logging.info(f"Watching directory: {WATCH_DIR}")
    logging.info(f"Processed files moved to: {PROCESSED_DIR}")

    while True:
        try:
            files = [
                f
                for f in os.listdir(WATCH_DIR)
                if f.endswith((".pcap", ".pcapng"))
                and os.path.isfile(os.path.join(WATCH_DIR, f))
            ]

            for filename in files:
                filepath = os.path.join(WATCH_DIR, filename)
                try:
                    logging.info(f"Processing: {filename}")
                    process_pcap_file(filepath, producer)
                    # Move to processed directory
                    processed_path = os.path.join(PROCESSED_DIR, filename)
                    os.rename(filepath, processed_path)
                    logging.info(f"Moved {filename} to processed directory")
                except Exception as e:
                    logging.error(f"Error processing {filename}: {e}")

            time.sleep(POLL_INTERVAL)
        except Exception as e:
            logging.error(f"Error in watch loop: {e}")
            time.sleep(POLL_INTERVAL)


def main():
    """Run the producer in CLI or watch mode."""
    # CLI mode for backward compatibility
    if len(sys.argv) == 2:
        pcap_file = sys.argv[1]
        start_metrics_server()
        producer = KafkaProducer(
            bootstrap_servers=config.KAFKA_BOOTSTRAP,
            retries=5,
            linger_ms=10,
            value_serializer=lambda v: v,
            acks="all",
        )
        process_pcap_file(pcap_file, producer)
        producer.close()
        return

    # Watch mode for K8s deployment
    start_metrics_server()
    producer = KafkaProducer(
        bootstrap_servers=config.KAFKA_BOOTSTRAP,
        retries=5,
        linger_ms=10,
        value_serializer=lambda v: v,
        acks="all",
    )
    logging.info("Starting in watch mode...")
    try:
        watch_directory(producer)
    finally:
        producer.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Producer shutdown requested.")
        sys.exit(0)
