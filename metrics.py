"""Prometheus metric definitions for the PCAP processing pipeline."""

from prometheus_client import Counter, Gauge, Histogram, start_http_server

from config import config

# Producer metrics
packets_total = Counter("pcap_packets_total", "Total packets by protocol", ["protocol"])
bytes_total = Counter("pcap_bytes_total", "Total bytes by protocol", ["protocol"])
file_processing_duration = Histogram(
    "pcap_file_processing_seconds",
    "Time to process a PCAP file",
    buckets=[0.1, 0.5, 1, 2, 5, 10, 30, 60, 120],
)

# Consumer metrics
elastic_write_total = Counter(
    "pcap_elastic_write_total", "Elasticsearch write results", ["status"]
)
consumer_lag = Gauge("pcap_consumer_lag", "Kafka consumer lag (messages behind)")
dlq_messages_total = Counter(
    "pcap_dlq_messages_total", "Messages sent to DLQ", ["reason"]
)


def start_metrics_server():
    """Start the Prometheus HTTP metrics server on the configured port."""
    start_http_server(config.METRICS_PORT)
