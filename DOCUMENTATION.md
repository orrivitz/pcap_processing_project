# PCAP Processing Pipeline - Documentation

A distributed system for parsing PCAP network capture files and indexing packet data into Elasticsearch via Kafka.

## Architecture Overview

### Data Flow (Packet Processing)
```
┌─────────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌───────────────┐     ┌─────────┐
│  PCAP File  │────▶│ Producer │────▶│  Kafka   │────▶│ Consumer │────▶│ Elasticsearch │────▶│ Kibana  │
└─────────────┘     └──────────┘     └──────────┘     └──────────┘     └───────────────┘     └─────────┘
```

### Metrics Flow (Observability)
```
┌──────────┐
│ Producer │──────┐
└──────────┘      │     ┌────────────┐
                  ├────▶│ Prometheus │  (scrapes /metrics on port 9100)
┌──────────┐      │     └────────────┘
│ Consumer │──────┘
└──────────┘
```

### Combined View
```
                                    DATA FLOW
┌─────────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌───────────────┐
│  PCAP File  │────▶│ Producer │────▶│  Kafka   │────▶│ Consumer │────▶│ Elasticsearch │
└─────────────┘     └────┬─────┘     └──────────┘     └────┬─────┘     └───────┬───────┘
                         │                                 │                   │
                         │ metrics                         │ metrics           │
                         ▼                                 ▼                   ▼
                    ┌────────────────────────────────────────┐          ┌───────────┐
                    │              Prometheus                │          │  Kibana   │
                    │         (scrapes :9100/metrics)        │          │  (UI)     │
                    └────────────────────────────────────────┘          └───────────┘
```

---

## Module Reference

### 1. CLI Entry Point (`pcap_main.py`)

Command-line tool that parses a PCAP file and sends packet data to Kafka.

**Usage:**
```bash
python -m pcap_main <pcap_file> [--bootstrap HOST:PORT] [--topic TOPIC]
```

The PCAP file can also be specified via the `PCAP_FILE` environment variable.

Auto-starts `kubectl port-forward` for Redpanda Console (8080), Prometheus (9090), and Kibana (5601), then prints dashboard URLs.

### 2. PCAP Parser (`pcap_parser/parser.py`)

Core parsing module using `dpkt`.

| Function | Description |
|----------|-------------|
| `parse_packet(ts, buf, datalink)` | Parse a single packet buffer, returns a dict or `None` |
| `parse_pcap(file_path)` | Parse entire PCAP file, returns `pandas.DataFrame` |
| `iter_pcap(file_path)` | Streaming generator, yields one packet dict at a time |

**Supported datalink types:** Ethernet (`DLT_EN10MB`), Linux SLL (`DLT_LINUX_SLL`), Raw IP (`DLT_RAW`), Loopback (`DLT_NULL`), WiFi 802.11 (`DLT_IEEE802_11`), Radiotap (`DLT_IEEE802_11_RADIO`).

**Supported protocols:** TCP, UDP, ICMP, ARP, other.

### 3. Producer Service (`producer_service.py`)

Kafka producer that runs in two modes:

- **CLI mode** — process a single PCAP file
- **Watch mode** — poll a directory for new `.pcap`/`.pcapng` files

### 4. Consumer Service (`consumer_service.py`)

Kafka consumer that reads packets from Kafka and bulk-indexes them to Elasticsearch.

**Features:**
- Batch size of up to 100 documents per bulk request (smaller batches are flushed immediately after each poll cycle, so files with fewer than 100 packets are processed without waiting)
- Idempotent writes — each document gets a deterministic `_id` (`topic-partition-offset`) so retries overwrite instead of duplicating
- Retry with exponential backoff (up to 2 retries)
- Dead Letter Queue (`pcap-packets-dlq`) for failed documents
- Consumer lag tracking via Prometheus Gauge
- Auto-applies ES index template on startup

### 5. Configuration (`config.py`)

Centralized configuration via environment variables.

```python
class Config:
    KAFKA_BOOTSTRAP   # Kafka broker address (default: kafka:9092)
    METRICS_PORT      # Prometheus metrics port (default: 9100)
    ELASTIC_URL       # Elasticsearch URL (default: http://elasticsearch:9200)
    ELASTIC_INDEX     # Index name prefix (default: pcap-packets)
    ELASTIC_USERNAME  # ES basic auth username (optional)
    ELASTIC_PASSWORD  # ES basic auth password (optional)
    PCAP_FILE         # PCAP file path (optional, alternative to CLI arg)
```

### 6. Metrics (`metrics.py`)

Prometheus metrics for observability. Both the producer and consumer expose a `/metrics` HTTP endpoint on port 9100, which Prometheus scrapes every 15 seconds (configured in `prometheus.yaml`).

#### Producer Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pcap_packets_total` | Counter | `protocol` | Cumulative count of packets parsed, broken down by L4 protocol (`tcp`, `udp`, `icmp`, `arp`, `other`). Incremented once per packet during PCAP parsing. |
| `pcap_bytes_total` | Counter | `protocol` | Cumulative byte count of raw packet data, broken down by L4 protocol. Reflects the `packet_length` field of each parsed packet. |
| `pcap_file_processing_seconds` | Histogram | *(none)* | Wall-clock time (in seconds) to parse a single PCAP file end-to-end. Uses buckets: 0.1, 0.5, 1, 2, 5, 10, 30, 60, 120 seconds. |

**What's normal / abnormal:**

| Metric | Normal Range | Investigate If |
|--------|-------------|----------------|
| `pcap_packets_total` | Grows proportionally to file size | Stays at 0 after sending a file (parsing failed or file was empty) |
| `pcap_bytes_total` | Roughly `pcap_packets_total × avg_packet_size` | Much larger than expected (malformed length fields) or 0 |
| `pcap_file_processing_seconds` | < 10s for files under 100K packets; < 60s for 1M packets | > 120s consistently (disk I/O bottleneck or very large file) |

#### Consumer Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pcap_elastic_write_total` | Counter | `status` | Cumulative count of documents written to Elasticsearch. Label `status=success` counts indexed docs; `status=fail` counts docs that failed after all retries and were sent to the DLQ. |
| `pcap_consumer_lag` | Gauge | *(none)* | Current number of messages the consumer is behind the latest Kafka offset. Calculated every poll cycle by comparing committed offsets to end offsets across all assigned partitions. |
| `pcap_dlq_messages_total` | Counter | `reason` | Cumulative count of messages sent to the Dead Letter Queue (`pcap-packets-dlq`). Label `reason` indicates the cause: `invalid_json`, `missing_timestamp`, `es_bulk_failure`, or `init` (startup dummy message). |

**What's normal / abnormal:**

| Metric | Normal Range | Investigate If |
|--------|-------------|----------------|
| `pcap_elastic_write_total{status="success"}` | Grows steadily as data is consumed | Flat while `pcap_packets_total` is growing (consumer not running or ES is down) |
| `pcap_elastic_write_total{status="fail"}` | 0 (ideal) or very low | > 1% of total writes — indicates persistent ES issues or bad data |
| `pcap_consumer_lag` | 0 when idle; spikes briefly after sending a file, then returns to 0 | Stays > 0 for minutes (consumer is too slow, crashed, or ES is unresponsive) |
| `pcap_dlq_messages_total` | 1 (`init` message at startup) | Growing beyond 1 — means real messages are failing. Check `reason` label to diagnose |

#### Useful Prometheus Queries

```promql
# Current consumer lag (should be 0 when caught up)
pcap_consumer_lag

# Average file processing time (seconds)
pcap_file_processing_seconds_sum / pcap_file_processing_seconds_count

# 95th percentile processing time
histogram_quantile(0.95, pcap_file_processing_seconds_bucket)

# DLQ messages per minute (should be 0 in normal operation)
rate(pcap_dlq_messages_total[1m]) * 60

# ES write success rate (should be close to 1.0)
pcap_elastic_write_total{status="success"}
  / (pcap_elastic_write_total{status="success"} + pcap_elastic_write_total{status="fail"})

# Packets parsed per second (rate over last 5 minutes)
rate(pcap_packets_total[5m])

# Bytes processed per second by protocol
rate(pcap_bytes_total[5m])

# Total packets per protocol (breakdown)
pcap_packets_total
```

---

## Kubernetes Deployment

### Services

| Service | Port | Description |
|---------|------|-------------|
| Kafka | 9092 (internal), 9094 (external) | Message broker |
| Elasticsearch | 9200 | Search engine |
| Kibana | 5601 | Visualization |
| Prometheus | 9090 | Metrics |
| Redpanda Console | 8080 | Kafka UI |

### Deploy All Services

```bash
kubectl apply -f k8s/
```

### Access UIs (Minikube)

```bash
# Kibana
minikube service kibana --url

# Prometheus
minikube service prometheus --url

# Redpanda Console (Kafka UI)
minikube service redpanda-console --url
```

### Port Forward for CLI

```bash
# Required to use CLI locally
kubectl port-forward svc/kafka 9094:9094
```

---

## Docker Images

### Build Images (Minikube)

```bash
minikube image build -t pcap-producer:latest -f Dockerfile.producer .
minikube image build -t pcap-consumer:latest -f Dockerfile.consumer .
```

### Restart Deployments

```bash
kubectl rollout restart deployment pcap-producer pcap-consumer
```

---

## Data Flow

1. **Ingestion** - PCAP file → Producer parses → Sends JSON packets to Kafka
2. **Processing** - Consumer reads from Kafka → Bulk indexes to Elasticsearch
3. **Visualization** - Kibana queries Elasticsearch for packet data
4. **Monitoring** - Prometheus scrapes metrics from Producer/Consumer

---

## Elasticsearch Index

**Index Pattern:** `pcap-packets-YYYY.MM.DD`

**Document Schema:**
```json
{
  "doc_id": "pcap-packets-0-42",
  "timestamp": "2026-03-02T10:30:45.123456",
  "packet_length": 1500,
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "src_port": 443,
  "dst_port": 52341,
  "l4_protocol": "tcp",
  "ingested_at": "2026-03-02T10:30:46.000000"
}
```

The `doc_id` is a deterministic identifier derived from the Kafka topic, partition, and offset (e.g., `pcap-packets-0-42`). It is also used as the Elasticsearch `_id`, ensuring idempotent writes.

**Query Example (via curl):**
```bash
curl -s "http://localhost:9200/pcap-packets-*/_count"
curl -s "http://localhost:9200/pcap-packets-*/_search?size=10"
```

---

## Dependencies

**requirements.txt:**
- `dpkt` - PCAP parsing
- `kafka-python` - Kafka client
- `elasticsearch>=8.0.0,<9.0.0` - Elasticsearch client
- `prometheus_client` - Metrics
- `pandas` - Data processing
- `pytest` - Test framework
- `scapy` - Packet crafting (tests only)

---

## Quick Start

```bash
# 1. Deploy to Kubernetes
kubectl apply -f k8s/

# 2. Wait for pods
kubectl get pods -w

# 3. Port forward Kafka
kubectl port-forward svc/kafka 9094:9094

# 4. Send PCAP file
python -m pcap_main "path/to/capture.pcap"

# 5. Check Elasticsearch
kubectl exec $(kubectl get pods -l app=elasticsearch -o jsonpath="{.items[0].metadata.name}") -- curl -s "http://localhost:9200/pcap-packets-*/_count"

# 6. View in Kibana
minikube service kibana --url
```
