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
- Batch size of 100 documents per bulk request
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

Prometheus metrics for observability.

**Producer Metrics:**
| Metric | Type | Description |
|--------|------|-------------|
| `pcap_packets_total` | Counter | Total packets by protocol |
| `pcap_bytes_total` | Counter | Total bytes by protocol |
| `pcap_file_processing_seconds` | Histogram | Time to process a PCAP file |

**Consumer Metrics:**
| Metric | Type | Description |
|--------|------|-------------|
| `pcap_elastic_write_total` | Counter | ES write results (success/fail) |
| `pcap_consumer_lag` | Gauge | Kafka consumer lag |
| `pcap_dlq_messages_total` | Counter | Messages sent to DLQ |

**Prometheus Queries:**
```promql
# Consumer lag
pcap_consumer_lag

# Average file processing time
pcap_file_processing_seconds_sum / pcap_file_processing_seconds_count

# 95th percentile processing time
histogram_quantile(0.95, pcap_file_processing_seconds_bucket)

# DLQ rate per minute
rate(pcap_dlq_messages_total[1m]) * 60

# Packets per protocol
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
