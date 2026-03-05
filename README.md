# PCAP to Elasticsearch Pipeline

A Kubernetes-based pipeline that reads PCAP files, extracts packet metadata, streams to Kafka, indexes to Elasticsearch, and exposes Prometheus metrics.

## Architecture

```
PCAP File → Producer → Kafka → Consumer → Elasticsearch
                ↓                  ↓
            Prometheus ←──────────┘
```

## Features

* Parses IPv4, ARP, TCP, UDP, ICMP packets
* Supports multiple datalink types (Ethernet, WiFi/Radiotap, Raw IP, Linux SLL)
* Bulk writes to Elasticsearch with retry logic and Dead Letter Queue (DLQ)
* Prometheus metrics for packets, bytes, and ES write status
* Date-based ES indices (`pcap-packets-YYYY.MM.DD`)

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KAFKA_BOOTSTRAP` | `kafka:9092` | Kafka bootstrap servers |
| `ELASTIC_URL` | `http://elasticsearch:9200` | Elasticsearch URL |
| `ELASTIC_INDEX` | `pcap-packets` | Elasticsearch index name prefix |
| `ELASTIC_USERNAME` | *(none)* | ES basic auth username (optional) |
| `ELASTIC_PASSWORD` | *(none)* | ES basic auth password (optional) |
| `METRICS_PORT` | `9100` | Prometheus metrics port |
| `PCAP_FILE` | *(none)* | PCAP file path (alternative to CLI arg) |
| `PCAP_WATCH_DIR` | `/data/pcap` | Directory to watch for PCAP files |
| `PCAP_PROCESSED_DIR` | `/data/processed` | Directory for processed files |
| `POLL_INTERVAL` | `5` | Seconds between directory polls |

## Prerequisites

- Python 3.11+
- Docker
- Minikube
- kubectl

## Quick Start (from scratch)

```bash
# 1. Clone the repo
git clone <repo-url>
cd PacketsProject

# 2. Create virtual environment and install dependencies
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate    # Linux/Mac
pip install -r requirements.txt

# 3. Start minikube (if not already running)
minikube start --driver=docker

# 4. Build Docker images inside minikube
minikube image build -t pcap-producer:latest -f Dockerfile.producer .
minikube image build -t pcap-consumer:latest -f Dockerfile.consumer .

# 5. Deploy all services to Kubernetes
kubectl apply -f k8s/

# 6. Wait for all pods to be Running
kubectl get pods -w

# 7. Port-forward Kafka for local CLI access (keep this terminal open)
kubectl port-forward svc/kafka 9094:9094

# 8. Send a PCAP file (in a second terminal, with venv activated)
python -m pcap_main path/to/capture.pcap
```

The CLI automatically starts port-forwards for Kibana (5601), Prometheus (9090), and Redpanda Console (8080), and prints dashboard URLs.

### Alternative: Watch Mode (in-cluster)

Instead of the CLI, you can copy a PCAP file directly to the producer pod:

```bash
kubectl cp myfile.pcap $(kubectl get pods -l app=pcap-producer -o jsonpath="{.items[0].metadata.name}"):/data/pcap/
```

## Example Elasticsearch Document

```json
{
  "doc_id": "pcap-packets-0-42",
  "timestamp": "2026-03-02T14:30:45.123456",
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "src_port": 54321,
  "dst_port": 443,
  "l4_protocol": "tcp",
  "packet_length": 1500,
  "ingested_at": "2026-03-02T14:30:46.000000"
}
```

The `doc_id` is a deterministic identifier (`topic-partition-offset`) also used as the Elasticsearch `_id` for idempotent writes.

For ARP packets, `src_port` and `dst_port` are `null`, and `l4_protocol` is `"arp"`.

## Prometheus Metrics

Exposed on port `9100` at `/metrics`.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pcap_packets_total` | Counter | `protocol` | Total packets processed |
| `pcap_bytes_total` | Counter | `protocol` | Total bytes processed |
| `pcap_elastic_write_total` | Counter | `status` | ES writes (success/fail) |
| `pcap_dlq_messages_total` | Counter | `reason` | Messages sent to DLQ |
| `pcap_consumer_lag` | Gauge | - | Kafka consumer lag |
| `pcap_file_processing_seconds` | Histogram | - | PCAP file processing time |

### Testing Metrics

```bash
# Port-forward to metrics
kubectl port-forward svc/pcap-consumer 9100:9100

# Fetch metrics
curl http://localhost:9100/metrics
```

## Bulk Write Behavior

The consumer uses Elasticsearch's bulk API for efficient indexing:
- Batches up to 100 documents per bulk request
- Retries failed documents up to 2 times with exponential backoff
- Failed documents after retries are sent to DLQ topic (`pcap-packets-dlq`)
- Metrics track success/failure counts

## Example PCAP Files

Sample PCAP files can be obtained from:
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)
- [tcpdump.org](https://www.tcpdump.org/)
- Generate with `tcpdump -w capture.pcap`

## Testing

```bash
pytest tests/ -v
```

Tests cover:
- PCAP parsing (multiple datalink types, protocols)
- ARP packet extraction
- Consumer DLQ handling
- Metrics increments
- Config defaults and env overrides

## Python API

```python
from pcap_parser.parser import parse_pcap

df = parse_pcap("/path/to/file.pcap")
print(df.head())
```

Returns a DataFrame with columns: `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `l4_protocol`, `packet_length`
