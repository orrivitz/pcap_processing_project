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

class Config:
    KAFKA_BOOTSTRAP   # Kafka broker address
    METRICS_PORT      # Prometheus metrics port
    ELASTIC_URL       # Elasticsearch URL
    ELASTIC_USERNAME  # ES authentication
    ELASTIC_PASSWORD  # ES authentication
    ELASTIC_INDEX     # Default index name
```

---

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
  "l4_protocol": "TCP",
  "src_mac": "aa:bb:cc:dd:ee:ff",
  "dst_mac": "11:22:33:44:55:66"
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
