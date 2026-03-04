from prometheus_client import CollectorRegistry, Counter


def get_metric_value(counter, labels):
    for sample in counter.collect()[0].samples:
        if all(sample.labels.get(k) == v for k, v in labels.items()):
            return sample.value
    return 0


def test_packets_total_metric():
    registry = CollectorRegistry()
    packets_total = Counter(
        "pcap_packets_total",
        "Total packets by protocol",
        ["protocol"],
        registry=registry,
    )
    packets_total.labels(protocol="tcp").inc()
    packets_total.labels(protocol="udp").inc(2)
    tcp_val = get_metric_value(packets_total, {"protocol": "tcp"})
    udp_val = get_metric_value(packets_total, {"protocol": "udp"})
    assert tcp_val == 1
    assert udp_val == 2


def test_bytes_total_metric():
    registry = CollectorRegistry()
    bytes_total = Counter(
        "pcap_bytes_total", "Total bytes by protocol", ["protocol"], registry=registry
    )
    bytes_total.labels(protocol="tcp").inc(100)
    bytes_total.labels(protocol="udp").inc(200)
    tcp_val = get_metric_value(bytes_total, {"protocol": "tcp"})
    udp_val = get_metric_value(bytes_total, {"protocol": "udp"})
    assert tcp_val == 100
    assert udp_val == 200


def test_elastic_write_total_metric():
    registry = CollectorRegistry()
    elastic_write_total = Counter(
        "pcap_elastic_write_total",
        "Elasticsearch write results",
        ["status"],
        registry=registry,
    )
    elastic_write_total.labels(status="success").inc(5)
    elastic_write_total.labels(status="fail").inc(2)
    success_val = get_metric_value(elastic_write_total, {"status": "success"})
    fail_val = get_metric_value(elastic_write_total, {"status": "fail"})
    assert success_val == 5
    assert fail_val == 2
