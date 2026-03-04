import pytest

from config import Config


def test_config_defaults(monkeypatch):
    monkeypatch.delenv("KAFKA_BOOTSTRAP", raising=False)
    monkeypatch.delenv("METRICS_PORT", raising=False)
    monkeypatch.delenv("ELASTIC_URL", raising=False)
    monkeypatch.delenv("ELASTIC_INDEX", raising=False)
    monkeypatch.delenv("PCAP_FILE", raising=False)
    cfg = Config()
    assert cfg.KAFKA_BOOTSTRAP == "kafka:9092"
    assert cfg.METRICS_PORT == 9100
    assert cfg.ELASTIC_URL == "http://elasticsearch:9200"
    assert cfg.ELASTIC_INDEX == "pcap-packets"
    assert cfg.PCAP_FILE is None


def test_config_env(monkeypatch):
    monkeypatch.setenv("KAFKA_BOOTSTRAP", "custom:1234")
    monkeypatch.setenv("METRICS_PORT", "9999")
    monkeypatch.setenv("ELASTIC_URL", "http://custom-es:9200")
    monkeypatch.setenv("ELASTIC_INDEX", "custom-index")
    monkeypatch.setenv("ELASTIC_USERNAME", "user")
    monkeypatch.setenv("ELASTIC_PASSWORD", "pass")
    monkeypatch.setenv("PCAP_FILE", "/data/test.pcap")
    cfg = Config()
    assert cfg.KAFKA_BOOTSTRAP == "custom:1234"
    assert cfg.METRICS_PORT == 9999
    assert cfg.ELASTIC_URL == "http://custom-es:9200"
    assert cfg.ELASTIC_INDEX == "custom-index"
    assert cfg.PCAP_FILE == "/data/test.pcap"
    assert cfg.get_es_auth() == ("user", "pass")
