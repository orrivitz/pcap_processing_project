import os

import pytest

from config import Config


def test_config_defaults(monkeypatch):
    monkeypatch.delenv("KAFKA_BOOTSTRAP", raising=False)
    monkeypatch.delenv("METRICS_PORT", raising=False)
    monkeypatch.delenv("ELASTIC_URL", raising=False)
    cfg = Config()
    assert cfg.KAFKA_BOOTSTRAP == "kafka:9092"
    assert cfg.METRICS_PORT == 9100
    assert cfg.ELASTIC_URL == "http://elasticsearch:9200"


def test_config_env(monkeypatch):
    monkeypatch.setenv("KAFKA_BOOTSTRAP", "custom:1234")
    monkeypatch.setenv("METRICS_PORT", "9999")
    monkeypatch.setenv("ELASTIC_URL", "http://custom-es:9200")
    monkeypatch.setenv("ELASTIC_USERNAME", "user")
    monkeypatch.setenv("ELASTIC_PASSWORD", "pass")
    cfg = Config()
    assert cfg.KAFKA_BOOTSTRAP == "custom:1234"
    assert cfg.METRICS_PORT == 9999
    assert cfg.ELASTIC_URL == "http://custom-es:9200"
    assert cfg.get_es_auth() == ("user", "pass")
