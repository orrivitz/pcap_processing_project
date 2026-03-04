import os
from typing import Optional


class Config:
    def __init__(self):
        # Producer config
        self.KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
        self.METRICS_PORT = int(os.getenv("METRICS_PORT", "9100"))
        # Consumer config
        self.ELASTIC_URL = os.getenv("ELASTIC_URL", "http://elasticsearch:9200")
        self.ELASTIC_INDEX = os.getenv("ELASTIC_INDEX", "pcap-packets")
        self.ELASTIC_USERNAME = os.getenv("ELASTIC_USERNAME")
        self.ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD")
        # CLI / producer config
        self.PCAP_FILE = os.getenv("PCAP_FILE")

    def get_es_auth(self) -> Optional[tuple]:
        if self.ELASTIC_USERNAME and self.ELASTIC_PASSWORD:
            return (self.ELASTIC_USERNAME, self.ELASTIC_PASSWORD)
        return None


config = Config()
