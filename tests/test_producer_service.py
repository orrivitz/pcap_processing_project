from datetime import datetime
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

import producer_service


def test_serialize_packet():
    row = pd.Series(
        {
            "timestamp": datetime(2024, 1, 1, 12, 0, 0),
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "src_port": 1234,
            "dst_port": 80,
            "l4_protocol": "tcp",
            "packet_length": 100,
        }
    )
    result = producer_service.serialize_packet(row)
    assert b'"timestamp": "2024-01-01T12:00:00"' in result


@patch("producer_service.KafkaProducer")
@patch("producer_service.parse_pcap")
def test_main_sends_packets(mock_parse_pcap, mock_kafka):
    df = pd.DataFrame(
        [
            {
                "timestamp": datetime(2024, 1, 1, 12, 0, 0),
                "src_ip": "1.1.1.1",
                "dst_ip": "2.2.2.2",
                "src_port": 1234,
                "dst_port": 80,
                "l4_protocol": "tcp",
                "packet_length": 100,
            }
        ]
    )
    mock_parse_pcap.return_value = df
    mock_producer = MagicMock()
    mock_kafka.return_value = mock_producer
    with patch("producer_service.sys.argv", ["producer_service.py", "dummy.pcap"]):
        with patch("producer_service.start_metrics_server"):
            producer_service.main()
    assert mock_producer.send.called
    assert mock_producer.flush.called
    assert mock_producer.close.called
