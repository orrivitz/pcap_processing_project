import json
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

import consumer_service


def test_get_index_name():
    ts = "2024-01-01T12:00:00"
    idx = consumer_service.get_index_name(ts)
    assert idx == "pcap-packets-2024.01.01"


def test_get_index_name_custom_prefix():
    ts = "2024-06-15T08:30:00"
    idx = consumer_service.get_index_name(ts, index_prefix="custom-index")
    assert idx == "custom-index-2024.06.15"


@patch("consumer_service.KafkaConsumer")
@patch("consumer_service.KafkaProducer")
@patch("consumer_service.Elasticsearch")
@patch("consumer_service.helpers.bulk")
def test_main_process_batch(mock_bulk, mock_es, mock_producer, mock_consumer):
    # Simulate 1 success, 1 fail
    mock_bulk.return_value = (
        1,
        [
            {
                "_source": {
                    "timestamp": "2024-01-01T12:00:00",
                    "l4_protocol": "tcp",
                    "packet_length": 100,
                }
            }
        ],
    )
    batch = [
        MagicMock(
            value=json.dumps(
                {
                    "timestamp": "2024-01-01T12:00:00",
                    "l4_protocol": "tcp",
                    "packet_length": 100,
                }
            ).encode()
        )
    ]
    es = MagicMock()
    dlq_producer = MagicMock()
    consumer_service.process_batch(batch, es, dlq_producer)
    assert dlq_producer.send.called


@patch("consumer_service.helpers.bulk", side_effect=Exception("fail"))
def test_process_batch_full_failure(mock_bulk):
    batch = [
        MagicMock(
            value=json.dumps(
                {
                    "timestamp": "2024-01-01T12:00:00",
                    "l4_protocol": "tcp",
                    "packet_length": 100,
                }
            ).encode()
        )
    ]
    es = MagicMock()
    dlq_producer = MagicMock()
    consumer_service.process_batch(batch, es, dlq_producer)
    assert dlq_producer.send.called


def test_build_bulk_actions_valid_messages():
    """Test build_bulk_actions with valid JSON messages."""
    dlq_producer = MagicMock()
    msg1 = MagicMock(
        value=json.dumps(
            {"timestamp": "2024-01-01T12:00:00", "l4_protocol": "tcp"}
        ).encode()
    )
    msg2 = MagicMock(
        value=json.dumps(
            {"timestamp": "2024-01-02T12:00:00", "l4_protocol": "udp"}
        ).encode()
    )

    actions = consumer_service.build_bulk_actions([msg1, msg2], dlq_producer)

    assert len(actions) == 2
    assert actions[0]["_index"] == "pcap-packets-2024.01.01"
    assert actions[1]["_index"] == "pcap-packets-2024.01.02"
    assert not dlq_producer.send.called


def test_build_bulk_actions_invalid_json():
    """Test build_bulk_actions sends invalid JSON to DLQ."""
    dlq_producer = MagicMock()
    valid_msg = MagicMock(
        value=json.dumps({"timestamp": "2024-01-01T12:00:00"}).encode()
    )
    invalid_msg = MagicMock(
        value=b"not valid json", topic="pcap-packets", partition=0, offset=123
    )

    actions = consumer_service.build_bulk_actions(
        [valid_msg, invalid_msg], dlq_producer
    )

    assert len(actions) == 1  # Only valid message
    assert dlq_producer.send.called
    # Verify DLQ message content
    call_args = dlq_producer.send.call_args
    assert call_args[0][0] == "pcap-packets-dlq"


def test_build_bulk_actions_missing_timestamp():
    """Test build_bulk_actions handles missing timestamp field."""
    dlq_producer = MagicMock()
    msg = MagicMock(
        value=json.dumps({"l4_protocol": "tcp"}).encode(),
        topic="pcap-packets",
        partition=0,
        offset=456,
    )

    actions = consumer_service.build_bulk_actions([msg], dlq_producer)

    assert len(actions) == 0  # No valid actions
    assert dlq_producer.send.called


def test_send_to_dlq():
    """Test send_to_dlq sends messages correctly."""
    dlq_producer = MagicMock()
    failed_docs = [
        {"_source": {"timestamp": "2024-01-01T12:00:00", "data": "test1"}},
        {"_source": {"timestamp": "2024-01-02T12:00:00", "data": "test2"}},
    ]

    consumer_service.send_to_dlq(dlq_producer, failed_docs, "Test error")

    assert dlq_producer.send.call_count == 2
