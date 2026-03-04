import json
import logging
import math
import os
import time
from datetime import datetime, timezone

from elasticsearch import Elasticsearch, helpers
from kafka import KafkaConsumer, KafkaProducer

from config import config
from metrics import (
    bytes_total,
    consumer_lag,
    dlq_messages_total,
    elastic_write_total,
    packets_total,
    start_metrics_server,
)

os.environ["PYTHONUNBUFFERED"] = "1"

TOPIC = "pcap-packets"
DLQ_TOPIC = "pcap-packets-dlq"
BATCH_SIZE = 100
GROUP_ID = "pcap-elastic-consumer-v2"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def get_index_name(ts):
    if isinstance(ts, str):
        dt = datetime.fromisoformat(ts)
    else:
        # Unix timestamp (float or int)
        dt = datetime.fromtimestamp(ts)
    return f"pcap-packets-{dt:%Y.%m.%d}"


def sanitize_doc(doc):
    """Replace NaN/Inf values with None for ES compatibility."""
    sanitized = {}
    for key, value in doc.items():
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            sanitized[key] = None
        elif isinstance(value, dict):
            sanitized[key] = sanitize_doc(value)
        else:
            sanitized[key] = value
    return sanitized


def build_bulk_actions(messages, dlq_producer):
    """Build ES bulk actions, sending unparseable messages to DLQ."""
    actions = []
    for msg in messages:
        try:
            doc = json.loads(msg.value)
            doc = sanitize_doc(doc)  # Clean NaN/Inf values
            doc["ingested_at"] = datetime.now(timezone.utc).isoformat()
            index_name = get_index_name(doc["timestamp"])
            # Track packet/byte metrics on consumer side
            protocol = doc.get("l4_protocol", "unknown")
            packets_total.labels(protocol=protocol).inc()
            length = doc.get("packet_length", 0) or 0
            bytes_total.labels(protocol=protocol).inc(length)
            actions.append({"_index": index_name, "_source": doc})
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            # Send malformed message to DLQ
            dlq_msg = {
                "original_message": (
                    msg.value.decode("utf-8", errors="replace")
                    if isinstance(msg.value, bytes)
                    else str(msg.value)
                ),
                "error": f"Parse error: {str(e)}",
                "failed_at": datetime.now(timezone.utc).isoformat(),
                "topic": msg.topic,
                "partition": msg.partition,
                "offset": msg.offset,
            }
            dlq_producer.send(DLQ_TOPIC, json.dumps(dlq_msg).encode("utf-8"))
            dlq_messages_total.labels(reason="parse_error").inc()
            logging.error(f"Failed to parse message at offset {msg.offset}: {e}")
    return actions


def send_to_dlq(producer, failed_docs, error):
    now = datetime.now(timezone.utc).isoformat()
    for doc in failed_docs:
        # Handle different doc structures from ES bulk failures
        if isinstance(doc, dict):
            original = doc.get("_source", doc)
        else:
            original = str(doc)
        dlq_msg = {"original_message": original, "error": error, "failed_at": now}
        try:
            producer.send(DLQ_TOPIC, json.dumps(dlq_msg, default=str).encode("utf-8"))
        except Exception as e:
            logging.error(f"Failed to send to DLQ: {e}")
        dlq_messages_total.labels(reason=error[:50]).inc()


def ensure_dlq_topic(dlq_producer):
    """Send a dummy message to DLQ topic to ensure it exists for monitoring."""
    dlq_msg = {
        "original_message": "DLQ topic initialization",
        "error": "none",
        "failed_at": datetime.now(timezone.utc).isoformat(),
        "note": "This is a dummy message to ensure the DLQ topic exists.",
    }
    dlq_producer.send(DLQ_TOPIC, json.dumps(dlq_msg).encode("utf-8"))
    dlq_messages_total.labels(reason="init").inc()


def main():
    print("Starting consumer...", flush=True)

    # Log startup configuration
    logging.info("=== Consumer Configuration ===")
    logging.info(f"Kafka Bootstrap: {config.KAFKA_BOOTSTRAP}")
    logging.info(f"Elasticsearch URL: {config.ELASTIC_URL}")
    logging.info(f"Metrics Port: {config.METRICS_PORT}")
    logging.info(f"Consumer Group: {GROUP_ID}")
    logging.info(f"Topic: {TOPIC}")
    logging.info(f"DLQ Topic: {DLQ_TOPIC}")
    logging.info(f"Batch Size: {BATCH_SIZE}")
    logging.info("===============================")

    start_metrics_server()
    print("Metrics server started", flush=True)

    # Create consumer WITH group_id for Redpanda Console visibility
    # Must use subscribe() (not assign()) to register with group coordinator
    consumer = KafkaConsumer(
        bootstrap_servers=config.KAFKA_BOOTSTRAP,
        group_id=GROUP_ID,  # Required for consumer group registration
        auto_offset_reset="latest",
        value_deserializer=lambda v: v,
        enable_auto_commit=True,  # Commit offsets automatically
        session_timeout_ms=30000,  # 30s session timeout
        heartbeat_interval_ms=10000,  # 10s heartbeat
        max_poll_interval_ms=300000,  # 5 min max between polls
    )

    # Use subscribe() - NOT assign() - to register with group coordinator
    consumer.subscribe([TOPIC])
    print(f"Consumer group '{GROUP_ID}' subscribed to {TOPIC}", flush=True)

    # Wait for partition assignment (JoinGroup/SyncGroup protocol)
    print("Waiting for partition assignment...", flush=True)
    max_wait = 60  # Wait up to 60 seconds
    waited = 0
    while not consumer.assignment() and waited < max_wait:
        consumer.poll(timeout_ms=1000)
        waited += 1
        if waited % 10 == 0:
            print(f"Still waiting for assignment... ({waited}s)", flush=True)

    assignment = consumer.assignment()
    if not assignment:
        print(
            "ERROR: No partition assignment after 60s. Check group coordinator.",
            flush=True,
        )
    else:
        print(f"Got partition assignment: {assignment}", flush=True)

    dlq_producer = KafkaProducer(
        bootstrap_servers=config.KAFKA_BOOTSTRAP,
        retries=5,
        linger_ms=10,
        value_serializer=lambda v: v,
        acks="all",
    )
    es = Elasticsearch(
        config.ELASTIC_URL, basic_auth=config.get_es_auth(), verify_certs=True
    )
    ensure_dlq_topic(dlq_producer)
    batch = []
    logging.info("Entering main loop...")
    msg_count = 0
    poll_count = 0
    try:
        while True:
            # Use poll() to properly maintain group coordinator heartbeats
            # This ensures consumer stays registered in Redpanda Console
            records = consumer.poll(timeout_ms=5000, max_records=100)
            poll_count += 1

            for tp, messages in records.items():
                for msg in messages:
                    batch.append(msg)
                    msg_count += 1
                    if len(batch) >= BATCH_SIZE:
                        process_batch(batch, es, dlq_producer)
                        batch = []

            # Process remaining batch
            if batch:
                process_batch(batch, es, dlq_producer)
                batch = []

            # Log status every ~60 seconds (12 polls * 5s)
            if poll_count % 12 == 0:
                logging.info(
                    f"Poll #{poll_count}: processed {msg_count} messages total"
                )

    except KeyboardInterrupt:
        logging.info("Consumer shutdown requested.")
    finally:
        consumer.close()
        dlq_producer.close()
        es.close()


def process_batch(batch, es, dlq_producer, max_retries=2):
    actions = build_bulk_actions(batch, dlq_producer)
    if not actions:
        return  # All messages were unparseable

    remaining_actions = actions
    for attempt in range(max_retries + 1):  # max_retries + 1 = total attempts
        try:
            success, failed = helpers.bulk(
                es,
                remaining_actions,
                stats_only=False,
                raise_on_error=False,
                raise_on_exception=False,
            )

            if success:
                elastic_write_total.labels(status="success").inc(success)
                logging.info(f"Bulk write success: {success} indexed")

            if failed:
                if attempt < max_retries:
                    # Retry failed items with exponential backoff
                    remaining_actions = failed
                    backoff = 2**attempt  # 1s, 2s, 4s...
                    logging.warning(
                        f"Bulk write partial failure: {len(failed)} failed, retrying in {backoff}s (attempt {attempt + 2}/{max_retries + 1})"
                    )
                    time.sleep(backoff)
                    continue
                else:
                    # Max retries exceeded, send to DLQ
                    elastic_write_total.labels(status="fail").inc(len(failed))
                    send_to_dlq(
                        dlq_producer, failed, "Elasticsearch bulk failure after retries"
                    )
                    logging.error(
                        f"Bulk write failed after {max_retries + 1} attempts: {len(failed)} sent to DLQ"
                    )

            # Success or partial success handled, exit retry loop
            break

        except Exception as e:
            if attempt < max_retries:
                backoff = 2**attempt
                logging.warning(
                    f"Bulk write error: {e}, retrying in {backoff}s (attempt {attempt + 2}/{max_retries + 1})"
                )
                time.sleep(backoff)
                continue
            else:
                # Max retries exceeded
                elastic_write_total.labels(status="fail").inc(len(remaining_actions))
                send_to_dlq(
                    dlq_producer, remaining_actions, f"ES error after retries: {str(e)}"
                )
                logging.error(
                    f"Bulk write full failure after {max_retries + 1} attempts: {e}"
                )


if __name__ == "__main__":
    main()
