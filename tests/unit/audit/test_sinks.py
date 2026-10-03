"""Unit tests for LocalJsonlSink, CloudWatchSink, and MultiSink."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from kua.audit.chain import HashChain, verify_chain
from kua.audit.events import AuditEvent, AuditEventType
from kua.audit.sinks import CloudWatchSink, LocalJsonlSink, MultiSink
from kua.core.errors import AuditError


def test_local_jsonl_sink(tmp_path: Path) -> None:
    """LocalJsonlSink appends valid JSONL lines that can be verified as a chain."""
    sink = LocalJsonlSink(tmp_path)
    chain = HashChain(run_id="run-local-1")

    events = [
        chain.next(AuditEventType.RUN_STARTED, "kua", {"msg": "start"}),
        chain.next(AuditEventType.FINDING, "kua", {"id": "RULE-1"}),
        chain.next(AuditEventType.RUN_FINISHED, "kua", {"status": "ok"}),
    ]

    sink.write(events[:2])
    sink.write(events[2:])
    sink.write([])  # Empty batch should be no-op
    sink.close()

    log_file = tmp_path / "run-local-1.jsonl"
    assert log_file.exists()

    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3

    read_events = [AuditEvent.model_validate(json.loads(line)) for line in lines]
    assert read_events == events

    valid, bad_idx = verify_chain(read_events)
    assert valid is True
    assert bad_idx is None


@mock_aws
def test_cloudwatch_sink_group_creation_and_retention() -> None:
    """CloudWatchSink creates log group and stream with retention when create_group is True."""
    client = boto3.client("logs", region_name="us-west-2")
    log_group = "/kua/test-cluster"
    stream = "run-cw-1"

    sink = CloudWatchSink(
        logs_client=client,
        log_group=log_group,
        stream=stream,
        create_group=True,
        retention_days=90,
    )

    # Verify log group was created
    desc = client.describe_log_groups(logGroupNamePrefix=log_group)
    groups = desc["logGroups"]
    assert any(g["logGroupName"] == log_group for g in groups)

    # Verify stream was created
    streams_desc = client.describe_log_streams(logGroupName=log_group)
    assert any(s["logStreamName"] == stream for s in streams_desc["logStreams"])

    # Write events
    chain = HashChain(run_id=stream)
    event = chain.next(AuditEventType.RUN_STARTED, "kua", {"hello": "world"})
    sink.write([])
    sink.write([event])
    sink.close()

    # Read back from CloudWatch
    events_resp = client.get_log_events(logGroupName=log_group, logStreamName=stream)
    cw_events = events_resp["events"]
    assert len(cw_events) == 1
    stored_payload = json.loads(cw_events[0]["message"])
    assert stored_payload["run_id"] == stream
    assert stored_payload["payload"] == {"hello": "world"}


@mock_aws
def test_cloudwatch_sink_missing_group_raises() -> None:
    """CloudWatchSink raises AuditError when log group is missing and create_group is False."""
    client = boto3.client("logs", region_name="us-west-2")
    log_group = "/kua/nonexistent"

    with pytest.raises(AuditError) as exc_info:
        CloudWatchSink(
            logs_client=client,
            log_group=log_group,
            stream="run-stream",
            create_group=False,
        )

    assert "log group missing; create via Terraform or set audit.create_log_group" in str(
        exc_info.value
    )


@mock_aws
def test_cloudwatch_sink_existing_stream_ignored() -> None:
    """CloudWatchSink ignores ResourceAlreadyExistsException when stream already exists."""
    client = boto3.client("logs", region_name="us-west-2")
    log_group = "/kua/existing-group"
    stream = "existing-stream"

    client.create_log_group(logGroupName=log_group)
    client.create_log_stream(logGroupName=log_group, logStreamName=stream)

    # Should not raise
    sink = CloudWatchSink(
        logs_client=client,
        log_group=log_group,
        stream=stream,
        create_group=False,
    )
    sink.close()


@mock_aws
def test_cloudwatch_sink_batch_splitting_by_size() -> None:
    """Events are split into multiple put_log_events batches when payload exceeds 1MB."""
    client = boto3.client("logs", region_name="us-west-2")
    log_group = "/kua/batching"
    stream = "run-batch"

    client.create_log_group(logGroupName=log_group)

    sink = CloudWatchSink(
        logs_client=client,
        log_group=log_group,
        stream=stream,
        create_group=False,
    )

    chain = HashChain(run_id=stream)
    # Create 4 events each having ~300KB payload (total ~1.2MB, which exceeds 1,048,576 bytes)
    big_chunk = "x" * 300_000
    events = [
        chain.next(AuditEventType.FINDING, "kua", {"chunk": f"{big_chunk}-{i}"}) for i in range(4)
    ]

    sink.write(events)
    sink.close()

    # Verify all 4 events made it into CloudWatch
    events_resp = client.get_log_events(logGroupName=log_group, logStreamName=stream)
    assert len(events_resp["events"]) == 4


def test_cloudwatch_sink_retries_throttling(monkeypatch: pytest.MonkeyPatch) -> None:
    """CloudWatchSink retries on throttling and succeeds when subsequent call succeeds."""
    mock_client = MagicMock()
    mock_client.describe_log_groups.return_value = {"logGroups": [{"logGroupName": "/kua/retry"}]}

    # First call throttles, second call succeeds
    error_response = {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}}
    mock_client.put_log_events.side_effect = [
        ClientError(error_response, "PutLogEvents"),
        {"nextSequenceToken": "123"},
    ]

    # Speed up backoff for test
    monkeypatch.setattr("kua.audit.sinks.CW_BASE_BACKOFF_SECONDS", 0.001)

    sink = CloudWatchSink(
        logs_client=mock_client,
        log_group="/kua/retry",
        stream="run-retry",
        create_group=False,
    )

    chain = HashChain(run_id="run-retry")
    event = chain.next(AuditEventType.RUN_STARTED, "kua", {})

    sink.write([event])
    assert mock_client.put_log_events.call_count == 2


def test_cloudwatch_sink_exhausted_retries_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """CloudWatchSink raises AuditError when max retries are exhausted."""
    mock_client = MagicMock()
    mock_client.describe_log_groups.return_value = {
        "logGroups": [{"logGroupName": "/kua/retry-fail"}]
    }

    error_response = {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}}
    mock_client.put_log_events.side_effect = ClientError(error_response, "PutLogEvents")

    monkeypatch.setattr("kua.audit.sinks.CW_BASE_BACKOFF_SECONDS", 0.001)

    sink = CloudWatchSink(
        logs_client=mock_client,
        log_group="/kua/retry-fail",
        stream="run-fail",
        create_group=False,
    )

    chain = HashChain(run_id="run-fail")
    event = chain.next(AuditEventType.RUN_STARTED, "kua", {})

    with pytest.raises(AuditError) as exc_info:
        sink.write([event])

    assert "CloudWatch put_log_events failed" in str(exc_info.value)


def test_multi_sink_fanout_and_fail_loud(tmp_path: Path) -> None:
    """MultiSink writes to local sink even if another sink fails, and raises at close()."""
    local_sink = LocalJsonlSink(tmp_path)

    failing_sink = MagicMock()
    failing_sink.write.side_effect = RuntimeError("Remote network failure")

    multi = MultiSink([failing_sink, local_sink])

    chain = HashChain(run_id="run-multi")
    event = chain.next(AuditEventType.RUN_STARTED, "kua", {"status": "ok"})

    # Write does not raise immediately
    multi.write([event])

    # Local sink still received and wrote the event
    log_file = tmp_path / "run-multi.jsonl"
    assert log_file.exists()
    assert "run-multi" in log_file.read_text(encoding="utf-8")

    # Close fails loudly
    with pytest.raises(AuditError) as exc_info:
        multi.close()

    assert "One or more audit sinks failed" in str(exc_info.value)
    assert "Remote network failure" in str(exc_info.value)
