"""Unit tests for AuditLogger and run identifier generator."""

import re
from unittest.mock import MagicMock

import pytest

from kua.audit.events import AuditEventType
from kua.audit.logger import AuditLogger, new_run_id
from kua.core.errors import AuditError


def test_new_run_id_format() -> None:
    """new_run_id generates strings matching kua-<yyyymmddTHHMMSSZ>-<6 hex chars>."""
    pattern = re.compile(r"^kua-\d{8}T\d{6}Z-[0-9a-f]{6}$")
    run_id1 = new_run_id()
    run_id2 = new_run_id()

    assert pattern.match(run_id1) is not None
    assert pattern.match(run_id2) is not None
    assert run_id1 != run_id2


def test_audit_logger_buffering_and_auto_flush() -> None:
    """AuditLogger buffers events until buffer_size is reached, then flushes."""
    mock_sink = MagicMock()
    logger = AuditLogger(
        run_id="run-buf-1",
        actor="kua/0.1.0",
        sinks=mock_sink,
        buffer_size=3,
    )

    # Emit 2 events -> should not flush yet
    logger.emit(AuditEventType.RUN_STARTED, {"step": 1})
    logger.emit(AuditEventType.CONFIG_LOADED, {"step": 2})
    assert mock_sink.write.call_count == 0
    assert len(logger.buffer) == 2

    # Emit 3rd event -> reaches buffer_size (3), triggers flush
    logger.emit(AuditEventType.COLLECTOR_STARTED, {"step": 3})
    assert mock_sink.write.call_count == 1
    assert len(logger.buffer) == 0

    # Ensure flushed events were 3
    flushed_events = mock_sink.write.call_args[0][0]
    assert len(flushed_events) == 3
    assert flushed_events[0].seq == 1
    assert flushed_events[1].seq == 2
    assert flushed_events[2].seq == 3


def test_audit_logger_context_manager_flushes_and_closes() -> None:
    """Exiting the context manager flushes remaining events and closes sinks."""
    mock_sink = MagicMock()

    with AuditLogger(
        run_id="run-ctx-1",
        actor="kua/0.1.0",
        sinks=[mock_sink],
        buffer_size=10,
    ) as logger:
        logger.emit(AuditEventType.RUN_STARTED, {"step": 1})
        assert mock_sink.write.call_count == 0

    # On context exit, buffer is flushed and sink is closed
    assert mock_sink.write.call_count == 1
    assert mock_sink.close.call_count == 1


def test_audit_logger_applies_redaction() -> None:
    """Emitted events have redaction applied to sensitive payload values."""
    mock_sink = MagicMock()
    logger = AuditLogger(
        run_id="run-redact",
        actor="kua/0.1.0",
        sinks=mock_sink,
        buffer_size=1,
    )

    event = logger.emit(
        AuditEventType.CONFIG_LOADED,
        {
            "cluster": "prod",
            "api_key": "raw-key-12345",
            "access_key": "AKIAIOSFODNN7EXAMPLE",
        },
    )

    assert event.payload["cluster"] == "prod"
    assert event.payload["api_key"] == "***REDACTED***"
    assert event.payload["access_key"] == "***REDACTED***"


def test_audit_logger_emit_after_close_raises() -> None:
    """Emitting events on a closed logger raises AuditError."""
    mock_sink = MagicMock()
    logger = AuditLogger(
        run_id="run-closed",
        actor="kua/0.1.0",
        sinks=mock_sink,
    )
    logger.close()

    with pytest.raises(AuditError) as exc_info:
        logger.emit(AuditEventType.RUN_FINISHED, {})

    assert "Cannot emit events on a closed AuditLogger" in str(exc_info.value)


def test_audit_logger_double_close_idempotent() -> None:
    """Calling close multiple times is idempotent and does not raise."""
    mock_sink = MagicMock()
    logger = AuditLogger(run_id="run-double", actor="kua", sinks=mock_sink)
    logger.close()
    logger.close()
    assert mock_sink.close.call_count == 1


def test_audit_logger_non_dict_payload_wrapped() -> None:
    """Non-dict payload is wrapped in a dict before chaining."""
    mock_sink = MagicMock()
    logger = AuditLogger(run_id="run-wrap", actor="kua", sinks=mock_sink)
    event = logger.emit(AuditEventType.RUN_STARTED, "scalar-message")  # type: ignore[arg-type]
    assert event.payload == {"value": "scalar-message"}
