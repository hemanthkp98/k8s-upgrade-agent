"""Audit event sinks for local files and AWS CloudWatch Logs."""

import contextlib
import io
import os
import time
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from kua.audit.chain import canonical_json
from kua.audit.events import AuditEvent
from kua.core.errors import AuditError

# CloudWatch Logs PutLogEvents constraints:
# Max 10,000 events per batch
# Max 1,048,576 bytes per batch (each event message length + 26 bytes overhead)
MAX_CW_BATCH_EVENTS = 10_000
MAX_CW_BATCH_BYTES = 1_048_576
CW_EVENT_OVERHEAD_BYTES = 26
CW_MAX_RETRIES = 5
CW_BASE_BACKOFF_SECONDS = 0.1

RETRYABLE_ERROR_CODES = {
    "ThrottlingException",
    "Throttling",
    "RequestLimitExceeded",
    "ProvisionedThroughputExceededException",
    "ServiceUnavailable",
    "InternalFailure",
    "InternalServerError",
    "RequestTimeout",
}


@runtime_checkable
class AuditSink(Protocol):
    """Protocol for audit event persistence targets."""

    def write(self, events: list[AuditEvent]) -> None:
        """Write a batch of audit events."""
        ...

    def close(self) -> None:
        """Flush buffers and close resources."""
        ...


class LocalJsonlSink:
    """Writes audit events to a JSONL file per run_id with fsync on close."""

    def __init__(self, dir_path: Path | str) -> None:
        self.dir_path = Path(dir_path)
        self._files: dict[str, io.TextIOWrapper] = {}

    def write(self, events: list[AuditEvent]) -> None:
        """Append audit events to <dir_path>/<run_id>.jsonl."""
        if not events:
            return
        self.dir_path.mkdir(parents=True, exist_ok=True)
        for event in events:
            run_id = event.run_id
            if run_id not in self._files or self._files[run_id].closed:
                file_path = self.dir_path / f"{run_id}.jsonl"
                self._files[run_id] = open(file_path, "a", encoding="utf-8")  # noqa: SIM115
            line = canonical_json(event.model_dump(mode="json")).decode("utf-8")
            self._files[run_id].write(line + "\n")
            self._files[run_id].flush()

    def close(self) -> None:
        """Fsync and close all open file handles."""
        for f in self._files.values():
            if not f.closed:
                f.flush()
                with contextlib.suppress(OSError):
                    os.fsync(f.fileno())
                f.close()
        self._files.clear()


def _is_retryable_cw_error(exc: Exception) -> bool:
    """Determine whether a CloudWatch client error is transient or throttling."""
    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
    http_status = getattr(exc, "response", {}).get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
    return code in RETRYABLE_ERROR_CODES or (500 <= http_status <= 599) or http_status == 429


class CloudWatchSink:
    """Streams audit events to AWS CloudWatch Logs.

    Respects CloudWatch batch size (10k events or 1MB) and rate limits,
    retrying throttling with exponential backoff.
    """

    def __init__(
        self,
        logs_client: Any,
        log_group: str,
        stream: str,
        create_group: bool = False,
        retention_days: int = 365,
        kms_key_arn: str | None = None,
    ) -> None:
        self.logs_client = logs_client
        self.log_group = log_group
        self.stream = stream

        self._ensure_log_group(create_group, retention_days, kms_key_arn)
        self._ensure_log_stream()

    def _ensure_log_group(
        self,
        create_group: bool,
        retention_days: int,
        kms_key_arn: str | None,
    ) -> None:
        """Verify log group existence or optionally create it with retention and KMS."""
        try:
            paginator = self.logs_client.describe_log_groups(logGroupNamePrefix=self.log_group)
            groups = paginator.get("logGroups", [])
            exact_match = any(g.get("logGroupName") == self.log_group for g in groups)
        except Exception as e:
            raise AuditError(
                f"Failed to describe CloudWatch log groups for '{self.log_group}': {e}"
            ) from e

        if not exact_match:
            if not create_group:
                raise AuditError(
                    "log group missing; create via Terraform or set audit.create_log_group"
                )

            create_kwargs: dict[str, Any] = {"logGroupName": self.log_group}
            if kms_key_arn:
                create_kwargs["kmsKeyId"] = kms_key_arn

            try:
                self.logs_client.create_log_group(**create_kwargs)
            except Exception as e:
                code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
                if code != "ResourceAlreadyExistsException":
                    raise AuditError(
                        f"Failed to create CloudWatch log group '{self.log_group}': {e}"
                    ) from e

            try:
                self.logs_client.put_retention_policy(
                    logGroupName=self.log_group,
                    retentionInDays=retention_days,
                )
            except Exception as e:
                raise AuditError(
                    f"Failed to set retention policy on log group '{self.log_group}': {e}"
                ) from e

    def _ensure_log_stream(self) -> None:
        """Create the log stream if it does not already exist."""
        try:
            self.logs_client.create_log_stream(
                logGroupName=self.log_group,
                logStreamName=self.stream,
            )
        except Exception as e:
            code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
            if code != "ResourceAlreadyExistsException":
                raise AuditError(
                    f"Failed to create CloudWatch log stream '{self.stream}': {e}"
                ) from e

    def write(self, events: list[AuditEvent]) -> None:
        """Batch and send audit events to CloudWatch Logs with strict ordering."""
        if not events:
            return

        # CloudWatch requires log events to be sorted strictly by timestamp
        sorted_events = sorted(
            events,
            key=lambda e: (int(e.ts.timestamp() * 1000), e.seq),
        )

        batches: list[list[dict[str, Any]]] = []
        current_batch: list[dict[str, Any]] = []
        current_bytes = 0

        for event in sorted_events:
            message = canonical_json(event.model_dump(mode="json")).decode("utf-8")
            timestamp_ms = int(event.ts.timestamp() * 1000)
            event_dict = {"timestamp": timestamp_ms, "message": message}
            event_bytes = len(message.encode("utf-8")) + CW_EVENT_OVERHEAD_BYTES

            if current_batch and (
                len(current_batch) >= MAX_CW_BATCH_EVENTS
                or current_bytes + event_bytes > MAX_CW_BATCH_BYTES
            ):
                batches.append(current_batch)
                current_batch = []
                current_bytes = 0

            current_batch.append(event_dict)
            current_bytes += event_bytes

        if current_batch:
            batches.append(current_batch)

        for batch in batches:
            self._put_batch_with_retry(batch)

    def _put_batch_with_retry(self, batch: list[dict[str, Any]]) -> None:
        """Submit a single batch to CloudWatch with exponential backoff on retryable errors."""
        for attempt in range(CW_MAX_RETRIES):
            try:
                self.logs_client.put_log_events(
                    logGroupName=self.log_group,
                    logStreamName=self.stream,
                    logEvents=batch,
                )
                return
            except Exception as exc:
                if attempt < CW_MAX_RETRIES - 1 and _is_retryable_cw_error(exc):
                    time.sleep(CW_BASE_BACKOFF_SECONDS * (2**attempt))
                    continue
                raise AuditError(f"CloudWatch put_log_events failed: {exc}") from exc

    def close(self) -> None:
        """No persistent resources to close for CloudWatch client."""


class MultiSink:
    """Fans out audit events to multiple underlying sinks.

    Ensures that local sinks continue writing even if remote sinks (e.g. CloudWatch)
    fail, and aggregates errors to fail loudly on close().
    """

    def __init__(self, sinks: list[AuditSink]) -> None:
        self.sinks = list(sinks)
        self._errors: list[Exception] = []

    def write(self, events: list[AuditEvent]) -> None:
        """Deliver events to all underlying sinks, collecting any errors."""
        for sink in self.sinks:
            try:
                sink.write(events)
            except Exception as e:
                self._errors.append(e)

    def close(self) -> None:
        """Close all child sinks and raise AuditError if any error was encountered."""
        for sink in self.sinks:
            try:
                sink.close()
            except Exception as e:
                self._errors.append(e)

        if self._errors:
            messages = "; ".join(str(e) for e in self._errors)
            raise AuditError(f"One or more audit sinks failed: {messages}")
