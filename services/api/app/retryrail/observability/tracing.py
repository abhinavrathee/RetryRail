"""W3C-compatible request context and immutable domain-lineage helpers."""

from __future__ import annotations

import hashlib
import re
import secrets
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, cast

import structlog
from sqlalchemy import select

from retryrail.db.tables import TraceLinkRecord

if TYPE_CHECKING:
    from collections.abc import Generator
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession

_TRACEPARENT = re.compile(
    r"^00-(?P<trace_id>[0-9a-f]{32})-(?P<parent_id>[0-9a-f]{16})-"
    r"(?P<flags>[0-9a-f]{2})$",
    re.IGNORECASE,
)
_CURRENT_TRACE: ContextVar[TraceContext | None] = ContextVar(
    "retryrail_current_trace",
    default=None,
)
_ZERO_TRACE_ID = "0" * 32
_ZERO_SPAN_ID = "0" * 16


class TraceEntity(StrEnum):
    """Bounded domain entities admitted to the correlation ledger."""

    EVENT = "event"
    OUTBOX = "outbox"
    INCIDENT = "incident"
    PLAN = "plan"
    ACTION = "action"


class TraceLineageError(ValueError):
    """A stored trace link conflicts with the requested bounded lineage."""


@dataclass(frozen=True, slots=True)
class TraceContext:
    """Validated in-process trace context with no business or customer data."""

    trace_id: str
    span_id: str
    sampled: bool = True

    @property
    def traceparent(self) -> str:
        """Render the W3C traceparent value returned by the API."""

        flags = "01" if self.sampled else "00"
        return f"00-{self.trace_id}-{self.span_id}-{flags}"


def request_trace_context(traceparent: str | None) -> TraceContext:
    """Continue a valid W3C trace or start a fresh bounded trace."""

    trace_id: str | None = None
    sampled = True
    if traceparent is not None and (match := _TRACEPARENT.fullmatch(traceparent.strip())):
        candidate_trace = match.group("trace_id").lower()
        candidate_parent = match.group("parent_id").lower()
        if candidate_trace != _ZERO_TRACE_ID and candidate_parent != _ZERO_SPAN_ID:
            trace_id = candidate_trace
            sampled = bool(int(match.group("flags"), 16) & 1)
    return TraceContext(
        trace_id=trace_id or secrets.token_hex(16),
        span_id=secrets.token_hex(8),
        sampled=sampled,
    )


@contextmanager
def bind_trace_context(context: TraceContext) -> Generator[None]:
    """Bind one trace to both service helpers and structured application logs."""

    token = _CURRENT_TRACE.set(context)
    try:
        with structlog.contextvars.bound_contextvars(
            trace_id=context.trace_id,
            span_id=context.span_id,
        ):
            yield
    finally:
        _CURRENT_TRACE.reset(token)


def current_trace_context() -> TraceContext | None:
    """Return the currently bound request/worker trace, when one exists."""

    return _CURRENT_TRACE.get()


def deterministic_trace_id(merchant_id: str, entity_type: TraceEntity, entity_id: str) -> str:
    """Create a stable non-reversible fallback for non-HTTP and legacy roots."""

    return _digest("trace", merchant_id, entity_type.value, entity_id)[:32]


def deterministic_span_id(entity_type: TraceEntity, entity_id: str) -> str:
    """Create the stable span identity used to make retries idempotent."""

    return _digest("span", entity_type.value, entity_id)[:16]


async def ensure_root_trace_link(
    session: AsyncSession,
    *,
    merchant_id: str,
    entity_type: TraceEntity,
    entity_id: str,
    created_at: datetime,
    trace_id: str | None = None,
) -> TraceLinkRecord:
    """Return or stage one immutable root link for a domain entity."""

    existing = await _trace_link(session, entity_type=entity_type, entity_id=entity_id)
    if existing is not None:
        _validate_existing(existing, merchant_id=merchant_id)
        return existing
    active = current_trace_context()
    resolved_trace_id = trace_id or (
        active.trace_id
        if active is not None
        else deterministic_trace_id(merchant_id, entity_type, entity_id)
    )
    record = TraceLinkRecord(
        trace_link_id=_digest("link", entity_type.value, entity_id)[:80],
        trace_id=resolved_trace_id,
        span_id=deterministic_span_id(entity_type, entity_id),
        parent_span_id=None,
        entity_type=entity_type.value,
        entity_id=entity_id,
        merchant_id=merchant_id,
        created_at=created_at,
    )
    session.add(record)
    return record


async def ensure_child_trace_link(
    session: AsyncSession,
    *,
    merchant_id: str,
    entity_type: TraceEntity,
    entity_id: str,
    parent: TraceLinkRecord,
    created_at: datetime,
) -> TraceLinkRecord:
    """Return or stage one child while preserving its parent's trace identity."""

    if parent.merchant_id != merchant_id:
        raise TraceLineageError
    existing = await _trace_link(session, entity_type=entity_type, entity_id=entity_id)
    if existing is not None:
        _validate_existing(
            existing,
            merchant_id=merchant_id,
            trace_id=parent.trace_id,
            parent_span_id=parent.span_id,
        )
        return existing
    record = TraceLinkRecord(
        trace_link_id=_digest("link", entity_type.value, entity_id)[:80],
        trace_id=parent.trace_id,
        span_id=deterministic_span_id(entity_type, entity_id),
        parent_span_id=parent.span_id,
        entity_type=entity_type.value,
        entity_id=entity_id,
        merchant_id=merchant_id,
        created_at=created_at,
    )
    session.add(record)
    return record


async def get_trace_link(
    session: AsyncSession,
    *,
    entity_type: TraceEntity,
    entity_id: str,
) -> TraceLinkRecord | None:
    """Read one entity's immutable trace link without mutating lineage."""

    return await _trace_link(session, entity_type=entity_type, entity_id=entity_id)


async def _trace_link(
    session: AsyncSession,
    *,
    entity_type: TraceEntity,
    entity_id: str,
) -> TraceLinkRecord | None:
    return cast(
        "TraceLinkRecord | None",
        await session.scalar(
            select(TraceLinkRecord).where(
                TraceLinkRecord.entity_type == entity_type.value,
                TraceLinkRecord.entity_id == entity_id,
            )
        ),
    )


def _validate_existing(
    record: TraceLinkRecord,
    *,
    merchant_id: str,
    trace_id: str | None = None,
    parent_span_id: str | None = None,
) -> None:
    if record.merchant_id != merchant_id:
        raise TraceLineageError
    if trace_id is not None and record.trace_id != trace_id:
        raise TraceLineageError
    if parent_span_id is not None and record.parent_span_id != parent_span_id:
        raise TraceLineageError


def _digest(*parts: str) -> str:
    material = "\x1f".join(("retryrail-trace-v1", *parts)).encode()
    return hashlib.sha256(material).hexdigest()
