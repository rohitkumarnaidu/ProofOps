"""M01.1 shared value conventions (identifiers, time, versions, hashes, pages).

Helpers moved verbatim from legacy ``app.schemas`` so behavior cannot drift;
new helpers (``new_id``, ``confidence_bucket``, ``PageParams``) are M01.1
decisions documented below.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from app.contracts.enums import ConfidenceLevel

NAMESPACE_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")

# Log-fetch cap in spec tools (get_logs limit<=500): page ceiling reuses it so
# pagination can never widen a read the spec deliberately bounded.
MAX_PAGE_SIZE = 500


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    """Opaque identifier (uuid4 hex). No global format beyond non-empty."""
    return uuid.uuid4().hex


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def params_hash(params: dict) -> str:
    """Scope binding: approval tokens commit to the EXACT parameter set."""
    return sha256_hex(canonical_json(params))


def confidence_bucket(confidence: float) -> ConfidenceLevel:
    """Map a 0..1 confidence to its bucket. M01.1 thresholds: <0.4 low,
    <0.7 medium, else high. Change only via contract change request."""
    if not 0.0 <= confidence <= 1.0:
        raise ValueError(f"confidence must be within 0..1, got: {confidence}")
    if confidence < 0.4:
        return ConfidenceLevel.LOW
    if confidence < 0.7:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.HIGH


class PageParams(BaseModel):
    """Pagination basics. Bounded so reads stay within spec limits."""

    model_config = {"frozen": True}

    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=MAX_PAGE_SIZE)
