"""Deterministic evidence service (M05): capture, hash, freshness, trust, pack.

Every important conclusion traces CLAIM -> EVIDENCE -> SOURCE -> TIMESTAMP ->
HASH. This module builds that chain's first links: it captures evidence
records with content hashes, judges freshness/trust by deterministic rules,
assembles the bounded Evidence Pack for diagnosis, and measures MUST-CITE
claim coverage for the RCA publish gate.

NO EVIDENCE -> NO CLAIM -> NO ACTION: the coverage gate primitive
(:func:`must_cite_coverage`) measures; the publisher (future A4/publish_rca)
enforces coverage == 1.0. This module never publishes.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any
from collections.abc import Mapping

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.contracts.enums import ClaimClass, SourceType, TrustLevel  # noqa: E402
from app.contracts.evidence import Evidence  # noqa: E402
from app.contracts.hypothesis import Claim  # noqa: E402
from app.contracts.values import canonical_json, sha256_hex  # noqa: E402

# Freshness gate: evidence older than this at capture is stale (spec: the
# policy engine escalates on stale evidence >15m; M18.4 attacks it).
STALE_AFTER_S = 900.0

# Pack budget: the Evidence Pack handed to diagnosis stays compact so raw
# telemetry dumps never enter model context (M05.5; char/4 token estimate).
PACK_MAX_ITEMS = 32
PACK_MAX_REF_LEN = 512


def content_hash(content: bytes | str) -> str:
    """Custody hash of a source blob (M05.2). Bytes hash raw; str as UTF-8."""
    if isinstance(content, bytes):
        return hashlib.sha256(content).hexdigest()
    if isinstance(content, str):
        return sha256_hex(content)
    raise ValueError(
        f"content must be bytes or str, got {type(content).__name__}")


def capture_evidence(incident_id: str, source_type: SourceType | str,
                     source_id: str, ref: str, content: bytes | str,
                     relevance: float = 1.0,
                     trust: TrustLevel | str = TrustLevel.MED,
                     freshness_s: float = 0.0) -> Evidence:
    """Capture one evidence record (M05.1): validated shape + content hash."""
    if isinstance(source_type, str) and not isinstance(source_type, SourceType):
        try:
            source_type = SourceType(source_type)
        except ValueError as exc:
            raise ValueError(f"unknown source_type: {source_type!r}") from exc
    if isinstance(trust, str) and not isinstance(trust, TrustLevel):
        try:
            trust = TrustLevel(trust)
        except ValueError as exc:
            raise ValueError(f"unknown trust level: {trust!r}") from exc
    return Evidence(
        incident_id=incident_id,
        source_type=source_type,  # type: ignore[arg-type]
        source_id=source_id,
        ref=ref,
        hash=content_hash(content),
        freshness_s=freshness_s,
        relevance=relevance,
        trust=trust,  # type: ignore[arg-type]
    )


def is_stale(evidence: Evidence, max_age_s: float = STALE_AFTER_S) -> bool:
    """Freshness gate (M05.3): True when the observation is too old to trust.

    Compares the recorded age-at-capture against the bound. Pure and
    total: every record gets a verdict, never an exception.
    """
    return float(evidence.freshness_s) > float(max_age_s)


def trust_for(fresh: bool, corroborated: bool) -> TrustLevel:
    """Trust-level rule (M05.4), mirroring the M01.4 advisory semantics.

    high = fresh AND corroborated by >=2 independent sources; med = fresh
    single source (default for newly captured evidence); low = stale or
    uncorroborated third-party provenance - consume only with corroboration.
    """
    if fresh and corroborated:
        return TrustLevel.HIGH
    if fresh:
        return TrustLevel.MED
    return TrustLevel.LOW


def pack_size_tokens_estimate(pack: Mapping[str, Any]) -> int:
    """Estimate Evidence Pack size in tokens (chars // 4 heuristic).

    A documented ESTIMATE for budget enforcement, not a tokenizer claim.
    Packs must stay <= 6000 tokens (PROVISIONAL, spec S23) so full telemetry
    blobs never enter model context - they live in storage by ref.
    """
    return len(canonical_json(pack).encode("utf-8")) // 4


def must_cite_coverage(claims: list[Claim],
                       valid_evidence_ids: set[str] | frozenset[str]) -> float:
    """MUST-CITE coverage (M05.6): fraction of must-cite claims with >=1
    valid evidence link. 1.0 (or no must-cite claims) opens the publish
    gate; anything less DENIES publication. SHOULD-CITE/OPTIONAL claims
    are reported but never gate.
    """
    must = [c for c in claims if c.claim_class is ClaimClass.MUST_CITE]
    if not must:
        return 1.0
    covered = sum(1 for c in must
                  if any(e in valid_evidence_ids for e in c.evidence_ids))
    return covered / len(must)
