"""Deterministic evidence service (M05): capture, hash, freshness, trust, pack.

Every important conclusion traces CLAIM -> EVIDENCE -> SOURCE -> TIMESTAMP ->
HASH. This module builds that chain's first links: it captures evidence
records with content hashes, judges freshness/trust by deterministic rules,
assembles the bounded Evidence Pack for diagnosis, and measures MUST-CITE
claim coverage for the RCA publish gate.

NO EVIDENCE -> NO CLAIM -> NO ACTION: the coverage gate primitive
(:func:`must_cite_coverage`) measures; the publisher (future A4/publish_rca)
enforces coverage == 1.0. This module never publishes. An EMPTY claim list
scores 0.0 (an evidence-free RCA must never pass); a non-empty list with no
MUST-CITE claims scores 1.0 (advisory-only RCAs may publish).
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
                        valid_evidence_ids: set[str] | frozenset[str],
                        evidence_by_id: Mapping[str, Evidence] | None = None
                        ) -> float:
    """MUST-CITE coverage (M05.6): fraction of must-cite claims with >=1
    GROUNDED evidence link. 0.0 for an empty claim list (deny); 1.0 when no
    must-cite claims exist in a non-empty list (advisory-only may publish).

    Two depths (backward compatible): with ``evidence_by_id`` omitted, a
    cited id counts when it is a member of ``valid_evidence_ids`` (legacy
    membership path kept for the A4 draft flow, which pre-validates its set).
    With the mapping provided (the publish-gate path), a cited id counts
    only when it resolves to evidence that is fresh (not stale), trusted
    (MED or HIGH — LOW never grounds), and sealed (non-empty custody hash).
    Per-evidence failures deny that citation (fail closed); malformed
    containers raise (fail loud, never silent).
    """
    if not isinstance(claims, (list, tuple)):
        raise ValueError(
            f"claims must be a list, got {type(claims).__name__}")
    if not isinstance(valid_evidence_ids, (set, frozenset)):
        raise ValueError("valid_evidence_ids must be a set of ids")
    if evidence_by_id is not None and not isinstance(evidence_by_id, Mapping):
        raise ValueError("evidence_by_id must be a mapping or None")
    claims = list(claims)
    if not claims:
        return 0.0
    must = [c for c in claims if c.claim_class == ClaimClass.MUST_CITE]
    if not must:
        return 1.0
    covered = sum(1 for c in must if _safe_grounded(
        c, valid_evidence_ids, evidence_by_id))
    return covered / len(must)


def _safe_grounded(claim: Claim, valid_evidence_ids: set[str] | frozenset[str],
                   evidence_by_id: Mapping[str, Evidence] | None) -> bool:
    """Gate direction: a claim that cannot even be READ denies (never passes
    on confusion)."""
    try:
        return _claim_grounded(claim, valid_evidence_ids, evidence_by_id)
    except Exception:
        return False


def _claim_grounded(claim: Claim, valid_evidence_ids: set[str] | frozenset[str],
                    evidence_by_id: Mapping[str, Evidence] | None) -> bool:
    """One claim counts iff >=1 cited id is a valid, grounded link."""
    for cited in claim.evidence_ids:
        if cited not in valid_evidence_ids:
            continue
        if evidence_by_id is None:
            return True
        try:
            ev = evidence_by_id.get(cited)
            if ev is None:
                continue
            if is_stale(ev):
                continue
            if ev.trust == TrustLevel.LOW:
                continue
            if not ev.hash:
                continue
        except Exception:
            continue  # malformed evidence denies the citation, never passes
        return True
    return False


def verify_evidence_pack(pack: Any) -> bool:
    """Pack verifier (M05.5): shape + budget gate for a built Evidence Pack.

    Activates the PACK_MAX_ITEMS / PACK_MAX_REF_LEN constants (previously
    declared, never enforced): every item must validate as canonical
    Evidence, refs fit their cap, item count fits, and the token estimate
    fits 6000. Total function: malformed input returns False, never raises.
    """
    try:
        if not isinstance(pack, Mapping):
            return False
        items = pack.get("evidence", [])
        if isinstance(items, (str, bytes)) or not isinstance(items, (list, tuple)):
            return False
        items = list(items)
        if len(items) > PACK_MAX_ITEMS:
            return False
        for item in items:
            if not isinstance(item, Mapping):
                return False
            ev = Evidence.model_validate(dict(item))
            if len(ev.ref) > PACK_MAX_REF_LEN:
                return False
        return pack_size_tokens_estimate(pack) <= 6000
    except Exception:
        return False
