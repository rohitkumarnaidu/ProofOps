"""Versioned runbook loader with tamper-evident hashing (V2 §20).

Hash = SHA256(canonical YAML-dict minus the `hash` field). Any edit without
re-stamping fails verification -> poisoned-runbook defense in depth.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from app.schemas import Runbook, canonical_json, sha256_hex  # noqa: E402

RUNBOOK_DIR = Path(__file__).resolve().parents[3] / "runbooks"


def content_hash(data: dict) -> str:
    body = {k: v for k, v in data.items() if k != "hash"}
    return sha256_hex(canonical_json(body))


def load_runbook(runbook_id: str, directory: Path = RUNBOOK_DIR) -> Runbook:
    matches = sorted(directory.glob(f"{runbook_id}.yaml"))
    if not matches:
        raise FileNotFoundError(f"runbook not found: {runbook_id}")
    with open(matches[0], encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if data.get("hash") != content_hash(data):
        raise ValueError(f"runbook hash mismatch (tampered?): {runbook_id}")
    return Runbook(**data)


def stamp_hashes(directory: Path = RUNBOOK_DIR) -> None:
    """Maintainer op: recompute `hash` after an intentional, reviewed edit."""
    for path in sorted(directory.glob("*.yaml")):
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        data["hash"] = content_hash(data)
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, sort_keys=False)
