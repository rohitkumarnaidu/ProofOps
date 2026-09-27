"""Carriers for the single-use approval token (M07 HITL, ADR-015).

Why this module exists
----------------------
An approval token is an HMAC bearer credential: single-use, TTL-bound, and
deliberately **never persisted** by the approvals store (AGENTS.md 1.1 #4/#6/#7).
That is the right design, and it has a consequence -- something has to carry the
token from the process that minted it to the human who must spend it. If nothing
does, the request can never be approved and the incident stalls forever. This
module is that something, and it is deliberately boring about it.

Three carriers, selected by ``Settings.APPROVAL_TOKEN_DELIVERY``:

``approver_minted`` (default)
    Nothing is carried, because nothing is minted. The control plane parks the
    proposed action; the human raises the approval request from the Safety Gate
    and receives the token in that response. No token ever exists that the
    approver did not create, so no token can leak from us to them.

``out_of_band``
    The control plane mints, then writes the token to a 0600 file *outside* the
    API's own state directory, so the API process cannot read back a live
    credential it issued. The approver reads it out of band and pastes it into
    the Safety Gate, exactly as today.

``scoped_view``
    The control plane mints, and the token is held in this process's memory until
    an approver retrieves it. This is the weakest of the three and is not the
    default, because a live credential crosses a read path. It is implemented
    with mitigations rather than left as a raw token in a GET response:
    approver/admin role only, single-read, TTL-bounded, audited, and never
    included in the ordinary approval view or any list endpoint.

The invariant every carrier must preserve
-----------------------------------------
A carrier may move a token. A carrier may never widen who can use one. In
particular no carrier may make a token retrievable by a principal who could not
already have minted it.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from app import paths

#: Tokens handed over through ``scoped_view`` expire from the moment they are
#: *minted*, not from first read. A token that only starts its clock when someone
#: asks for it would be a token with no TTL at all from the system's point of
#: view.
_SCOPED_VIEW_READ_TTL_SECONDS = 120

#: Guard against unbounded growth if a caller never reads its token. The oldest
#: entries are dropped first; a token nobody claimed is the least useful thing to
#: keep in memory.
_MAX_PENDING = 64


def _sink_dir() -> Path:
    """Directory for out-of-band token files.

    Deliberately a *sibling* of the API state directory, not a child: the
    approvals store and audit chains live under state_dir, and a credential sink
    inside it would be one permissions mistake away from being readable by
    anything that can read the audit log.
    """
    return paths.state_dir().parent / "approval-tokens"


def deliver_out_of_band(approval_id: str, token: str) -> str:
    """Write the token to a 0600 file for out-of-band pickup. Returns the path.

    The file is created with restrictive permissions *at creation time* rather
    than chmod-ed afterwards, so there is no window in which the token exists in
    a world-readable file.
    """
    directory = _sink_dir()
    directory.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        # Best effort: a filesystem that cannot hold POSIX modes (Windows) still
        # gets the file, and the API's own ACLs apply there.
        pass

    target = directory / f"{_safe(approval_id)}.token"
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(token)
    return str(target)


def _safe(approval_id: str) -> str:
    """Constrain an id to a safe filename.

    An approval id becomes a path here, so it must not be able to escape the sink
    directory or carry separators.
    """
    cleaned = "".join(ch for ch in str(approval_id) if ch.isalnum() or ch in "-_")
    return cleaned[:96] or "unknown"


# ---------------------------------------------------------------------------
# scoped_view: in-memory, single-read, approver-only
# ---------------------------------------------------------------------------

_PENDING: dict[str, dict[str, Any]] = {}


def hold_for_scoped_view(approval_id: str, token: str) -> None:
    """Hold a token for one approver to collect, until its TTL lapses."""
    _PENDING[str(approval_id)] = {
        "token": str(token),
        "minted_at": time.time(),
    }
    if len(_PENDING) > _MAX_PENDING:
        oldest = sorted(_PENDING.items(), key=lambda kv: kv[1]["minted_at"])
        for key, _ in oldest[: len(_PENDING) - _MAX_PENDING]:
            _PENDING.pop(key, None)


def peek_scoped_view(approval_id: str) -> bool:
    """Whether a collectable token exists. Reads nothing."""
    _expire()
    return str(approval_id) in _PENDING


def claim_scoped_view(approval_id: str) -> str | None:
    """Consume the token exactly once, or return None.

    Single-use is enforced here, not merely documented. The entry is removed
    before the value is returned, so two concurrent claims cannot both succeed:
    whoever gets there first takes it, and the second finds nothing. An approval
    token that could be spent twice would be a token, not a credential.
    """
    _expire()
    entry = _PENDING.pop(str(approval_id), None)
    if entry is None:
        return None
    return str(entry["token"])


def _expire() -> None:
    """Drop anything past its TTL. Called on every access, not on a timer.

    A background sweeper would keep the process alive and add a moving part; a
    token that is only ever looked up through this module can simply be checked
    at lookup time, which is also the moment the answer is returned.
    """
    cutoff = time.time() - _SCOPED_VIEW_READ_TTL_SECONDS
    for key in [k for k, v in _PENDING.items() if v["minted_at"] < cutoff]:
        _PENDING.pop(key, None)


def pending_count() -> int:
    """How many tokens are awaiting collection. Diagnostics only."""
    _expire()
    return len(_PENDING)
