"""Mojibake gate: no committed source may contain CP1252-mis-decoded UTF-8.

Why this exists
---------------
A batch of UI strings was committed as double- and triple-encoded UTF-8, e.g.
the literal for an ellipsis arrived as the 14 bytes ``c383c2a2c3a2e2809ac2acc382c2a6``
instead of ``e280a6``. The browser rendered that as a run of symbols:

    ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â¦ handoff 66105ca437dc4f96a7e1b79c20d654ca

Severity was cosmetic-but-cosmetic-is-not: this is a product whose entire
thesis is that the UI never shows a claim it cannot evidence. Garbage in the
render path is the same class of defect as a fabricated number, and it also
corrupts copy that a human is expected to read during approval.

Detection
---------
Mojibake is not found by *searching* for the visible garbage -- the visible
form depends on which mis-decode rounds happened, and one variant
(``c383e2809ac2b7``) is already a CP1252 fixed point, so "does reversing the
transform change the string?" answers no and misses it.

Instead this asserts a property of the intended text: every run of non-ASCII
bytes must be legitimate typography. A run is flagged when it contains any
character that only exists in this codebase as a mis-decode artefact
(A-circumflex, A-tilde, florin, euro, single-low-9 quotation, per-mille, ...).
Legitimate multi-character runs are NOT flagged, because they contain none of
those signals:

    "--" + section sign      "+/-" + less-or-equal
    arrow/ellipsis/arrow     box-drawing characters
    warning emoji + U+FE0F

The signal set is the empirical inverse of every mojibake run this gate has
seen in this repository, not a guess at CP1252.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Text suffixes worth scanning. Binaries (.png/.ico/.woff/...) and lockfiles
# are excluded because their bytes are not expected to be UTF-8 text.
TEXT_SUFFIXES = frozenset(
    {
        ".css",
        ".html",
        ".json",
        ".js",
        ".md",
        ".mjs",
        ".py",
        ".sh",
        ".ts",
        ".tsx",
        ".txt",
        ".yaml",
        ".yml",
    }
)

# Characters that appear in this repo ONLY as CP1252 mis-decode artefacts.
MOJIBAKE_SIGNALS = frozenset(
    {
        0x00A2,  # cent sign          <- artefact
        0x00A6,  # broken bar         <- artefact
        0x00AC,  # not sign           <- artefact
        0x00C2,  # A with circumflex  <- artefact
        0x00C3,  # A with tilde       <- artefact
        0x00C5,  # A with ring above  <- artefact
        0x00C6,  # AE ligature        <- artefact
        0x00E2,  # a with circumflex  <- artefact
        0x00E3,  # a with tilde       <- artefact
        0x0152,  # OE ligature        <- artefact
        0x0153,  # oe ligature        <- artefact
        0x0160,  # S with caron       <- artefact
        0x0161,  # s with caron       <- artefact
        0x0178,  # Y with diaeresis   <- artefact
        0x0179,  # Z with caron       <- artefact
        0x017D,  # Z with caron       <- artefact
        0x0192,  # florin             <- artefact
        0x201A,  # single low-9 quote <- artefact
        0x20AC,  # euro sign          <- artefact
        0x2030,  # per mille          <- artefact
        0x2122,  # trade mark         <- artefact
    }
)

# Any run of bytes >= 0x80. Deliberately splits on ASCII so that a mixed run
# such as "-> text" is still inspected.
NON_ASCII_RUN = re.compile(b"[\x80-\xff]+")


def tracked_text_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    paths = []
    for name in out.split("\0"):
        if not name:
            continue
        p = ROOT / name
        if p.suffix in TEXT_SUFFIXES and p.is_file():
            paths.append(p)
    return paths


def find_mojibake() -> list[tuple[str, int, str, str]]:
    """Return (path, line, decoded_run, hex) for every offending run."""
    findings: list[tuple[str, int, str, str]] = []
    for path in tracked_text_files():
        data = path.read_bytes()
        rel = path.relative_to(ROOT).as_posix()
        for lineno, line in enumerate(data.split(b"\n"), 1):
            for match in NON_ASCII_RUN.finditer(line):
                raw = match.group(0)
                try:
                    decoded = raw.decode("utf-8")
                except UnicodeDecodeError:
                    findings.append((rel, lineno, "<invalid utf-8>", raw.hex()))
                    continue
                if any(ord(ch) in MOJIBAKE_SIGNALS for ch in decoded):
                    findings.append((rel, lineno, decoded, raw.hex()))
    return findings


def test_no_mojibake_in_tracked_source() -> None:
    findings = find_mojibake()
    if findings:
        detail = "\n".join(
            f"  {rel}:{lineno}  chars={chars!r}  hex={hexs}"
            for rel, lineno, chars, hexs in findings[:40]
        )
        total = len(findings)
        raise AssertionError(
            f"{total} CP1252-mis-decoded run(s) committed in source. "
            "Fix the literal to the intended character (U+00B7, U+2026, "
            "U+2014, U+2192) and re-run this gate:\n" + detail
        )


def test_gate_actually_detects_mojibake() -> None:
    """A gate that cannot fail is not a gate.

    Feeds the detector the exact byte sequences that shipped the defect and
    asserts each is caught, so the signal set cannot silently drift into
    uselessness.
    """
    caught: list[str] = []
    for hexs in (
        "c383c2a2c3a2e2809ac2acc382c2a6",  # 2x-encoded U+2026
        "c383e2809ac382c2b7",  # 2x-encoded U+00B7
        "c383c692c386e28099c383e2809ac382c2a2c383c692c382c2a2c383c2a2c3a2e2809ac2acc385c2a1"
        "c383e2809ac382c2acc383c692c382c2a2c383c2a2c3a2e282acc5a1c382c2acc383e2809ac382c29d",
        "c383c2a2c3a2e2809ac2acc3a2e282acc29d",  # 2x-encoded U+2014
        "c383c2a2c3a2e282acc2a0c3a2e282ace284a2",  # 2x-encoded U+2192
    ):
        raw = bytes.fromhex(hexs)
        decoded = raw.decode("utf-8")
        if any(ord(ch) in MOJIBAKE_SIGNALS for ch in decoded):
            caught.append(decoded)

    assert len(caught) == 5, f"gate failed to detect known-bad runs: {len(caught)}/5"


def test_intended_typography_is_not_flagged() -> None:
    """Guards against over-broad detection, which would make the gate useless.

    These are the legitimate non-ASCII runs that really occur in the repo: a
    dash plus a section sign in AGENTS.md, an inequality in a doc, an
    arrow-ellipsis-arrow in the master plan, and box drawing in an architecture
    table. All must pass.
    """
    legitimate = [
        "e28093c2a7",  # en dash + section sign   (AGENTS.md)
        "c2b1e289a4",  # plus-minus + less-or-equal
        "e28692e280a6e28692",  # arrow + ellipsis + arrow
        "c2a7c2a7",  # section sign twice
        "e2949ce29480e29480",  # box drawing: tee, horizontal, horizontal
        "e29494e29480e29480",  # box drawing: elbow, horizontal, horizontal
    ]
    for hexs in legitimate:
        decoded = bytes.fromhex(hexs).decode("utf-8")
        assert not any(ord(ch) in MOJIBAKE_SIGNALS for ch in decoded), (
            f"false positive on legitimate text {decoded!r}"
        )


def test_single_typography_chars_are_allowed() -> None:
    for hexs, expected in (
        ("c2b7", "U+00B7 middle dot"),
        ("e280a6", "U+2026 ellipsis"),
        ("e28094", "U+2014 em dash"),
        ("e28692", "U+2192 rightwards arrow"),
    ):
        decoded = bytes.fromhex(hexs).decode("utf-8")
        assert len(decoded) == 1
        assert not any(ord(ch) in MOJIBAKE_SIGNALS for ch in decoded), expected
