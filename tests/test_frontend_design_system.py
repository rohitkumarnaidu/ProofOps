"""Design-system tokens: WCAG contrast is asserted, not assumed.

The design-system audit found ~34 raw colour literals spread across 199
className sites with no token layer and no contrast verification. Introducing
tokens without verification only centralises the problem: one edit to
`--color-fg-muted` would silently degrade every screen at once, and no test in
the repo could see it.

So these tests parse the tokens back out of index.css and compute real WCAG 2.x
contrast ratios for the pairs the UI actually renders. A token that stops
contrast is a build failure, which is the whole point of having tokens.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CSS = ROOT / "frontend" / "src" / "index.css"
UI = ROOT / "frontend" / "src" / "components" / "ui.tsx"

# 2.1 sRGB -> linear light, per WCAG 2.x relative-luminance definition.
def _channel(value: float) -> float:
    if value <= 0.03928:
        return value / 12.92
    return ((value + 0.055) / 1.055) ** 2.4


def luminance(hex_color: str) -> float:
    r, g, b = _rgb(hex_color)
    return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)


def _rgb(hex_color: str) -> tuple[float, float, float]:
    value = hex_color.lstrip("#")
    assert len(value) == 6, f"expected 6-digit hex, got {hex_color!r}"
    return (
        int(value[0:2], 16) / 255,
        int(value[2:4], 16) / 255,
        int(value[4:6], 16) / 255,
    )


def contrast(fg: str, bg: str) -> float:
    a, b = luminance(fg), luminance(bg)
    hi, lo = max(a, b), min(a, b)
    return (hi + 0.05) / (lo + 0.05)


def tokens() -> dict[str, str]:
    """Read `--color-*: #hex` declarations out of the token layer."""
    css = CSS.read_text(encoding="utf-8")
    return {
        name: value
        for name, value in re.findall(r"--color-([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\s*;", css)
    }


TOKENS = tokens()


# ---------------------------------------------------------------------------
# Text pairs the UI actually renders
# ---------------------------------------------------------------------------

# (foreground, background, minimum ratio, what it is)
TEXT_PAIRS = [
    ("fg", "canvas", 4.5, "primary body text on the app background"),
    ("fg", "surface", 4.5, "primary body text on a panel"),
    ("fg", "surface-raised", 4.5, "primary body text on a hovered/raised row"),
    ("fg-muted", "canvas", 4.5, "secondary text on the app background"),
    ("fg-muted", "surface", 4.5, "secondary text on a panel"),
    ("fg-subtle", "canvas", 4.5, "captions and meta on the app background"),
    ("fg-subtle", "surface", 4.5, "captions and meta on a panel"),
    ("accent-fg", "accent", 4.5, "primary button label"),
    ("ok-fg", "ok", 4.5, "success pill label"),
    ("warn-fg", "warn", 4.5, "warning pill label"),
    ("danger-fg", "danger", 4.5, "danger pill and error text label"),
    ("info-fg", "info", 4.5, "info pill label"),
    ("neutral-fg", "neutral", 4.5, "neutral pill label"),
]


@pytest.mark.parametrize("fg, bg, minimum, description", TEXT_PAIRS)
def test_text_token_contrast_meets_wcag_aa(fg, bg, minimum, description):
    assert fg in TOKENS, f"missing --color-{fg} token"
    assert bg in TOKENS, f"missing --color-{bg} token"
    ratio = contrast(TOKENS[fg], TOKENS[bg])
    assert ratio >= minimum, (
        f"{description}: --color-{fg} on --color-{bg} is {ratio:.2f}:1, "
        f"below the {minimum}:1 minimum (WCAG 2.2 SC 1.4.3)"
    )


# ---------------------------------------------------------------------------
# Non-text boundaries: SC 1.4.11 needs 3:1 for anything required to identify a
# component. Purely decorative separators are explicitly out of scope, which is
# why `line` / `line-strong` are NOT asserted here and `line-control` is.
# ---------------------------------------------------------------------------

BOUNDARY_PAIRS = [
    ("focus", "canvas", "focus ring against the app background"),
    ("focus", "surface", "focus ring against a panel"),
    ("focus", "surface-sunken", "focus ring against a form control's own fill"),
    ("line-control", "surface", "form control boundary against the panel behind it"),
    ("line-control", "surface-sunken", "form control boundary against its own fill"),
    ("line-control", "canvas", "form control boundary against the app background"),
    ("accent", "surface", "primary button edge against a panel"),
    ("danger", "surface", "error border against a panel"),
    ("danger", "canvas", "error border against the app background"),
]


@pytest.mark.parametrize("fg, bg, description", BOUNDARY_PAIRS)
def test_boundary_token_contrast_meets_wcag_non_text(fg, bg, description):
    ratio = contrast(TOKENS[fg], TOKENS[bg])
    assert ratio >= 3.0, (
        f"{description}: --color-{fg} on --color-{bg} is {ratio:.2f}:1, "
        f"below the 3:1 minimum (WCAG 2.2 SC 1.4.11)"
    )


def test_decorative_separators_stay_below_the_component_threshold():
    """Documents the deliberate line/line-control split, so it cannot be undone.

    If these ever cross 3:1 they have stopped being quiet separators and the
    distinction the palette is built on has quietly rotted. Asserting the
    inequality keeps the design intent explicit rather than incidental.
    """
    for bg in ("canvas", "surface"):
        assert contrast(TOKENS["line"], TOKENS[bg]) < 3.0, (
            "--color-line is meant to be a decorative separator, not a component "
            "boundary; if it now clears 3:1, fold it into the control token story"
        )
    # The control token must be strictly the more visible of the two.
    assert contrast(TOKENS["line-control"], TOKENS["surface"]) > contrast(
        TOKENS["line"], TOKENS["surface"]
    )


# ---------------------------------------------------------------------------
# The token layer must actually be the source of colour
# ---------------------------------------------------------------------------

def test_token_layer_defines_the_full_palette():
    """Every colour the primitives reference must exist as a token."""
    required = {
        "canvas", "surface", "surface-raised", "surface-sunken",
        "line", "line-strong", "line-control",
        "fg", "fg-muted", "fg-subtle", "fg-inverse",
        "accent", "accent-strong", "accent-fg", "focus",
        "ok", "ok-fg", "warn", "warn-fg", "danger", "danger-fg",
        "info", "info-fg", "neutral", "neutral-fg",
    }
    missing = sorted(required - set(TOKENS))
    assert not missing, f"tokens missing from index.css: {missing}"


def test_primitives_contain_no_raw_hex_colours():
    """The primitive layer must be themeable from one place.

    A raw hex in a primitive silently defeats the token layer, so this is
    pinned rather than left to review.
    """
    source = UI.read_text(encoding="utf-8")
    raw = re.findall(r"#[0-9a-fA-F]{3,8}\b", source)
    assert not raw, f"ui.tsx must use token utilities, found raw colours: {raw}"


def test_token_layer_is_the_only_place_hex_colours_are_declared():
    """No view or component may re-introduce a hardcoded palette colour."""
    offenders: list[str] = []
    for path in sorted((ROOT / "frontend" / "src").rglob("*.tsx")):
        if path.name == "ui.tsx":
            continue
        found = re.findall(r"(?:bg|text|border|ring)-\[#[0-9a-fA-F]{3,8}\]", path.read_text(
            encoding="utf-8"))
        if found:
            offenders.append(f"{path.name}: {found}")
    assert not offenders, "hardcoded palette utilities found: " + "; ".join(offenders)


# ---------------------------------------------------------------------------
# Spread-order contract
# ---------------------------------------------------------------------------

def test_control_uses_the_control_boundary_token():
    """Form controls must use `line-control`, not the decorative `line`.

    `line` is a row rule at ~1.3:1 and is exempt from SC 1.4.11. A control
    boundary is not exempt, and the failure is invisible in review because the
    border still renders -- just too faint to identify the control.
    """
    source = UI.read_text(encoding="utf-8")
    control_block = source.split("const CONTROL =", 1)[1].split("\n\n", 1)[0]
    assert "border-line-control" in control_block, (
        "CONTROL must border with line-control so the control boundary meets "
        "SC 1.4.11, not the decorative separator token"
    )


def _strip_line_comments(source: str) -> str:
    """Drop `//` and block comments, leaving string literals intact.

    Needed because the primitives' docs discuss the very markup they are
    searched for -- the file header literally contains `<button>` inside a
    `/* */` block -- so a naive search matches prose instead of JSX.
    """
    out: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(source):
        ch = source[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < len(source):
                out.append(source[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < len(source) and source[i + 1] == "/":
            while i < len(source) and source[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < len(source) and source[i + 1] == "*":
            end = source.find("*/", i + 2)
            i = len(source) if end == -1 else end + 2
            # Keep newlines so line-relative offsets and diffs stay sane.
            out.append("\n")
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def test_primitives_spread_caller_props_before_their_own_contract():
    """`{...rest}` must precede `className`/a11y props in every primitive.

    Caught by a real browser, not by types. A view passed
    `className="w-full min-w-0 sm:w-64"` to <TextField>; because `{...rest}`
    was spread *after* `className`, the caller's className replaced the
    primitive's own classes outright and the input rendered with no border and
    no background. `tsc` is perfectly happy with that, and so was every
    source-grep test.

    The invariant: a caller may ADD presentation, never remove the primitive's
    structural and accessibility contract.
    """
    source = _strip_line_comments(UI.read_text(encoding="utf-8"))
    offenders: list[str] = []
    for primitive in ("input", "textarea", "select", "button"):
        # Each primitive element is rendered exactly once in this file.
        idx = source.index(f"<{primitive}")
        block = source[idx : idx + 1400]
        rest_at = block.find("{...rest}")
        class_at = block.find("className=")
        if rest_at == -1 or class_at == -1:
            offenders.append(
                f"<{primitive}>: could not locate {{...rest}} (at {rest_at}) "
                f"and/or className (at {class_at})"
            )
        elif rest_at > class_at:
            offenders.append(
                f"<{primitive}>: {{...rest}} at offset {rest_at} comes AFTER "
                f"className at {class_at}, so caller props can clobber the primitive"
            )
    assert not offenders, "; ".join(offenders)
