"""Frontend API-base resolution: behavioral regression for the blank-white-screen P0.

Why this file exists
--------------------
A shipped UI build rendered an entirely blank page: `#root` had zero children and
the console showed `Uncaught TypeError: r.map is not a function`.

The real chain, and why the pre-existing frontend tests could not see it:

1. `frontend/Dockerfile` declared `ARG VITE_API_URL=""`.
2. Vite inlines `import.meta.env.VITE_API_URL` as the empty STRING (not undefined).
3. `api.ts` resolved it with `?.trim() ?? "/api"`. `??` only falls back on
   null/undefined, so `API_URL` stayed `""`.
4. Every call became same-origin and prefix-less: `fetch("/runs")`.
5. nginx serves the SPA fallback for unknown paths, so `/runs` returned
   `index.html` with **HTTP 200**.
6. `request()` does `await response.json().catch(() => ({}))` and only raises on
   `!response.ok`. 200 + HTML therefore returned `{}` -- a success, not an error.
7. `setRuns({})` then rendered `{}.map(...)` -> TypeError -> uncaught -> blank page.

Steps 2-6 are runtime data flow. A source-string assertion cannot evaluate them,
which is precisely the defect class the earlier M19 static tests missed. So the
tests below EXECUTE the shipped resolution logic against real env shapes and
assert the observable outcome, instead of grepping for a literal.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
API_TS = ROOT / "frontend" / "src" / "api.ts"
UI_DOCKERFILE = ROOT / "frontend" / "Dockerfile"


# ---------------------------------------------------------------------------
# Source handling
# ---------------------------------------------------------------------------

def _strip_line_comments(source: str) -> str:
    """Remove `//` comments while leaving string literals (e.g. `http://`) intact.

    Necessary because the file documents the very tokens the static checks below
    forbid; matching inside a comment would make the assertions meaningless.
    """
    out: list[str] = []
    in_string: str | None = None
    i = 0
    while i < len(source):
        ch = source[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < len(source):
                out.append(source[i + 1])
                i += 2
                continue
            if ch == in_string:
                in_string = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            in_string = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < len(source) and source[i + 1] == "/":
            while i < len(source) and source[i] != "\n":
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _resolution_block() -> str:
    """Verbatim api.ts text for API_URL resolution + apiBase(), comments removed."""
    source = _strip_line_comments(_raw_api_source())
    start = source.index("const configuredApiUrl")
    end = source.index("export function hasApiKey")
    return source[start:end]


def _raw_api_source() -> str:
    return API_TS.read_text(encoding="utf-8")


def _to_javascript(block: str) -> str:
    """Strip the TS-only `as` annotations so Node can run the real logic."""
    out = re.sub(r"\s+as\s+string\s*\|\s*undefined", "", block)
    return re.sub(r"\s+as\s+const\b", "", out)


def _evaluate_api_base(env: dict[str, str]) -> str:
    """Run the SHIPPED resolution logic under a given VITE_* env shape."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not on PATH; cannot evaluate the bundle's API base")

    block = _to_javascript(_resolution_block())
    # `import.meta.env` is a Vite compile-time construct; substitute the exact
    # shape Vite would inline, including an empty string for an unset ARG.
    block = block.replace("import.meta.env", "__VITE_ENV__")
    payload = (
        f"const __VITE_ENV__ = {json.dumps(env)};\n"
        + block
        + "\nconsole.log(JSON.stringify(apiBase()));\n"
    )

    keep = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "APPDATA", "LOCALAPPDATA", "HOME"}
    proc = subprocess.run(
        [node, "-e", payload],
        capture_output=True,
        text=True,
        timeout=60,
        env={k: v for k, v in os.environ.items() if k in keep},
        cwd=str(ROOT),
    )
    if proc.returncode != 0:
        raise AssertionError(f"node could not evaluate apiBase(): {proc.stderr.strip()[:600]}")
    return proc.stdout.strip().strip('"')


# ---------------------------------------------------------------------------
# The regression itself
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "env, expected",
    [
        pytest.param({}, "/api", id="unset-env-falls-back-to-same-origin"),
        pytest.param({"VITE_API_URL": ""}, "/api", id="empty-arg-falls-back-not-blank"),
        pytest.param({"VITE_API_URL": "   "}, "/api", id="whitespace-arg-falls-back"),
        pytest.param({"VITE_API_URL": "/api"}, "/api", id="explicit-same-origin"),
        pytest.param({"VITE_API_URL": "/api/"}, "/api", id="trailing-slash-normalized"),
        pytest.param({"VITE_API_URL": "/api///"}, "/api", id="many-trailing-slashes"),
        pytest.param(
            {"VITE_API_URL": "https://proofops.example.com"},
            "https://proofops.example.com",
            id="explicit-split-origin-override-still-honored",
        ),
    ],
)
def test_api_base_is_never_empty(env, expected):
    """`apiBase()` must never resolve to an empty string, for ANY env shape.

    An empty base is the exact precondition for the white screen: it turns
    `/runs` into a same-origin path that nginx answers with the SPA fallback.
    """
    result = _evaluate_api_base(env)
    assert result != "", "apiBase() must never be empty (blank-white-screen precondition)"
    assert result == expected, f"apiBase() resolved to {result!r} for env {env!r}"


def test_api_base_is_used_for_request_paths_not_only_helpers():
    """`request()` must build URLs from the same API_URL constant `apiBase()` reads.

    The shipped bug hid in this seam: `apiBase()` can be correct while `request()`
    reads the raw constant. Both must resolve through one value, or the fixes
    disagree and the UI silently regresses.
    """
    source = _strip_line_comments(_raw_api_source())
    assert "${API_URL}${path}" in source, (
        "request() must build its URL from the API_URL constant that apiBase() "
        "normalizes, so the two cannot drift"
    )
    assert 'API_URL.replace(/\\/+$/, "")' in source, (
        "apiBase() must normalize the same API_URL constant used by request()"
    )


# ---------------------------------------------------------------------------
# The build must not be able to reintroduce an empty default
# ---------------------------------------------------------------------------

def test_dockerfile_api_url_arg_defaults_to_same_origin():
    """The image default must BE the correct value, not an empty string.

    Defense in depth: the code now coerces falsy -> /api, and the build default
    should also be right so the inlined bundle is correct at the source.
    """
    dockerfile = UI_DOCKERFILE.read_text(encoding="utf-8")
    match = re.search(r"^ARG\s+VITE_API_URL=(.*)$", dockerfile, re.MULTILINE)
    assert match is not None, "VITE_API_URL ARG must be declared explicitly"
    default = match.group(1).strip().strip('"').strip("'")
    assert default == "/api", (
        f"VITE_API_URL ARG defaults to {default!r}; an empty default ships a bundle "
        "that fetches prefix-less same-origin paths and blanks the whole app"
    )


def test_api_url_resolution_uses_falsy_coalescing_not_nullish():
    """Pin the specific cause: `??` on an empty string is what caused the outage.

    Deliberately redundant with the behavioral test: that one proves the outcome,
    this one names the cause so a refactor reintroducing `??` fails with a
    message explaining WHY it matters.

    Scoped to the API_URL lines only. The API key legitimately keeps `?? ""`,
    because "no key" is a real, intended state (unauthenticated demo mode) and
    not a missing default.
    """
    block = _resolution_block()
    api_url_lines = block.split("const API_KEY")[0]
    assert "??" not in api_url_lines, (
        "API base resolution must not use `??`; a Dockerfile ARG default of \"\" is an "
        "empty string, not undefined, so `??` will not fall back to /api"
    )
    assert "configuredApiUrl ? configuredApiUrl" in api_url_lines, (
        "expected a truthiness-checked fallback so empty/whitespace env values "
        "resolve to the same-origin /api default"
    )


def test_no_hardcoded_cross_origin_backend_in_bundle_source():
    """No absolute backend origin may be baked in; the UI is same-origin.

    A hardcoded `http://localhost:8000` was the original defect: cross-origin from
    the browser against an API with no CORS middleware and no OPTIONS handler.
    Comments are stripped first so the explanation of the defect is not a match.
    """
    source = _strip_line_comments(_raw_api_source())
    assert "localhost:8000" not in source, (
        "api.ts must not hardcode an absolute backend origin; use the same-origin "
        "/api prefix that nginx proxies"
    )
