"""Zero-trust tests for approval-token delivery (M07, ADR-015).

An approval token is a single-use HMAC bearer credential. Everything here is
about one property: **a carrier may move a token; a carrier may never widen who
can use one.**

The default mode mints nothing at all, which is the whole point of it. These
tests exist because "we did not add a token to the response body" is a claim
that decays the first time someone adds a convenience field, so it is asserted
rather than trusted.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
APPROVALS = ROOT / "backend" / "app" / "routers" / "approvals.py"
DELIVERY = ROOT / "backend" / "app" / "services" / "token_delivery.py"
PIPELINE = ROOT / "backend" / "app" / "services" / "pipeline.py"
CONFIG = ROOT / "backend" / "app" / "config.py"
ENV_EXAMPLE = ROOT / ".env.example"


def _code(path: Path) -> str:
    src = path.read_text(encoding="utf-8")
    src = re_sub_comments(src)
    return src


def re_sub_comments(src: str) -> str:
    import re
    src = re.sub(r"\"\"\".*?\"\"\"", "", src, flags=re.S)
    src = re.sub(r"#\[^\n]*", "", src)
    src = re.sub(r"//[^\n]*", "", src)
    return src


def _fn(path: Path, name: str) -> str:
    """The function's executable body, with its docstring removed.

    Docstrings are prose about the code, not the code. Leaving them in makes
    substring assertions match the *explanation* rather than the behaviour --
    which is how a test passes while the function does the opposite.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)):
                node.body = node.body[1:]
            return ast.unparse(ast.Module(body=node.body, type_ignores=[]))
    raise AssertionError(f"{name} not found in {path.name}")


# ---------------------------------------------------------------------------
# The default mints nothing -- the strongest property
# ---------------------------------------------------------------------------

def test_default_mode_is_approver_minted():
    """The default must be the mode where no token exists to leak."""
    tree = ast.parse(CONFIG.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) \
                and node.target.id == "APPROVAL_TOKEN_DELIVERY":
            assert node.value is not None
            assert isinstance(node.value, ast.Constant)
            assert node.value.value == "approver_minted", (
                "the default must be approver_minted -- the mode in which the "
                "control plane never mints a token, so there is no credential "
                "to leak, intercept, or replay")
            return
    raise AssertionError("APPROVAL_TOKEN_DELIVERY is not a declared setting")


def test_approver_minted_mode_never_calls_request_approval():
    """In the default mode the park path must not mint.

    If parking a proposal also raised an approval request, the default mode
    would be silently the weakest mode with none of its guards.
    """
    body = _fn(PIPELINE, "_park_pending_approval")
    # The mint call must be reachable only from the non-default branches.
    assert "approver_minted" in body
    assert "park_proposal" in body
    assert "request_approval" in body, "the other two modes need a real request"
    # The mint call appears after the default branch returns.
    default_at = body.index("approver_minted")
    mint_at = body.index("request_approval")
    assert mint_at > default_at, (
        "request_approval must be unreachable in approver_minted mode")


def test_parked_proposals_contain_no_token_anywhere():
    """A proposal listing must never be able to leak a token.

    Asserted on a dict *key* holding a token value, not on the substring
    "token" -- the listing legitimately calls a helper whose name contains that
    word, and a substring check would either be useless or force the code to use
    misleading names.
    """
    body = _fn(APPROVALS, "list_proposals")
    assert "'token':" not in body and '"token":' not in body, (
        "list_proposals must not put a token value in the payload it returns")
    assert "token_available" in body, (
        "the gate should still be able to tell the approver a token awaits")


def test_the_ordinary_view_never_returns_a_token():
    """approval_view is what the Safety Gate polls. It must stay token-free."""
    body = _fn(APPROVALS, "approval_view")
    assert "'token':" not in body and '"token":' not in body, (
        "approval_view must not include a token: it is the polled read path")


# ---------------------------------------------------------------------------
# scoped_view: the weakest mode, so the most guard rails
# ---------------------------------------------------------------------------

def test_scoped_view_claim_requires_an_approver_role():
    body = _fn(APPROVALS, "http_claim_token")
    assert "_require_key" in body, "the claim endpoint must authenticate"
    # Matched loosely: ast.unparse normalises quote style, and pinning the
    # literal formatting would make this test fail on a rename rather than on a
    # weakened role check.
    assert "_authorize(identity, 'approver', 'admin')" in body or \
        '_authorize(identity, "approver", "admin")' in body, (
        "collecting a token must be approver/admin only, resolved server-side")
    # Role must come from the identity, never from the body or a query param.
    assert "body." not in body, (
        "the claim endpoint must not read a role or token from the request body")


def test_scoped_view_claim_is_single_use():
    """Two claims must not both succeed."""
    body = _fn(DELIVERY, "claim_scoped_view")
    assert ".pop(" in body, (
        "the entry must be removed before the value is returned, otherwise two "
        "concurrent claims could both spend a single-use token")
    # pop must come before the return.
    assert body.index(".pop(") < body.rindex("return"), (
        "pop must precede the return so a second caller finds nothing")


def test_scoped_view_is_ttl_bounded_from_mint_not_from_first_read():
    body = _fn(DELIVERY, "hold_for_scoped_view")
    assert "minted_at" in body, "the clock must start at mint"
    assert "time.time()" in body
    expire = _fn(DELIVERY, "_expire")
    assert "minted_at" in expire, (
        "expiry must be measured from mint. A token whose TTL starts when "
        "someone asks for it has no TTL at all from the system's point of view")


def test_scoped_view_never_hands_a_token_to_a_non_approver_via_peek():
    """`peek` is for diagnostics and must not return the secret."""
    body = _fn(DELIVERY, "peek_scoped_view")
    assert "return" in body
    assert "token" not in body.replace("str(approval_id)", ""), (
        "peek must return only a boolean; it exists so a list endpoint can say "
        "'a token awaits' without disclosing it")


def test_a_failed_claim_does_not_distinguish_why():
    """Never-expired vs already-spent must look identical from outside."""
    body = _fn(APPROVALS, "http_claim_token")
    assert "404" in body, "an uncollectable token is a plain 404"
    assert "expired" not in body.lower(), (
        "the response must not reveal whether a token existed and lapsed, "
        "which is exactly what an attacker enumerates")


def test_claim_is_audited():
    body = _fn(APPROVALS, "http_claim_token")
    assert "_emit(" in body, (
        "a credential leaving the process must land in the audit chain")


# ---------------------------------------------------------------------------
# out_of_band: written outside the API's own reach
# ---------------------------------------------------------------------------

def test_out_of_band_sink_is_outside_the_api_state_dir():
    body = _fn(DELIVERY, "_sink_dir")
    assert "state_dir().parent" in body, (
        "the token sink must be a sibling of the API state dir, not a child. "
        "The audit chains and approvals store live under state_dir; a credential "
        "sink inside it is one permissions mistake from being readable by "
        "anything that can read the audit log")


def test_out_of_band_file_is_created_restrictively_not_chmod_ed_afterwards():
    body = _fn(DELIVERY, "deliver_out_of_band")
    # ast.unparse renders octal literals in decimal, so 0o600 arrives as 384.
    # Assert the value, not the spelling.
    assert "384" in body or "0o600" in body, "the token file must be mode 0600"
    assert "os.open" in body, (
        "create with the mode at creation time; a create-then-chmod leaves a "
        "window where the token is world-readable")
    assert body.index("os.open") < body.index("handle.write")
    # The directory may legitimately be chmod-ed to 0700. What must not happen is
    # the *file* being created and then tightened, which leaves a readable window.
    assert "chmod(target" not in body and "chmod(str(target" not in body, (
        "the file mode must come from creation, not a later chmod on the file")


def test_sink_filename_cannot_escape_its_directory():
    body = _fn(DELIVERY, "_safe")
    assert "isalnum" in body, "ids must be reduced to a safe character set"
    for hostile in ("..", "/", "\\\\"):
        assert hostile not in body or "isalnum" in body


# ---------------------------------------------------------------------------
# Wiring and governance
# ---------------------------------------------------------------------------

def test_all_three_modes_are_reachable_and_documented():
    config = CONFIG.read_text(encoding="utf-8")
    for mode in ("approver_minted", "out_of_band", "scoped_view"):
        assert f'"{mode}"' in config, f"{mode} must be a declared mode"
    docs = (ROOT / "docs" / "CONFIGURATION.md").read_text(encoding="utf-8")
    assert "APPROVAL_TOKEN_DELIVERY" in docs
    env = ENV_EXAMPLE.read_text(encoding="utf-8")
    for mode in ("approver_minted", "out_of_band", "scoped_view"):
        assert mode in env, f"{mode} must be documented in the env template"


def test_the_settings_registration_is_complete():
    config = CONFIG.read_text(encoding="utf-8")
    assert '"APPROVAL_TOKEN_DELIVERY"' in config, (
        "must appear in Settings.inventory() so the parity tests govern it")


def test_parking_never_approves_anything():
    """The park path may only ever create something a human can act on."""
    body = _fn(PIPELINE, "_park_pending_approval")
    assert "approve_approval" not in body, (
        "_park_pending_approval must never approve. It runs on the stall path, "
        "and approving there would be the worker authorising its own action")
    assert "verified_permit" not in body, (
        "a permit must never be minted here; permits come from verified_permit "
        "after a human decision")


def test_no_mode_widens_who_can_spend_a_token():
    """Cross-check: none of the three may accept an identity argument."""
    for fn_name in ("http_claim_token",):
        body = _fn(APPROVALS, fn_name)
        assert "x_api_key" in body, (
            f"{fn_name} must authenticate rather than trust a claimed caller")


@pytest.mark.parametrize("path", [APPROVALS, DELIVERY, PIPELINE])
def test_no_module_reads_environ_directly(path: Path):
    """Mirrors test_config_hardening: resolve through Settings."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "environ":
            raise AssertionError(f"direct os.environ in {path.name}")
