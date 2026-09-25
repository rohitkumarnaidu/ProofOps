"""The frontend typecheck gate must be `tsc -b`, not `tsc --noEmit`.

Found while refactoring the views: `npx tsc --noEmit` reported a clean exit 0
across the entire design-system change, and it would have kept doing so
indefinitely. `frontend/tsconfig.json` is solution-style -- it carries
`"files": []` and a list of project references and no `include` -- so
`--noEmit` compiles nothing at all. It is a green light wired to no bulb.

The real check is `tsc -b`, which walks the project references and compiles
`tsconfig.app.json` (the config that actually has `"include": ["src"]`).
`npm run build` already used `tsc -b`, so the container image build was never
at risk; the defect was in the ad-hoc verification command, which is precisely
the kind of gate that reports success without testing anything.

These tests pin the arrangement so the distinction cannot be lost again, and
record WHY the solution-style root config exists rather than deleting it.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"


def _load_jsonc(path: Path) -> dict:
    """Load a tsconfig.

    The frontend tsconfigs are JSONC -- they carry `/* Bundler mode */` style
    comments, which is legal for tsc but not for `json.loads`. Comments are
    stripped here rather than removing them from the configs, because the
    annotations are the only thing explaining what each flag group is for.
    """
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"^\s*//.*$", "", text, flags=re.MULTILINE)
    return json.loads(text)


def test_root_tsconfig_is_solution_style() -> None:
    """Document the trap: the root config compiles no sources by itself.

    If this ever stops being true, `--noEmit` becomes meaningful again and the
    comment below becomes misleading. Re-read before changing the assertion.
    """
    config = _load_jsonc(FRONTEND / "tsconfig.json")
    assert config.get("files") == [], (
        "frontend/tsconfig.json is expected to be solution-style with an empty "
        "`files` array; that is WHY `tsc --noEmit` typechecks nothing here"
    )
    assert config.get("references"), (
        "the root config is expected to reference the app/node project configs"
    )
    assert "include" not in config, (
        "if the root config gains an `include`, `tsc --noEmit` would start "
        "compiling sources and this file's guidance needs revisiting"
    )


def test_app_config_is_the_one_that_includes_sources() -> None:
    app = _load_jsonc(FRONTEND / "tsconfig.app.json")
    assert app.get("include") == ["src"], (
        "tsconfig.app.json is the config that must include src; it is the "
        "project `tsc -b` actually compiles"
    )
    # Strictness was absent here, so the app was type-checked in the permissive
    # default mode. Added in this pass; the tree was already clean under it.
    assert app["compilerOptions"].get("strict") is True, (
        "the frontend must be type-checked under strict mode; without it, "
        "implicit any and unchecked null flow straight through the UI"
    )
    assert app["compilerOptions"].get("noUnusedLocals") is True


def test_build_script_typechecks_with_project_references() -> None:
    """The image build must typecheck for real.

    `npm run build` is what the Dockerfile runs, so this is the gate that
    actually protects the shipped bundle. If it drops `tsc -b`, a type error
    reaches production with nothing complaining.
    """
    manifest = json.loads((FRONTEND / "package.json").read_text(encoding="utf-8"))
    build = manifest["scripts"]["build"]
    assert "tsc -b" in build, (
        f"frontend build script is {build!r}; it must run `tsc -b` so the project "
        "graph is compiled, not just bundle"
    )
    assert "vite build" in build


def test_lint_script_covers_src() -> None:
    manifest = json.loads((FRONTEND / "package.json").read_text(encoding="utf-8"))
    assert "oxlint" in manifest["scripts"]["lint"]


# Matches an actual command invocation, not prose that merely names the flag.
# A docstring saying "invisible to `tsc --noEmit`" documents the trap and must
# not be flagged by the guard against walking into it, so only command-prefixed
# forms count: that is how the mistake is actually made.
_INVOCATION = re.compile(r"(?:npx|npm\s+run|yarn|pnpm|bunx)\s+tsc\s+--noEmit")


def test_no_vacuous_noemit_invocation_is_committed_as_a_gate() -> None:
    """Guard against a test or script baking in the check that checks nothing.

    This file excludes itself: it necessarily contains the flag string in order
    to search for it, and documenting a trap is not walking into it.
    """
    self_name = Path(__file__).name
    offenders: list[str] = []
    for path in list((ROOT / "tests").glob("*.py")) + list((ROOT / "scripts").glob("*.py")):
        if path.name == self_name:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if _INVOCATION.search(text):
            offenders.append(path.name)
    assert not offenders, (
        "these files invoke `tsc --noEmit`, which typechecks nothing in this repo "
        f"(solution-style root tsconfig); use `tsc -b`: {offenders}"
    )
