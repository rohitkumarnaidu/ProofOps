from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "frontend" / "src"


def source(relative: str) -> str:
    return (UI / relative).read_text(encoding="utf-8")


def test_shell_has_skip_link_main_landmark_and_route_focus() -> None:
    app = source("App.tsx")
    index = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    assert 'href="#main-content"' in app
    assert "Skip to main content" in app
    assert 'id="main-content"' in app
    assert "<main" in app
    assert 'querySelector<HTMLElement>("[data-page-heading]")' in app
    assert "?.focus()" in app
    assert '<html lang="en">' in index


def test_primary_navigation_is_named_and_marks_current_page() -> None:
    app = source("App.tsx")
    assert 'aria-label="Primary"' in app
    assert 'aria-current={active ? "page" : undefined}' in app
    assert 'location.pathname === "/" ? "page" : undefined' in app
    assert 'role="link"' in app
    assert 'aria-disabled="true"' in app


def test_every_operator_view_has_a_focusable_page_heading() -> None:
    for name in (
        "CommandCenter.tsx",
        "IncidentDetail.tsx",
        "SafetyGate.tsx",
        "ExecutionView.tsx",
        "RCAView.tsx",
    ):
        view = source(f"views/{name}")
        assert "data-page-heading" in view
        assert "tabIndex={-1}" in view
        assert "<h1" in view


def test_keyboard_focus_and_reduced_motion_are_preserved() -> None:
    css = source("index.css")
    assert ":focus-visible" in css
    assert "outline: 3px solid" in css
    assert "outline-offset: 3px" in css
    assert "scroll-margin-block" in css
    assert "@media (prefers-reduced-motion: reduce)" in css
    assert "animation-duration: 0.01ms !important" in css
    assert "transition-duration: 0.01ms !important" in css
    assert "outline: none" not in css


def test_interactive_targets_and_skip_link_have_source_basics() -> None:
    css = source("index.css")
    assert ".skip-link" in css
    assert ".skip-link:focus" in css
    assert "min-height: 2rem" in css
    assert 'position: "fixed"' not in css
    assert "position: fixed" in css


def test_errors_and_stream_updates_are_announced() -> None:
    for name in (
        "CommandCenter.tsx",
        "IncidentDetail.tsx",
        "SafetyGate.tsx",
        "ExecutionView.tsx",
        "RCAView.tsx",
    ):
        view = source(f"views/{name}")
        assert 'role="alert"' in view
    for name in (
        "IncidentDetail.tsx",
        "SafetyGate.tsx",
        "ExecutionView.tsx",
        "RCAView.tsx",
    ):
        view = source(f"views/{name}")
        assert 'aria-live="polite"' in view
        assert "Event stream:" in view


def test_form_controls_have_programmatic_labels() -> None:
    app = source("App.tsx")
    command = source("views/CommandCenter.tsx")
    gate = source("views/SafetyGate.tsx")
    assert 'htmlFor="current-incident"' in app
    assert 'htmlFor="new-incident"' in command
    assert 'htmlFor="action-json"' in gate
    assert 'htmlFor="approval-token"' in gate
    assert 'aria-describedby="action-json-help"' in gate


def test_tables_have_captions_scopes_and_overflow_containers() -> None:
    for name in ("views/CommandCenter.tsx", "components/StateDiff.tsx"):
        view = source(name)
        assert "<table" in view
        assert "<caption" in view
        assert view.count('scope="col"') >= 3
        assert "overflow-x-auto" in view


def test_hashes_tokens_and_wide_values_wrap() -> None:
    gate = source("views/SafetyGate.tsx")
    rca = source("views/RCAView.tsx")
    detail = source("views/IncidentDetail.tsx")
    diff = source("components/StateDiff.tsx")
    assert "break-all font-mono" in gate
    assert "Approval token (page state only; lost on reload)" in gate
    assert "break-all" in rca
    assert "break-all" in detail
    assert "max-w-80 break-all" in diff


def test_no_icon_only_controls_are_introduced() -> None:
    source_files = list(UI.rglob("*.tsx"))
    assert all("<svg" not in path.read_text(encoding="utf-8") for path in source_files)
    for path in source_files:
        text = path.read_text(encoding="utf-8")
        assert "aria-label=\"\"" not in text
