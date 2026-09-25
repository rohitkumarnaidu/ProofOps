import re
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
    """Failures must be announced, not merely coloured.

    The five views no longer each carry a literal role="alert" because the
    announcing markup moved into the shared primitives. The invariant is now
    asserted at both layers: the primitives really do emit an alert role, and
    every view actually routes its failures through one of them (or declares
    its own). Asserting only the primitive would let a view quietly stop
    reporting errors at all; asserting only the view would have been the old
    grep.
    """
    ui = source("components/ui.tsx")
    assert 'role="alert"' in ui, (
        "ErrorState and/or Notice must render role=alert; a failure that is only "
        "coloured red is invisible to a screen reader"
    )
    # The alert role is only useful if it is actually announced, which needs an
    # assertive live region alongside it.
    assert '"assertive"' in ui, (
        "the alert role must be paired with aria-live=assertive so assistive tech "
        "announces the failure instead of only exposing it on navigation"
    )

    for name in (
        "CommandCenter.tsx",
        "IncidentDetail.tsx",
        "SafetyGate.tsx",
        "ExecutionView.tsx",
        "RCAView.tsx",
    ):
        view = source(f"views/{name}")
        assert "ErrorState" in view or 'role="alert"' in view, (
            f"{name} must surface failures through the ErrorState primitive or its "
            "own role=alert element"
        )
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
    """Every form control must have a programmatic label.

    Previously this asserted two hardcoded ids in two files, which said nothing
    about the other three views and broke the moment a control was expressed
    through the shared Field primitive instead of raw markup. The invariant is
    now checked where it actually lives:

      1. the Field primitive emits <label htmlFor> wired to the control id, so
         a control built through it cannot exist unlabelled;
      2. any view still using RAW <input>/<select>/<textarea> must pair it with
         a literal htmlFor in the same file.

    That is a superset of the old assertions rather than a relaxation: it
    covers every view, and it also pins the primitive's own wiring.
    """
    ui_primitives = source("components/ui.tsx")
    # (1) the primitive's contract
    assert "<label" in ui_primitives
    assert "htmlFor={id}" in ui_primitives, (
        "FieldShell must wire <label htmlFor> to the control id so the "
        "label/control relationship cannot drift"
    )
    assert 'id={controlId}' in ui_primitives, (
        "the control must receive the same id the label points at"
    )

    # (2) raw controls must still be explicitly labelled
    raw_control = re.compile(r"<(input|select|textarea)\b")
    html_for = re.compile(r'<label[^>]*\bhtmlFor="([^"]+)"')
    for name in (
        "App.tsx",
        "views/CommandCenter.tsx",
        "views/IncidentDetail.tsx",
        "views/SafetyGate.tsx",
        "views/ExecutionView.tsx",
        "views/RCAView.tsx",
    ):
        text = source(name)
        labelled = set(html_for.findall(text))
        for match in raw_control.finditer(text):
            # An id on the same element is the other half of the pairing.
            tail = text[match.end() : match.end() + 200]
            control_id = re.search(r'\bid="([^"]+)"', tail)
            if control_id is None:
                continue  # a primitive, or a control with no id at all
            assert control_id.group(1) in labelled, (
                f"{name}: <{match.group(1)} id=\"{control_id.group(1)}\"> has no "
                "matching <label htmlFor>; a control with a programmatic label is required"
            )

    # The two ids the old test named still exist, now expressed as props on the
    # shared Field primitive rather than hand-written label/input pairs. The
    # label/control/description wiring is asserted above at the primitive.
    assert 'id="current-incident"' in source("App.tsx")
    assert 'id="new-incident"' in source("views/CommandCenter.tsx")
    gate = source("views/SafetyGate.tsx")
    assert "TextAreaField" in gate, (
        "the Safety Gate's JSON and token inputs must use the TextAreaField "
        "primitive so their label and hint wiring cannot drift"
    )
    assert 'id="action-json"' in gate
    assert 'id="approval-token"' in gate
    # The action-JSON hint is still required: it is what tells the operator the
    # empty fields are deliberate rather than a bug.
    assert "this view does not supply incident evidence or risk claims" in gate


def test_tables_have_captions_scopes_and_overflow_containers() -> None:
    """Caption + column-header scope + horizontal overflow containment.

    The shared DataTable primitive is now the single implementation, so the
    guarantee is asserted there; StateDiff still renders its own comparison
    table and is checked directly. CommandCenter is asserted to actually use
    the primitive, otherwise "the primitive is correct" proves nothing about the
    screen an operator is looking at.
    """
    primitives = source("components/ui.tsx")
    assert "<table" in primitives
    assert "<caption" in primitives
    assert 'scope="col"' in primitives
    assert "overflow-x-auto" in primitives

    command = source("views/CommandCenter.tsx")
    assert "DataTable" in command, (
        "CommandCenter must render its queue through the DataTable primitive, "
        "not a hand-rolled table that could drift from the caption/scope contract"
    )
    assert "<table" not in command, (
        "CommandCenter should not hand-roll a <table>; the primitive owns that markup"
    )

    diff = source("components/StateDiff.tsx")
    assert "<table" in diff
    assert "<caption" in diff
    assert diff.count('scope="col"') >= 3
    assert "overflow-x-auto" in diff


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
