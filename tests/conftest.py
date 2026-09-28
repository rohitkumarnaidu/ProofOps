"""Test-suite environment, so a green run means something.

`get_settings()` is called at import time by two modules -- the Kubernetes
executor and the Prometheus verifier -- and `APPROVAL_SECRET`,
`POSTGRES_PASSWORD` and `PROOFOPS_API_KEY` are all required with no defaults.
A bare `pytest tests/` therefore died during collection with:

    app.config.ConfigurationError: APPROVAL_SECRET: invalid value <REDACTED>;
    PROOFOPS_API_KEY: ...; POSTGRES_PASSWORD: ...

before a single test ran, on any machine without a populated `.env`.

That is worse than a missing setup step, for two reasons. On CI there is no
`.env` (correctly gitignored) and nothing exported the values, so the unit job
had been red for runs on end, and the red was blamed on the code. On a developer
machine the suite was green only because the developer's own `.env` happened to
be loaded, which made a green local run partly a measurement of that file rather
than of the tree. A test result that depends on untracked local state is not a
test result.

So the values are pinned here, once, for every run. `os.environ` is set at
import time, which is before pytest collects any test module, and pydantic
prefers the environment over `env_file`, so these win over a developer's `.env`
without needing to touch or read it. Nothing is printed and nothing is secret:
these are literals for tests, and `scripts/secret_scan.py` covers tracked files.

Tests that exercise fail-closed configuration are unaffected. They call
`monkeypatch.delenv(...)` for these names and set their own values, and
monkeypatch restores the process state afterwards, so the values below are back
in place for the next test.
"""
from __future__ import annotations

import os

# Long enough to clear the >=16 character rule and free of any marker the
# placeholder check rejects, so a test that flips APP_ENV=production still gets
# a value that is deliberately its own to judge.
_TEST_ENV = {
    "APPROVAL_SECRET": "test-approval-secret-32-chars-abcdef",
    "POSTGRES_PASSWORD": "test-db-password-not-a-real-secret",
    "PROOFOPS_API_KEY": "test-operator-key-not-a-real-secret",
    # Keep the suite on the deterministic path and off any developer's real
    # configuration, so a run does not change shape with the machine.
    "APP_ENV": "development",
    "EXECUTOR": "mock",
    "DEBUG": "false",
    # No credential, so provider honesty tests exercise the OFFLINE branch and
    # a developer's real Lyzr key cannot change a test outcome.
    "LYZR_API_KEY": "",
}

for _name, _value in _TEST_ENV.items():
    os.environ[_name] = _value
