"""M00.7 secret-scanner definition tests (host-safe UNIT + SECURITY).

Proves the scanner itself is trustworthy: live shapes fail (incl. the generic
leaked-key shape that closes the interim-audit P2), fixtures/prose do not,
template/workflow hygiene fires, and findings never echo values.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import secret_scan as scanner  # noqa: E402


class TestLivePatterns:
    def test_generic_leaked_key_fails(self):  # SECURITY
        # Real leaked key: sk- + 48 alphanumerics, no hyphens.
        leaked = "sk-" + "A" * 48
        findings = scanner._scan_live_patterns(
            Path("x.py"), f"KEY={leaked}")
        assert any("openai-generic-key" in f for f in findings), findings

    def test_live_and_proj_shapes_fail(self):  # SECURITY
        # Built dynamically so this file itself stays scanner-clean (the
        # scanner scans tracked test files too): no literal live shape in
        # source, only at runtime.
        for shape, name in [
            ("sk-" + "live-abcdef12345678", "openai-live-key"),
            ("sk-" + "proj-abcdef12345678", "openai-proj-key"),
            ("AKIA" + "A" * 16, "aws-access-key"),
            ("ghp_" + "A" * 36, "github-token"),
            ("xox" + "b-1234567890ab", "slack-token"),
        ]:
            findings = scanner._scan_live_patterns(
                Path("x.py"), f"value={shape}")
            assert any(name in f for f in findings), (shape, findings)

    def test_hyphenated_prose_does_not_trip(self):  # UNIT (negative)
        # Research prose like `task-with-...` contains `sk-with-...` with
        # hyphens: the generic pattern requires alphanumerics only, so prose
        # stays clean (the interim-audit P2 fix without false positives).
        prose = "you-know-a-20-step-ai-agent-task-with-95-accuracy-at-each-step"
        assert scanner._scan_live_patterns(Path("doc.md"), prose) == []

    def test_fine_grained_pat_and_xoxe_fail(self):  # SECURITY
        # LACK-4: fine-grained PATs and extended Slack types must fail.
        # Dynamic construction keeps this file scanner-clean.
        for shape, name in [
            ("github_pat_" + "a" * 22, "github-fine-grained-pat"),
            ("xox" + "e-1234567890ab", "slack-token"),
            ("xox" + "o-1234567890ab", "slack-token"),
        ]:
            findings = scanner._scan_live_patterns(
                Path("x.py"), "tok=" + shape)
            assert any(name in f for f in findings), (shape, findings)

    def test_fixtures_do_not_trip(self):  # UNIT (negative)
        # Hyphenated/short fixtures are documentation, not live keys.
        for fixture in [
            "sk-FAKE-planted-secret-0123456789abcdef",
            "sk-fakeKey12345678",
            "skadden.com",
        ]:
            assert scanner._scan_live_patterns(
                Path("t.py"), fixture) == [], fixture

    def test_findings_are_redacted(self):  # SECURITY
        leaked = "sk-" + "B" * 48
        findings = scanner._scan_live_patterns(Path("x.py"), leaked)
        assert findings and leaked not in " ".join(findings)


class TestPemBlocks:
    def test_real_block_fails(self):  # SECURITY
        # Built dynamically so this file itself stays scanner-clean: no
        # literal BEGIN..END real block in source, only at runtime.
        begin = "-----BEGIN " + "RSA PRIVATE KEY-----"
        end = "-----END " + "RSA PRIVATE KEY-----"
        block = (begin + "\n"
                 + "MIIEpAIBAAKCAQEA7b2m3n4p5q6r7s8t9u0v1w2x3y4z5\n"
                 + end)
        assert scanner._scan_pem_blocks("k.pem", block) != []

    def test_pgp_block_fails(self):  # SECURITY
        # LACK-4: PGP armor must fail like PEM. Dynamic, stays file-clean.
        begin = "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----"
        end = "-----END " + "PGP PRIVATE KEY BLOCK-----"
        block = begin + "\nMIIEpic\n" + end
        assert scanner._scan_pem_blocks("k.asc", block) != []

    def test_fixture_block_passes(self):  # UNIT (negative)
        block = ("-----BEGIN RSA PRIVATE KEY-----\n"
                 "MIIFakeKeyMaterial hunter2-fake\n"
                 "-----END RSA PRIVATE KEY-----")
        assert scanner._scan_pem_blocks("t.py", block) == []

    def test_regex_definition_passes(self):  # UNIT (negative)
        src = 're.compile(r"-----BEGIN RSA PRIVATE KEY-----")'
        assert scanner._scan_pem_blocks("logging_setup.py", src) == []


class TestTemplateAndWorkflows:
    def test_template_clean_tree_passes(self):  # UNIT
        assert scanner._check_template(ROOT) == []

    def test_template_missing_key_fails(self, tmp_path):  # UNIT (negative)
        (tmp_path / ".env.example").write_text(
            "APPROVAL_SECRET=change-me-x\n", encoding="utf-8")
        findings = scanner._check_template(tmp_path)
        assert any("LYZR_API_KEY" in f for f in findings), findings

    def test_workflow_clean_tree_passes(self):  # UNIT
        assert scanner._check_workflows(ROOT) == []

    def test_workflow_unsafe_compose_fails(self, tmp_path):  # SECURITY
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text(
            "run: docker compose config\n", encoding="utf-8")
        findings = scanner._check_workflows(tmp_path)
        assert any("compose-config-unsafe" in f for f in findings), findings

    def test_workflow_comment_does_not_trip(self, tmp_path):  # UNIT
        # Comments document the ban; only executable code can leak.
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text(
            "# NEVER runs plain compose config\nrun: echo ok\n",
            encoding="utf-8")
        assert scanner._check_workflows(tmp_path) == []
