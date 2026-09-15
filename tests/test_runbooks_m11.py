"""M11 runbooks: loader + hash + pin + params + seeds (host-safe).

Covers registry M11.1-M11.6 through the public loader API only:
- M11.1 schema: shipped files conform (id, pin, forbidden scope).
- M11.2 loader: load + parse-error + traversal + swap defenses.
- M11.3 hash: tampered / missing / wrong digests rejected.
- M11.4 pin: floating versions rejected at load.
- M11.5 params: shipped `string` / `integer-lo-hi` dialect enforced.
- M11.6 seeds: poisoned variants rejected + per-runbook content pins.
"""
import sys
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.runbooks import (  # noqa: E402 (M11 loader)
    content_hash,
    load_runbook,
    validate_parameters,
)

SEEDS = ["bad-deploy-rollback", "crashloop-oom", "db-pool-saturation",
         "net-dep-failover", "injection-quarantine"]
ROOT = Path(__file__).resolve().parents[1]


def _write(directory: Path, name: str, data: dict, stamped: bool = True) -> None:
    if stamped:
        data = dict(data)
        data["hash"] = content_hash(data)
    (directory / f"{name}.yaml").write_text(
        yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _seed_data(name: str) -> dict:
    return yaml.safe_load((ROOT / "runbooks" / f"{name}.yaml").read_text(encoding="utf-8"))


class TestShippedSeeds:  # M11.1 + M11.6 content
    @pytest.mark.parametrize("name", SEEDS)
    def test_seed_loads_and_binds_id(self, name):  # POSITIVE
        rb = load_runbook(name)
        assert rb.runbook_id == name
        assert rb.title.strip() == rb.title and rb.title
        assert rb.owner and rb.reviewed_at  # owner-attributed + reviewed

    @pytest.mark.parametrize("name", SEEDS)
    def test_seed_governed_shape(self, name):  # POSITIVE
        rb = load_runbook(name)
        assert rb.trigger.to_plain() and rb.scope  # trigger + env scope
        assert rb.preconditions and rb.diagnostic_steps
        assert rb.approval.to_plain() is not None
        assert rb.verification  # verification-aware
        assert rb.forbidden_actions  # forbidden-action-aware: never empty

    def test_quarantine_is_read_only(self):  # POSITIVE (M11.6)
        rb = load_runbook("injection-quarantine")
        assert set(map(str, rb.allowed_actions)) == {
            "read", "describe", "logs", "metrics", "list"}
        assert "restart_pod" in set(map(str, rb.forbidden_actions))

    def test_mutating_seeds_carry_rollback(self):  # POSITIVE (M11.6)
        for name in ("bad-deploy-rollback", "db-pool-saturation", "net-dep-failover"):
            rb = load_runbook(name)
            assert rb.rollback.to_plain().get("action")  # rollback-aware


class TestLoaderDefense:  # M11.2
    def test_unknown_id_missing_file(self):  # NEGATIVE
        with pytest.raises(FileNotFoundError):
            load_runbook("no-such-runbook")

    @pytest.mark.parametrize("bad", ["../app", "a/b", "", " bad", "bad ",
                                     "a" * 200, "rb.yaml", "*", "r;b"])
    def test_malformed_id_rejected_before_fs(self, bad, tmp_path):  # SECURITY
        (tmp_path / "sentinel.yaml").write_text("x: 1", encoding="utf-8")
        with pytest.raises(ValueError):
            load_runbook(bad, tmp_path)

    @pytest.mark.parametrize("doc", ["", "[]", "- a\n", "just text\n", "42\n"])
    def test_non_mapping_document_rejected(self, doc, tmp_path):  # NEGATIVE
        (tmp_path / "rb.yaml").write_text(doc, encoding="utf-8")
        with pytest.raises(ValueError):
            load_runbook("rb", tmp_path)

    def test_swapped_id_rejected(self, tmp_path):  # SECURITY (M11.6 poison)
        data = _seed_data("bad-deploy-rollback")  # id stays bad-deploy-rollback
        _write(tmp_path, "innocent-name", data)  # filed under a WRONG name
        with pytest.raises(ValueError, match="mismatch"):
            load_runbook("innocent-name", tmp_path)

    def test_contradictory_scope_rejected(self, tmp_path):  # SECURITY (M11.6)
        data = _seed_data("bad-deploy-rollback")
        data["forbidden_actions"] = ["rollback_deployment"]
        _write(tmp_path, "bad-deploy-rollback", data)
        with pytest.raises(ValidationError):
            load_runbook("bad-deploy-rollback", tmp_path)


class TestHashDefense:  # M11.3
    def test_tampered_content_rejected(self, tmp_path):  # SECURITY
        data = _seed_data("bad-deploy-rollback")  # keeps ORIGINAL stamped hash
        data["diagnostic_steps"] = ["do the wrong thing"]
        (tmp_path / "bad-deploy-rollback.yaml").write_text(
            yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        with pytest.raises(ValueError, match="hash mismatch"):
            load_runbook("bad-deploy-rollback", tmp_path)

    def test_missing_hash_rejected(self, tmp_path):  # SECURITY
        data = _seed_data("bad-deploy-rollback")
        del data["hash"]
        (tmp_path / "bad-deploy-rollback.yaml").write_text(
            yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        with pytest.raises(ValueError, match="hash mismatch"):
            load_runbook("bad-deploy-rollback", tmp_path)

    def test_wrong_hash_rejected(self, tmp_path):  # NEGATIVE
        data = _seed_data("bad-deploy-rollback")
        data["hash"] = "0" * 64
        (tmp_path / "bad-deploy-rollback.yaml").write_text(
            yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        with pytest.raises(ValueError, match="hash mismatch"):
            load_runbook("bad-deploy-rollback", tmp_path)


class TestVersionPin:  # M11.4
    @pytest.mark.parametrize("version", ["latest", "1.2", "v1.2.0", "^1.2.0", ""])
    def test_floating_version_rejected_at_load(self, version, tmp_path):  # NEGATIVE
        data = _seed_data("bad-deploy-rollback")
        data["version"] = version
        _write(tmp_path, "bad-deploy-rollback", data)
        with pytest.raises(ValidationError):
            load_runbook("bad-deploy-rollback", tmp_path)


class TestParameters:  # M11.5
    def test_string_param_ok(self):  # POSITIVE
        rb = load_runbook("bad-deploy-rollback")
        assert validate_parameters(rb, {"to_version": "v22"}) == {"to_version": "v22"}

    def test_integer_range_ok(self):  # POSITIVE
        rb = load_runbook("db-pool-saturation")
        assert validate_parameters(rb, {"replicas": 3}) == {"replicas": 3}

    def test_empty_schema_ok_empty_params(self):  # POSITIVE
        rb = load_runbook("injection-quarantine")
        assert validate_parameters(rb, {}) == {}

    @pytest.mark.parametrize("params", [{}, {"replicas": 3, "extra": 1},
                                        {"replicas": 0}, {"replicas": 11},
                                        {"replicas": "3"}, {"replicas": True},
                                        {"replicas": 3.0}, {"replicas": None}])
    def test_integer_param_abuse_rejected(self, params):  # NEGATIVE + SECURITY
        rb = load_runbook("db-pool-saturation")
        with pytest.raises(ValueError):
            validate_parameters(rb, params)

    @pytest.mark.parametrize("params", [{}, {"to_version": ""}, {"to_version": " v22"},
                                        {"to_version": 22}, {"to_version": None},
                                        {"to_version": "v22", "extra": "x"}])
    def test_string_param_abuse_rejected(self, params):  # NEGATIVE + SECURITY
        rb = load_runbook("bad-deploy-rollback")
        with pytest.raises(ValueError):
            validate_parameters(rb, params)

    def test_quarantine_takes_no_params(self):  # SECURITY
        rb = load_runbook("injection-quarantine")
        with pytest.raises(ValueError):
            validate_parameters(rb, {"replicas": 1})

    def test_non_mapping_params_rejected(self):  # NEGATIVE
        rb = load_runbook("bad-deploy-rollback")
        for bad in (None, "v22", [("to_version", "v22")]):
            with pytest.raises(ValueError):
                validate_parameters(rb, bad)  # type: ignore[arg-type]

    def test_unknown_type_token_rejected(self):  # SECURITY
        rb = load_runbook("bad-deploy-rollback").model_copy(
            update={"parameters_schema": {"to_version": "float"}})
        with pytest.raises(ValueError, match="unknown runbook param type"):
            validate_parameters(rb, {"to_version": "1.5"})
