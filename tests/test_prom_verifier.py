"""Tests for Independent Live Prometheus PromQL Telemetry Verifier."""
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.contracts.enums import Verdict
from app.contracts.verification import VerificationResult
from app.services.prom_verifier import PrometheusVerifier


@pytest.mark.asyncio
async def test_prom_verifier_offline_status():
    pv = PrometheusVerifier(base_url="http://127.0.0.1:59999")
    status = await pv.status()
    assert status["connected"] is False
    assert status["tier"] == "standby-sandbox"
    assert status["url"] == "http://127.0.0.1:59999"


@pytest.mark.asyncio
async def test_prom_verifier_offline_fallback():
    pv = PrometheusVerifier(base_url="http://127.0.0.1:59999")
    before = {"error_rate": 0.18, "replicas": 3, "pods_ready": True, "crashloop": False}
    after = {"error_rate": 0.005, "replicas": 3, "pods_ready": True, "crashloop": False}
    slo = {"error_rate_below": 0.01}

    result = await pv.verify(
        execution_id="exec-prom-01",
        service="checkout",
        before_state=before,
        after_state=after,
        slo=slo,
        command_succeeded=True,
    )
    assert isinstance(result, VerificationResult)
    assert result.verdict == Verdict.RESOLVED
    assert result.checks["error_rate_below_slo"] is True
    assert result.checks["pods_ready"] is True


@pytest.mark.asyncio
async def test_prom_verifier_live_resolved():
    pv = PrometheusVerifier()
    with patch.object(pv, "is_available", new_callable=AsyncMock) as mock_avail, \
         patch.object(pv, "query_promql", new_callable=AsyncMock) as mock_query:
        mock_avail.return_value = True

        async def _fake_promql(q: str):
            if "5.." in q:
                return 0.003  # Low error rate
            if "replicas_available" in q:
                return 3.0   # Healthy pods
            if "OOMKilled" in q:
                return 0.0   # No OOM
            return None

        mock_query.side_effect = _fake_promql

        before = {"error_rate": 0.15}
        after = {"error_rate": 0.15}  # Stale state should be superseded by live PromQL!
        slo = {"error_rate_below": 0.01}

        result = await pv.verify(
            execution_id="exec-prom-02",
            service="checkout",
            before_state=before,
            after_state=after,
            slo=slo,
            command_succeeded=True,
        )
        assert result.verdict == Verdict.RESOLVED
        assert "live-promql err=0.0030" in result.detail
        assert result.checks["error_rate_below_slo"] is True
        assert result.checks["no_crashloop"] is True


@pytest.mark.asyncio
async def test_prom_verifier_exit_0_bad_slo_never_resolves():
    """Enforce the non-negotiable invariant: EXIT 0 != RESOLVED."""
    pv = PrometheusVerifier()
    with patch.object(pv, "is_available", new_callable=AsyncMock) as mock_avail, \
         patch.object(pv, "query_promql", new_callable=AsyncMock) as mock_query:
        mock_avail.return_value = True

        async def _fake_promql(q: str):
            if "5.." in q:
                return 0.12  # High error rate (breaches SLO of 0.01)
            if "replicas_available" in q:
                return 3.0
            if "OOMKilled" in q:
                return 0.0
            return None

        mock_query.side_effect = _fake_promql

        before = {"error_rate": 0.18}
        after = {"error_rate": 0.12}
        slo = {"error_rate_below": 0.01}

        # Command exited 0 (succeeded), but SLO is violated!
        result = await pv.verify(
            execution_id="exec-prom-03",
            service="checkout",
            before_state=before,
            after_state=after,
            slo=slo,
            command_succeeded=True,
        )
        assert result.verdict != Verdict.RESOLVED
        assert result.verdict == Verdict.ROLLBACK_REQUIRED
        assert result.checks["error_rate_below_slo"] is False


def test_prom_verifier_sync_wrapper():
    pv = PrometheusVerifier(base_url="http://127.0.0.1:59999")
    before = {"error_rate": 0.18, "replicas": 3, "pods_ready": True, "crashloop": False}
    after = {"error_rate": 0.005, "replicas": 3, "pods_ready": True, "crashloop": False}
    slo = {"error_rate_below": 0.01}

    result = pv.verify_sync(
        execution_id="exec-prom-04",
        service="checkout",
        before_state=before,
        after_state=after,
        slo=slo,
        command_succeeded=True,
    )
    assert isinstance(result, VerificationResult)
    assert result.verdict == Verdict.RESOLVED
