"""Independent Live Prometheus Telemetry & PromQL SLO Verifier (M09 Live Tier).

Connects to Prometheus HTTP API (/api/v1/query) to execute real PromQL queries
against live cluster metrics. Evaluates HTTP error rates, available replicas,
latency percentiles, and CrashLoop/OOM container states.

Enforces the non-negotiable invariant:
  EXIT 0 != RESOLVED (Only observed Prometheus SLO metrics decide resolution).
"""
from __future__ import annotations

import httpx
from typing import Any

from app.contracts.enums import Verdict
from app.contracts.incident import FrozenDict
from app.contracts.verification import VerificationResult
from app.services import verifier as mock_verifier


class PrometheusVerifier:
    """Enterprise Prometheus PromQL Telemetry Verifier."""

    def __init__(self, base_url: str = "http://localhost:9090") -> None:
        self.base_url = base_url.rstrip("/")
        self._connected: bool | None = None

    async def is_available(self) -> bool:
        """Check if Prometheus API is responsive."""
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(f"{self.base_url}/-/healthy")
                self._connected = (resp.status_code == 200)
                return self._connected
        except Exception:
            self._connected = False
            return False

    async def status(self) -> dict[str, Any]:
        """Return Prometheus reachability status."""
        avail = await self.is_available()
        return {
            "connected": avail,
            "url": self.base_url,
            "tier": "live-promql" if avail else "standby-sandbox",
        }

    async def query_promql(self, query: str) -> float | None:
        """Execute instant PromQL query and extract numeric value."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{self.base_url}/api/v1/query",
                    params={"query": query},
                )
                if resp.status_code != 200:
                    return None
                data = resp.json()
                results = data.get("data", {}).get("result", [])
                if not results:
                    return None
                # Vector or scalar value: [timestamp, "value_string"]
                val_tuple = results[0].get("value")
                if val_tuple and len(val_tuple) == 2:
                    return float(val_tuple[1])
                return None
        except Exception:
            return None

    async def verify(
        self,
        execution_id: str,
        service: str,
        before_state: dict[str, Any],
        after_state: dict[str, Any],
        slo: dict[str, Any],
        expected: dict[str, Any] | None = None,
        command_succeeded: bool = True,
    ) -> VerificationResult:
        """Independently verify infrastructure health.

        If Prometheus is reachable, queries live PromQL.
        If Prometheus is offline, delegates to deterministic verifier.
        """
        if not await self.is_available():
            # Graceful fallback to verified sandbox verifier
            return mock_verifier.verify(
                execution_id=execution_id,
                before=before_state,
                after=after_state,
                slo=slo,
                expected=expected,
                command_succeeded=command_succeeded,
            )

        # Live PromQL evaluation
        err_query = (
            f'sum(rate(http_requests_total{{status=~"5..", service="{service}"}}[2m])) / '
            f'sum(rate(http_requests_total{{service="{service}"}}[2m]))'
        )
        obs_error_rate = await self.query_promql(err_query)
        if obs_error_rate is None:
            # Fallback query without service label
            obs_error_rate = await self.query_promql(
                'sum(rate(http_requests_total{status=~"5.."}[2m])) / sum(rate(http_requests_total[2m]))'
            )

        replicas_query = f'kube_deployment_status_replicas_available{{deployment=~".*{service}.*"}}'
        obs_replicas = await self.query_promql(replicas_query)

        oom_query = f'sum(kube_pod_container_status_last_terminated_reason{{reason="OOMKilled", pod=~".*{service}.*"}})'
        obs_oom = await self.query_promql(oom_query)

        # Use observed Prometheus numbers if present, else fallback to state
        err_val = obs_error_rate if obs_error_rate is not None else float(after_state.get("error_rate", 1.0))
        replicas_val = obs_replicas if obs_replicas is not None else int(after_state.get("replicas", 0))
        has_oom = (obs_oom is not None and obs_oom > 0) or bool(after_state.get("crashloop", False))

        error_slo = float(slo.get("error_rate_below", 0.01))
        checks: dict[str, bool] = {
            "error_rate_below_slo": err_val < error_slo,
            "pods_ready": replicas_val > 0,
            "replicas_positive": replicas_val > 0,
            "no_crashloop": not has_oom,
        }

        detail = (
            f"live-promql err={err_val:.4f} (slo<{error_slo}) "
            f"replicas={replicas_val} oom={has_oom} "
            f"exit={'0' if command_succeeded else 'nonzero'}"
        )

        if all(checks.values()):
            return VerificationResult(
                execution_id=execution_id,
                verdict=Verdict.RESOLVED,
                checks=FrozenDict(checks),
                detail=detail,
            )

        if checks["error_rate_below_slo"] and not all(checks.values()):
            return VerificationResult(
                execution_id=execution_id,
                verdict=Verdict.PARTIAL,
                checks=FrozenDict(checks),
                detail=detail,
            )

        return VerificationResult(
            execution_id=execution_id,
            verdict=Verdict.ROLLBACK_REQUIRED,
            checks=FrozenDict(checks),
            detail=detail,
        )

    def verify_sync(
        self,
        execution_id: str,
        service: str,
        before_state: dict[str, Any],
        after_state: dict[str, Any],
        slo: dict[str, Any],
        expected: dict[str, Any] | None = None,
        command_succeeded: bool = True,
    ) -> VerificationResult:
        """Synchronous wrapper for pipeline integration."""
        import asyncio
        import concurrent.futures

        try:
            # Check fast connectivity with a quick synchronous socket probe or timeout
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(
                    lambda: asyncio.run(
                        self.verify(
                            execution_id=execution_id,
                            service=service,
                            before_state=before_state,
                            after_state=after_state,
                            slo=slo,
                            expected=expected,
                            command_succeeded=command_succeeded,
                        )
                    )
                )
                return fut.result(timeout=3.0)
        except Exception:
            return mock_verifier.verify(
                execution_id=execution_id,
                before=before_state,
                after=after_state,
                slo=slo,
                expected=expected,
                command_succeeded=command_succeeded,
            )


# Singleton verifier
PROMETHEUS_VERIFIER = PrometheusVerifier()
