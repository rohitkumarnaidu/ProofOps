"""A real, instrumented demo workload for the live tier.

Why this exists
---------------
The verifier asks Prometheus for an error rate. Against synthetic telemetry that
question has no real answer, so the check silently rode the fallback path while
`replicas` was genuinely measured -- one honest signal resting on nothing, which
is the same defect as having none.

This service closes that. It is a small real HTTP server that:

  * serves requests, and returns 5xx when it is in its "bad" state
  * exposes Prometheus text metrics on /metrics
  * reports exactly the metric shape the verifier already queries:
    ``http_requests_total{service=...,status=...}``

So no verifier query had to be loosened to accommodate it. The metric name is the
one the SLO was already written against; what changed is that something real now
produces it, and its error rate can be measured before and after a remediation.

The bad/healthy switch is a file, so a "bad deploy" is a real state change an
operator (or a runbook) can make and observe, not a flag flipped in a mock.
"""

from __future__ import annotations

import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SERVICE = os.environ.get("DEMO_SERVICE", "checkout-api")
#: Path of the switch file. Present -> healthy. Absent -> failing, so a rollback
#: or a promotion is an observable filesystem fact rather than a runtime flag.
STATE_FILE = os.environ.get("DEMO_STATE_FILE", "/tmp/demo-healthy")
FAIL_RATE = float(os.environ.get("DEMO_FAIL_RATE", "1.0"))

_lock = threading.Lock()
_counters: dict[tuple[str, str], int] = {}
_started = time.time()


def _healthy() -> bool:
    return os.path.exists(STATE_FILE)


def _bump(status: str) -> None:
    with _lock:
        key = (SERVICE, status)
        _counters[key] = _counters.get(key, 0) + 1


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _respond(self, code: int, body: bytes,
                 content_type: str = "text/plain") -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (http.server naming)
        if self.path.startswith("/metrics"):
            self._respond(200, self._render_metrics().encode(),
                          "text/plain; version=0.0.4")
            return
        if self.path.startswith("/healthz"):
            # Liveness only: it says the process is up, not that it is serving
            # successfully. Conflating the two is how a broken service reports
            # healthy.
            self._respond(200, b"ok\n")
            return

        # Deterministic per-path outcome, so a run is reproducible: the same
        # request against the same state always produces the same status.
        healthy = _healthy()
        failing = not healthy and (hash(self.path) % 100) < int(FAIL_RATE * 100)
        code = 500 if failing else 200
        self._bump(str(code))
        self._respond(code, b"ok\n" if not failing else b"error\n")

    def _bump(self, status: str) -> None:
        globals()["_bump"](status)

    def log_message(self, fmt: str, *args: object) -> None:
        # Silence per-request logging: it is noise at scrape volume, and this
        # container's real logs are the audit trail, not access logs.
        return

    def _render_metrics(self) -> str:
        with _lock:
            snapshot = dict(_counters)
        lines = [
            "# HELP http_requests_total Total HTTP requests by service and status.",
            "# TYPE http_requests_total counter",
        ]
        for (service, status), count in sorted(snapshot.items()):
            lines.append(
                f'http_requests_total{{service="{service}",status="{status}"}} '
                f"{count}")
        # An unhealthy service must also be visible as a gauge, so a dashboard or
        # a verifier can read health without inferring it from a ratio.
        lines += [
            "# HELP demo_service_healthy 1 when the service is serving normally.",
            "# TYPE demo_service_healthy gauge",
            f'demo_service_healthy{{service="{SERVICE}"}} '
            f"{1 if _healthy() else 0}",
            "# HELP demo_service_uptime_seconds Seconds since start.",
            "# TYPE demo_service_uptime_seconds gauge",
            f'demo_service_uptime_seconds{{service="{SERVICE}"}} '
            f"{time.time() - _started:.3f}",
        ]
        return "\n".join(lines) + "\n"


def _self_traffic(interval: float = 2.0) -> None:
    """Generate real requests against ourselves so the SLO has a real series.

    Without this the counter only moves when something external happens to call
    the service, and Prometheus reports "no series" -- which the verifier must
    then treat as unmeasured. A real service under observation generates its own
    traffic; more importantly, this makes the metric a property of the service's
    actual behaviour rather than of whoever happened to be watching.

    Deliberately goes through the real request path, so the status codes counted
    are the ones a client would receive.
    """
    import urllib.error
    import urllib.request

    paths = ("/checkout", "/cart", "/health-check", "/checkout")
    while True:
        for path in paths:
            try:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{os.environ.get('PORT', '8082')}{path}",
                    timeout=3).read()
            except urllib.error.HTTPError:
                pass  # a 5xx is the interesting outcome, not an error here
            except Exception:
                pass
            time.sleep(interval / len(paths))


def main() -> None:
    port = int(os.environ.get("PORT", "8081"))
    traffic = threading.Thread(target=_self_traffic, daemon=True)
    traffic.start()
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
