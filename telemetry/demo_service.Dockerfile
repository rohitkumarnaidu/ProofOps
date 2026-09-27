# The real, instrumented demo workload for the live tier.
#
# Built twice, as two tags, from this one file:
#   :good  (DEMO_FAIL_RATE=0.0)  serves 200
#   :bad   (DEMO_FAIL_RATE=1.0)  serves 5xx
#
# That is what makes the rollback real. A "bad deploy" is a genuine image change
# on a genuine Deployment, and rolling it back is a genuine patch back to the
# previous tag through the real API server. The error rate that recovers is
# measured by Prometheus scraping the process that serves the traffic, so the
# before/after is observed rather than narrated.
#
# Deliberately stdlib-only: no pip install, no dependency drift, and the metrics
# come from the same process that serves the requests, so the error rate
# Prometheus scrapes and the error rate a user experiences cannot disagree.
FROM python:3.12-slim

ARG DEMO_FAIL_RATE=0.0
ENV PORT=8082 \
    DEMO_SERVICE=checkout-api \
    DEMO_STATE_FILE=/tmp/demo-healthy \
    DEMO_FAIL_RATE=${DEMO_FAIL_RATE} \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY telemetry/demo_service.py /app/demo_service.py

# Non-root: the service needs no write access beyond its own state file.
RUN useradd --system --uid 10001 demo
USER 10001

EXPOSE 8082
# Liveness only. It says the process is up, not that it is serving successfully;
# conflating the two is how a broken service reports healthy.
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD ["python", "-c", "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8082/healthz',timeout=2)"]

CMD ["python", "/app/demo_service.py"]
