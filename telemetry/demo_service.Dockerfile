# The real, instrumented demo workload for the live tier.
#
# Deliberately stdlib-only: no pip install, no requirements drift, and the
# metrics are emitted by the same process that serves the requests -- so the
# error rate Prometheus scrapes and the error rate a user actually experiences
# cannot disagree.
FROM python:3.12-slim

WORKDIR /app
COPY telemetry/demo_service.py /app/demo_service.py

ENV PORT=8081 \
    DEMO_SERVICE=checkout-api \
    DEMO_STATE_FILE=/tmp/demo-healthy \
    DEMO_FAIL_RATE=1.0 \
    PYTHONUNBUFFERED=1

# Non-root. The service needs no write access beyond its own state file.
RUN useradd --system --uid 10001 demo
USER 10001

EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD ["python", "-c", "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=2)"]

CMD ["python", "/app/demo_service.py"]
