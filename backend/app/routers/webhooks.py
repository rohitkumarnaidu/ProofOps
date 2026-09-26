"""Cloud Monitoring & Alerting Webhook Ingestion Adapters (M19c Enterprise Cloud Ingress).

Accepts native webhook payloads from enterprise monitoring systems:
1. Prometheus Alertmanager (POST /alerts/webhook/alertmanager)
2. Datadog Webhook (POST /alerts/webhook/datadog)
3. AWS CloudWatch / SNS (POST /alerts/webhook/cloudwatch)
4. PagerDuty v2 Webhook (POST /alerts/webhook/pagerduty)

Parses external payloads, normalizes them into ProofOps telemetry bundles,
and securely dispatches them to the orchestrator control plane.
"""
from __future__ import annotations

import json
import time
from typing import Any, Mapping
from pydantic import BaseModel, Field

from fastapi import APIRouter, Header, HTTPException, Request

router = APIRouter(prefix="/alerts/webhook", tags=["webhooks"])


def _detect_scenario(text: str) -> str:
    """Classify incident scenario from alert labels and annotations."""
    lower = text.lower()
    if any(k in lower for k in ("oom", "crashloop", "memorylimit", "137")):
        return "crashloop-oom"
    if any(k in lower for k in ("db", "pool", "database", "postgres", "mysql", "exhaust")):
        return "db-exhaust"
    if any(k in lower for k in ("network", "timeout", "egress", "dependency", "dns")):
        return "net-dep-fail"
    if any(k in lower for k in ("injection", "malicious", "attack", "sqli", "xss")):
        return "injection"
    return "bad-deploy"


@router.post("/alertmanager")
async def alertmanager_webhook(
    request: Request,
    x_api_key: str | None = Header(default=None),
) -> dict[str, Any]:
    """Ingest native Prometheus Alertmanager JSON webhook."""
    from app.services import orchestrator as orchestrator_mod

    payload = await request.json()
    alerts = payload.get("alerts", [])
    if not alerts:
        # Check single alert or root alert shape
        if "labels" in payload:
            alerts = [payload]
        else:
            raise HTTPException(status_code=422, detail="No alerts found in Alertmanager payload")

    first = alerts[0]
    labels = first.get("labels", {})
    annotations = first.get("annotations", {})

    service = labels.get("service") or labels.get("job") or labels.get("app") or "payment-service"
    env = labels.get("env") or labels.get("environment") or "prod"
    alertname = labels.get("alertname", "PrometheusAlert")
    summary = annotations.get("summary") or annotations.get("description") or f"Alert {alertname} firing"
    
    scenario = _detect_scenario(f"{alertname} {summary}")
    timestamp = int(time.time())
    incident_id = f"prom-{service}-{timestamp}"

    telemetry = {
        "service": service,
        "env": env,
        "metrics": {
            "error_rate": 0.18 if scenario == "bad-deploy" else 0.05,
            "firing_alerts": len(alerts),
            "severity": labels.get("severity", "critical"),
        },
        "error_signature": summary,
    }

    worker = orchestrator_mod.ORCHESTRATOR
    accepted = worker.submit(incident_id, scenario, telemetry, source="alertmanager-webhook")

    return {
        "accepted": accepted,
        "incident_id": incident_id,
        "source": "prometheus-alertmanager",
        "scenario": scenario,
        "service": service,
        "firing_count": len(alerts),
    }


@router.post("/datadog")
async def datadog_webhook(
    request: Request,
    x_api_key: str | None = Header(default=None),
) -> dict[str, Any]:
    """Ingest native Datadog alert webhook."""
    from app.services import orchestrator as orchestrator_mod

    payload = await request.json()
    title = payload.get("event_title") or payload.get("title") or "Datadog Monitor Triggered"
    body = payload.get("body") or payload.get("comment") or ""
    tags = payload.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]

    # Parse tags like env:prod, service:order-service
    tag_dict: dict[str, str] = {}
    for tag in tags:
        if ":" in tag:
            k, v = tag.split(":", 1)
            tag_dict[k.strip().lower()] = v.strip()

    service = tag_dict.get("service", "payment-service")
    env = tag_dict.get("env", "prod")
    scenario = _detect_scenario(f"{title} {body}")
    timestamp = int(time.time())
    incident_id = f"dd-{service}-{timestamp}"

    telemetry = {
        "service": service,
        "env": env,
        "metrics": {
            "error_rate": 0.15,
            "priority": payload.get("priority", "normal"),
            "alert_type": payload.get("alert_type", "error"),
        },
        "error_signature": title,
    }

    worker = orchestrator_mod.ORCHESTRATOR
    accepted = worker.submit(incident_id, scenario, telemetry, source="datadog-webhook")

    return {
        "accepted": accepted,
        "incident_id": incident_id,
        "source": "datadog",
        "scenario": scenario,
        "service": service,
    }


@router.post("/cloudwatch")
async def cloudwatch_webhook(
    request: Request,
    x_api_key: str | None = Header(default=None),
) -> dict[str, Any]:
    """Ingest AWS CloudWatch Alarm notification (via SNS HTTP POST)."""
    from app.services import orchestrator as orchestrator_mod

    raw_body = await request.body()
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

    # If sent via AWS SNS, the actual alarm is in the "Message" string
    if payload.get("Type") == "Notification" and "Message" in payload:
        try:
            msg = json.loads(payload["Message"])
        except Exception:
            msg = {"AlarmName": payload.get("Subject", "CloudWatchAlarm"), "NewStateReason": payload.get("Message")}
    else:
        msg = payload

    alarm_name = msg.get("AlarmName", "CloudWatchAlarm")
    reason = msg.get("NewStateReason", "")
    trigger = msg.get("Trigger", {})
    dimensions = trigger.get("Dimensions", [])
    
    service = "payment-service"
    for dim in dimensions:
        if dim.get("name", "").lower() in ("servicename", "service", "app"):
            service = dim.get("value", service)

    scenario = _detect_scenario(f"{alarm_name} {reason}")
    timestamp = int(time.time())
    incident_id = f"cw-{service}-{timestamp}"

    telemetry = {
        "service": service,
        "env": "prod",
        "metrics": {
            "error_rate": 0.14,
            "alarm_state": msg.get("NewStateValue", "ALARM"),
        },
        "error_signature": f"{alarm_name}: {reason}",
    }

    worker = orchestrator_mod.ORCHESTRATOR
    accepted = worker.submit(incident_id, scenario, telemetry, source="aws-cloudwatch-webhook")

    return {
        "accepted": accepted,
        "incident_id": incident_id,
        "source": "aws-cloudwatch",
        "scenario": scenario,
        "service": service,
    }


@router.post("/pagerduty")
async def pagerduty_webhook(
    request: Request,
    x_api_key: str | None = Header(default=None),
) -> dict[str, Any]:
    """Ingest PagerDuty v2 webhook."""
    from app.services import orchestrator as orchestrator_mod

    payload = await request.json()
    event = payload.get("event", {})
    data = event.get("data", {})
    title = data.get("title") or "PagerDuty High-Urgency Incident"
    service_info = data.get("service", {})
    service = service_info.get("summary", "payment-service")

    scenario = _detect_scenario(title)
    timestamp = int(time.time())
    incident_id = f"pd-{service}-{timestamp}"

    telemetry = {
        "service": service,
        "env": "prod",
        "metrics": {
            "error_rate": 0.16,
            "urgency": data.get("urgency", "high"),
        },
        "error_signature": title,
    }

    worker = orchestrator_mod.ORCHESTRATOR
    accepted = worker.submit(incident_id, scenario, telemetry, source="pagerduty-webhook")

    return {
        "accepted": accepted,
        "incident_id": incident_id,
        "source": "pagerduty",
        "scenario": scenario,
        "service": service,
    }
