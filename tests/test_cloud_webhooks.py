"""Tests for enterprise cloud monitoring webhooks (Alertmanager, Datadog, CloudWatch, PagerDuty)."""
import json
import sys
from pathlib import Path
import pytest

_ROOT = Path(__file__).resolve().parents[1]
_BACKEND = _ROOT / "backend"
sys.path.insert(0, str(_BACKEND))
sys.path.insert(0, str(_ROOT))

import app.compat  # noqa: F401
from starlette.testclient import TestClient
from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_alertmanager_webhook(client):
    payload = {
        "version": "4",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "PodCrashLooping",
                    "service": "checkout-service",
                    "severity": "critical",
                    "env": "production",
                },
                "annotations": {
                    "summary": "Pod checkout-service-789d is CrashLooping with OOMKilled",
                    "description": "Container exited with code 137",
                },
                "startsAt": "2026-09-26T10:00:00Z",
            }
        ],
    }
    resp = client.post("/alerts/webhook/alertmanager", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["source"] == "prometheus-alertmanager"
    assert data["service"] == "checkout-service"
    assert data["scenario"] == "crashloop-oom"
    assert "incident_id" in data


def test_datadog_webhook(client):
    payload = {
        "id": "datadog-evt-9912",
        "event_title": "Database connection pool exhausted",
        "body": "Connections exceeded 95% threshold on postgres-primary",
        "tags": ["env:production", "service:billing-service"],
        "priority": "normal",
        "alert_type": "error",
    }
    resp = client.post("/alerts/webhook/datadog", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["source"] == "datadog"
    assert data["service"] == "billing-service"
    assert data["scenario"] == "db-exhaust"
    assert "incident_id" in data


def test_cloudwatch_sns_webhook(client):
    sns_inner = {
        "AlarmName": "payment-api-network-timeout-high",
        "NewStateValue": "ALARM",
        "NewStateReason": "Threshold Crossed: 1 out of 1 datapoints (upstream network timeout > 5000ms)",
        "Trigger": {
            "Dimensions": [{"name": "ServiceName", "value": "payment-api"}]
        },
    }
    payload = {
        "Type": "Notification",
        "MessageId": "sns-12345",
        "Subject": "ALARM: payment-api-network-timeout-high in us-east-1",
        "Message": json.dumps(sns_inner),
    }
    resp = client.post("/alerts/webhook/cloudwatch", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["source"] == "aws-cloudwatch"
    assert data["service"] == "payment-api"
    assert data["scenario"] == "net-dep-fail"
    assert "incident_id" in data


def test_pagerduty_webhook(client):
    payload = {
        "event": {
            "id": "pd-evt-888",
            "event_type": "incident.triggered",
            "data": {
                "id": "P12345",
                "title": "High 5xx Spike following release v23",
                "service": {"summary": "auth-service"},
                "urgency": "high",
            },
        }
    }
    resp = client.post("/alerts/webhook/pagerduty", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["source"] == "pagerduty"
    assert data["service"] == "auth-service"
    assert data["scenario"] == "bad-deploy"
    assert "incident_id" in data
