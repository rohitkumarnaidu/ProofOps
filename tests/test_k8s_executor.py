"""Tests for Live Kubernetes Infrastructure Executor."""
import sys
from pathlib import Path
from unittest.mock import MagicMock
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.contracts.action import Action
from app.contracts.enums import ActionType, Environment, ExecutorTier, RiskLevel
from app.contracts.incident import FrozenDict
from app.services.k8s_executor import KubernetesExecutor, ClusterUnreachableError, K8S_EXECUTOR


def _make_action(action_type: str, resource_id: str = "web-api", params: dict | None = None) -> Action:
    return Action(
        action_id="act-k8s-01",
        incident_id="inc-k8s-01",
        agent_id="A3_planner",
        action_type=action_type,
        resource_type="deployment",
        resource_id=resource_id,
        environment=Environment.PROD,
        parameters=FrozenDict(params or {}),
        risk_level=RiskLevel.YELLOW,
        reason="Testing k8s executor",
        evidence_ids=("ev-1",),
        runbook_id="bad-deploy-rollback",
        runbook_version="1.0.0",
        expected_outcome="Deployment restored to healthy version",
        verification_plan=("check_ready",),
    )


def test_k8s_executor_offline_status():
    exec_inst = KubernetesExecutor(kubeconfig_path="/nonexistent/path/kube.config")
    status = exec_inst.cluster_status()
    assert status["connected"] is False
    assert status["tier"] == "offline"
    assert status["host"] is None


def test_k8s_executor_unreachable_error():
    exec_inst = KubernetesExecutor(kubeconfig_path="/nonexistent/path/kube.config")
    with pytest.raises(ClusterUnreachableError) as exc_info:
        exec_inst.get_deployment_state("default", "web-api")
    assert "unreachable" in str(exc_info.value).lower()


def test_k8s_executor_fallback_to_sandbox_when_offline():
    exec_inst = KubernetesExecutor(kubeconfig_path="/nonexistent/path/kube.config")
    action = _make_action("rollback_deployment", "checkout-api", {"to_version": "v22"})
    
    execution, after_state = exec_inst.execute(action)
    assert execution.action_id == "act-k8s-01"
    assert execution.incident_id == "inc-k8s-01"
    assert after_state["deployment_version"] == "v22"


def test_k8s_executor_mock_connected_rollback():
    exec_inst = KubernetesExecutor()
    exec_inst._connected = True
    mock_apps = MagicMock()
    mock_core = MagicMock()
    exec_inst._apps_v1 = mock_apps
    exec_inst._core_v1 = mock_core

    # Setup read_namespaced_deployment return mock
    dep_mock = MagicMock()
    dep_mock.spec.replicas = 2
    dep_mock.status.available_replicas = 2
    container_mock = MagicMock()
    container_mock.image = "org/checkout-api:v22"
    dep_mock.spec.template.spec.containers = [container_mock]
    dep_mock.metadata.generation = 4
    mock_apps.read_namespaced_deployment.return_value = dep_mock

    action = _make_action("rollback_deployment", "checkout-api", {"to_version": "org/checkout-api:v22", "namespace": "prod"})
    execution, after_state = exec_inst.execute(action)

    assert mock_apps.patch_namespaced_deployment.called
    patch_call = mock_apps.patch_namespaced_deployment.call_args
    assert patch_call.kwargs["name"] == "checkout-api"
    assert patch_call.kwargs["namespace"] == "prod"
    assert "rolled-back-to" in str(patch_call.kwargs["body"])
    assert any("rollback" in log for log in execution.logs)


def test_k8s_executor_mock_connected_restart():
    exec_inst = KubernetesExecutor()
    exec_inst._connected = True
    mock_apps = MagicMock()
    mock_core = MagicMock()
    exec_inst._apps_v1 = mock_apps
    exec_inst._core_v1 = mock_core

    dep_mock = MagicMock()
    dep_mock.spec.replicas = 3
    dep_mock.status.available_replicas = 3
    dep_mock.spec.template.spec.containers = [MagicMock(image="v1")]
    dep_mock.metadata.generation = 2
    mock_apps.read_namespaced_deployment.return_value = dep_mock

    action = _make_action("restart_pod", "payment-service", {"namespace": "prod"})
    execution, after_state = exec_inst.execute(action)

    assert mock_apps.patch_namespaced_deployment.called
    patch_call = mock_apps.patch_namespaced_deployment.call_args
    assert "restartedAt" in str(patch_call.kwargs["body"])
    assert any("rollout restart triggered" in log for log in execution.logs)


def test_k8s_executor_mock_connected_scale():
    exec_inst = KubernetesExecutor()
    exec_inst._connected = True
    mock_apps = MagicMock()
    mock_core = MagicMock()
    exec_inst._apps_v1 = mock_apps
    exec_inst._core_v1 = mock_core

    dep_mock = MagicMock()
    dep_mock.spec.replicas = 2
    dep_mock.status.available_replicas = 2
    dep_mock.spec.template.spec.containers = [MagicMock(image="v1")]
    dep_mock.metadata.generation = 1
    mock_apps.read_namespaced_deployment.return_value = dep_mock

    action = _make_action("scale_deployment", "worker-pool", {"replicas": 4, "namespace": "prod"})
    execution, after_state = exec_inst.execute(action)

    assert mock_apps.patch_namespaced_deployment.called
    patch_call = mock_apps.patch_namespaced_deployment.call_args
    assert patch_call.kwargs["body"]["spec"]["replicas"] == 4
    assert any("scaled to 4 replicas" in log for log in execution.logs)
