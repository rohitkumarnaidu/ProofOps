"""Live Kubernetes Infrastructure Executor (M08 Live Tier).

Connects to Kubernetes via the official kubernetes Python client.
Supports local (Docker Desktop / Kind / Minikube) and cloud (EKS / GKE / AKS)
clusters using ~/.kube/config or in-cluster ServiceAccount credentials.
"""
from __future__ import annotations

import copy
import datetime
import os
from pathlib import Path
from typing import Any, Mapping

from app.contracts.action import Action
from app.contracts.enums import ExecutorTier
from app.contracts.execution import Execution
from app.contracts.incident import FrozenDict


class ClusterUnreachableError(RuntimeError):
    """Raised when an operation requires a live Kubernetes cluster but none is reachable."""


class KubernetesExecutor:
    """Enterprise Kubernetes Executor for safe, governed cluster mutations."""

    def __init__(self, kubeconfig_path: str | None = None) -> None:
        self.kubeconfig_path = kubeconfig_path
        self._apps_v1 = None
        self._core_v1 = None
        self._connected = False
        self._cluster_host = ""

    def connect(self) -> bool:
        """Attempt connection to Kubernetes API server."""
        try:
            from kubernetes import client, config

            # Try custom kubeconfig path if specified
            if self.kubeconfig_path and os.path.exists(self.kubeconfig_path):
                config.load_kube_config(config_file=self.kubeconfig_path)
            else:
                # Try in-cluster first, then default local kubeconfig
                try:
                    config.load_incluster_config()
                except Exception:
                    config.load_kube_config()

            api_client = client.ApiClient()
            self._cluster_host = api_client.configuration.host
            self._apps_v1 = client.AppsV1Api(api_client)
            self._core_v1 = client.CoreV1Api(api_client)
            # Lightweight probe
            self._core_v1.get_api_resources()
            self._connected = True
            return True
        except Exception:
            self._connected = False
            return False

    @property
    def is_connected(self) -> bool:
        if not self._connected:
            self.connect()
        return self._connected

    def cluster_status(self) -> dict[str, Any]:
        """Return connectivity status and cluster host info."""
        connected = self.is_connected
        return {
            "connected": connected,
            "host": self._cluster_host if connected else None,
            "tier": "k8s" if connected else "offline",
        }

    def get_deployment_state(self, namespace: str, deployment_name: str) -> dict[str, Any]:
        """Fetch current deployment observables."""
        if not self.is_connected:
            raise ClusterUnreachableError("Cannot inspect deployment: Kubernetes cluster is unreachable.")
        assert self._apps_v1 is not None

        try:
            dep = self._apps_v1.read_namespaced_deployment(name=deployment_name, namespace=namespace)
            replicas = dep.spec.replicas or 1
            available = dep.status.available_replicas or 0
            containers = dep.spec.template.spec.containers
            image = containers[0].image if containers else "unknown"

            return {
                "deployment": deployment_name,
                "namespace": namespace,
                "replicas": replicas,
                "available_replicas": available,
                "image": image,
                "pods_ready": available >= replicas,
                "generation": dep.metadata.generation,
            }
        except Exception as exc:
            raise ClusterUnreachableError(f"Failed to read deployment {deployment_name}: {exc}") from exc

    def execute(self, action: Action, state: dict[str, Any] | None = None) -> tuple[Execution, dict[str, Any]]:
        """Apply an authorized action to the cluster.

        If live cluster is reachable, performs real Kubernetes API calls.
        If unreachable and state is provided, falls back to the deterministic
        sandbox with a documented fallback tier.
        """
        p = action.parameters
        namespace = str(p.get("namespace", "default"))
        deployment = str(p.get("deployment", action.resource_id))

        if not self.is_connected:
            # Fallback to local sandbox if cluster is offline
            from app.services import sandbox

            return sandbox.apply(action, state or sandbox.initial_state())

        assert self._apps_v1 is not None
        assert self._core_v1 is not None

        before_state = self.get_deployment_state(namespace, deployment)
        logs: list[str] = [
            f"k8s-exec action={action.action_type} resource={deployment} namespace={namespace}",
        ]

        if action.action_type == "rollback_deployment":
            to_version = str(p.get("to_version", ""))
            # In live K8s, patch container image or annotations to trigger rollout
            patch_body = {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {
                                "proofops.io/rolled-back-to": to_version,
                                "kubectl.kubernetes.io/restartedAt": datetime.datetime.now(
                                    datetime.timezone.utc
                                ).isoformat(),
                            }
                        }
                    }
                }
            }
            if to_version and "/" in to_version:
                # If full image specified, patch image directly
                patch_body["spec"]["template"]["spec"] = {
                    "containers": [{"name": deployment, "image": to_version}]
                }
            self._apps_v1.patch_namespaced_deployment(name=deployment, namespace=namespace, body=patch_body)
            logs.append(f"deployment {deployment} patched for rollback (rev {to_version})")

        elif action.action_type in ("restart_pod", "rolling_restart"):
            # Standard kubectl rollout restart equivalent
            restarted_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
            patch_body = {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {
                                "kubectl.kubernetes.io/restartedAt": restarted_at
                            }
                        }
                    }
                }
            }
            self._apps_v1.patch_namespaced_deployment(name=deployment, namespace=namespace, body=patch_body)
            logs.append(f"deployment {deployment} rollout restart triggered at {restarted_at}")

        elif action.action_type == "scale_deployment":
            new_replicas = int(p.get("replicas", before_state.get("replicas", 1)))
            patch_body = {"spec": {"replicas": new_replicas}}
            self._apps_v1.patch_namespaced_deployment(name=deployment, namespace=namespace, body=patch_body)
            logs.append(f"deployment {deployment} scaled to {new_replicas} replicas")

        elif action.action_type in ("read", "describe", "logs", "metrics", "list"):
            logs.append(f"inspected deployment {deployment} in {namespace}")

        after_state = self.get_deployment_state(namespace, deployment)
        diff = {
            k: {"before": before_state.get(k), "after": after_state.get(k)}
            for k in after_state
            if before_state.get(k) != after_state.get(k)
        }

        execution = Execution(
            action_id=action.action_id,
            incident_id=action.incident_id,
            tier=ExecutorTier.DOCKER,
            state_diff=FrozenDict({
                "before": before_state,
                "after": after_state,
                "changed": diff,
            }),
            logs=tuple(logs),
            idempotency_key=action.action_id,
        )

        return execution, after_state


# Singleton instance
K8S_EXECUTOR = KubernetesExecutor()
