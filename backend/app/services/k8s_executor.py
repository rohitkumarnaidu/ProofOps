"""Live Kubernetes Infrastructure Executor (M08 Live Tier).

Connects to Kubernetes via the official kubernetes Python client.
Supports local (Docker Desktop / Kind / Minikube) and cloud (EKS / GKE / AKS)
clusters using ~/.kube/config or in-cluster ServiceAccount credentials.
"""
from __future__ import annotations

import datetime
import os
from typing import Any

from app.config import get_settings
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
        # Typed as Any rather than None: the concrete AppsV1Api/CoreV1Api types
        # only exist once `kubernetes` is importable, and this module must import
        # cleanly without it (the driver is an optional live-tier dependency).
        self._apps_v1: Any = None
        self._core_v1: Any = None
        self._connected = False
        self._cluster_host = ""
        self._server_version = ""
        #: Why the last connect attempt failed, as an exception *type* only.
        #: Swallowing this is what let a missing driver and a live-but-denied
        #: cluster both report as the same silent "offline".
        self._error: str | None = None
        self._namespace = get_settings().KUBERNETES_NAMESPACE.strip()

    def connect(self) -> bool:
        """Attempt connection to Kubernetes API server.

        The probe is deliberately a *namespaced, authorised* read rather than
        API discovery. Discovery is cluster-scoped, so it is denied by exactly
        the RBAC this project wants: a ServiceAccount that may act on workloads
        in one namespace and nothing else. Probing with `get_api_resources()`
        therefore failed against a correctly-scoped identity and reported a
        healthy cluster as offline. A permission-appropriate probe tests the
        thing we actually need -- can we read the workloads we may act on.
        """
        try:
            from kubernetes import client, config

            if self.kubeconfig_path:
                # Fail closed. If an operator explicitly pinned a kubeconfig, a
                # missing file means "no cluster", not "try something else".
                #
                # Falling through to the ambient ~/.kube/config here was a
                # fail-open: a deployment configured for an unreachable sandbox
                # would silently connect to whatever cluster the host happened to
                # have a current context for -- possibly production. The
                # control plane would then be executing against a cluster nobody
                # chose. An explicit path is a hard boundary, not a hint.
                if not os.path.exists(self.kubeconfig_path):
                    self._connected = False
                    self._error = "KubeconfigNotFound"
                    return False
                config.load_kube_config(config_file=self.kubeconfig_path)
            else:
                # No explicit path: in-cluster first, then $KUBECONFIG / default.
                try:
                    config.load_incluster_config()
                except Exception:
                    config.load_kube_config()

            api_client = client.ApiClient()
            self._cluster_host = api_client.configuration.host
            self._apps_v1 = client.AppsV1Api(api_client)
            self._core_v1 = client.CoreV1Api(api_client)

            # Version is unauthenticated on every conformant apiserver, so it
            # proves the server is real without needing any permission at all.
            self._server_version = str(client.VersionApi(api_client).get_code().git_version)

            # Then prove we are actually *authorised* for the scope we claim,
            # using the narrowest call that scope permits.
            ns = self._namespace or "default"
            self._core_v1.list_namespaced_pod(ns, limit=1)

            self._connected = True
            self._error = None
            return True
        except Exception as exc:
            self._connected = False
            self._error = type(exc).__name__
            return False

    @property
    def is_connected(self) -> bool:
        if not self._connected:
            self.connect()
        return self._connected

    def cluster_status(self) -> dict[str, Any]:
        """Return connectivity status and cluster host info.

        Reports the failure reason alongside the boolean, because "not
        connected" is not actionable on its own: a missing driver, an absent
        kubeconfig, and a live cluster refusing our identity are three different
        problems with three different fixes.
        """
        connected = self.is_connected
        return {
            "connected": connected,
            "host": self._cluster_host if connected else None,
            "tier": "k8s" if connected else "offline",
            "version": self._server_version if connected else None,
            "namespace": self._namespace or None,
            "error": self._error,
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
        # Default to the namespace this identity is scoped to, not "default".
        #
        # The agent's ServiceAccount carries a namespaced Role in exactly one
        # namespace, so any other default is a guaranteed 403 -- and a 403 here
        # surfaced as a run stuck in EXECUTING with no verdict, which reads like
        # a hang rather than a permissions error. An action may still name a
        # namespace explicitly; the configured one is the floor.
        namespace = str(p.get("namespace") or self._namespace or "default")
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
            # Annotated as Any: this is a free-form JSON merge patch, and the two
            # shapes below (string annotations vs. a container list vs. an int
            # replica count) cannot share an inferred value type.
            patch_body: dict[str, Any] = {
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
            scale_body: dict[str, Any] = {"spec": {"replicas": new_replicas}}
            self._apps_v1.patch_namespaced_deployment(name=deployment, namespace=namespace, body=scale_body)
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
