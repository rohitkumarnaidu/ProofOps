#!/usr/bin/env bash
# Provision the real live tier: a genuine Kubernetes API server and a genuine
# Prometheus, both on this machine, with no cloud account and no credentials.
#
# Why KIND rather than real AWS/GCP: the safety claims this project makes are
# about the control plane, not about whose cloud it runs in. KIND gives a real
# API server with real RBAC on a laptop, so `delete namespace` is refused by
# actual Kubernetes authorization rather than only by our policy engine. Two
# independent boundaries, no billing, no keys, and it runs offline for a demo.
#
# What it creates:
#   - kind cluster "proofops" (Kubernetes v1.31.x, real API server)
#   - namespace proofops-demo + a deployment to act on
#   - ServiceAccount + namespaced Role: may read and scale workloads, and is
#     structurally unable to delete namespaces, read secrets, or mutate RBAC
#   - a kubeconfig for that ServiceAccount, written where the API container
#     mounts it, pointed at the kind-network address so TLS verifies against a
#     real certificate (no verification is ever disabled)
#   - a Prometheus container scraping the real API server
#
# Usage:  bash scripts/live_tier.sh up      # provision everything
#         bash scripts/live_tier.sh status  # report what is real right now
#         bash scripts/live_tier.sh down    # tear down
set -euo pipefail

# On a Windows host under Git Bash, MSYS rewrites any argument that looks like a
# POSIX absolute path into a Windows one, so /etc/prometheus/prometheus.yml
# becomes C:/Program Files/Git/etc/prometheus/prometheus.yml and Prometheus
# cannot find its own config. Disabling the conversion is the fix; a relative or
# Windows path would just move the breakage.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

CLUSTER="${PROOFOPS_KIND_CLUSTER:-proofops}"
NAMESPACE="${PROOFOPS_K8S_NAMESPACE:-proofops-demo}"
DEPLOY="${PROOFOPS_K8S_DEPLOY:-checkout-api}"
SA=proofops-agent
NETWORK=kind
STATE_DIR="${PROOFOPS_LIVE_STATE:-var/live}"
KUBECONFIG_OUT="${STATE_DIR}/kubeconfig"
PROM_CONTAINER=proofops-prometheus
PROM_PORT="${PROOFOPS_PROM_PORT:-9090}"
PROM_NET_PORT="${PROOFOPS_PROM_CONTAINER_PORT:-9090}"

say() { printf '  %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || fail "missing required tool: $1"; }

up() {
  need docker
  need kind
  need kubectl

  docker info >/dev/null 2>&1 || fail "docker daemon not running"
  mkdir -p "${STATE_DIR}"

  # ---- cluster ----------------------------------------------------------
  if kind get clusters 2>/dev/null | grep -qx "${CLUSTER}"; then
    say "kind cluster '${CLUSTER}' already exists"
  else
    say "creating kind cluster '${CLUSTER}' (real API server, ~30s)"
    kind create cluster --name "${CLUSTER}" --wait 240s >/dev/null
  fi
  ctx="kind-${CLUSTER}"
  kubectl config use-context "${ctx}" >/dev/null

  # ---- workload to act on ----------------------------------------------
  kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml \
    | kubectl apply -f - >/dev/null
  kubectl -n "${NAMESPACE}" apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${DEPLOY}
  namespace: ${NAMESPACE}
spec:
  replicas: 2
  selector:
    matchLabels: {app: ${DEPLOY}}
  template:
    metadata:
      labels: {app: ${DEPLOY}}
    spec:
      containers:
        - name: app
          image: registry.k8s.io/pause:3.9
          ports: [{containerPort: 8080}]
YAML
  say "namespace/${NAMESPACE} deployment/${DEPLOY} ready"

  # ---- RBAC: the second, independent safety boundary --------------------
  # Our policy engine already denies destructive actions. That is our own code
  # reasoning about our own inputs, so it is necessary but not sufficient. This
  # Role makes the *cluster* refuse independently: if the control plane had a
  # bypass, escalation still stops here.
  kubectl -n "${NAMESPACE}" apply -f - >/dev/null <<YAML
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${SA}
  namespace: ${NAMESPACE}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ${SA}
  namespace: ${NAMESPACE}
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "watch", "patch", "update"]
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${SA}
  namespace: ${NAMESPACE}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ${SA}
subjects:
  - kind: ServiceAccount
    name: ${SA}
    namespace: ${NAMESPACE}
YAML
  say "rbac: ${SA} may read+scale workloads; delete/secrets/rbac are NOT granted"

  # Prometheus needs to read the apiserver's /metrics, which is a non-resource
  # URL and is denied by default (hence the 403). This grant is deliberately as
  # small as a ClusterRole can be: read-only, and only that one path. It does not
  # widen any namespaced permission, so the delete/secrets/rbac denials above are
  # unaffected -- which the status check re-asserts on every run.
  kubectl apply -f - >/dev/null <<YAML
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ${SA}-metrics
rules:
  - nonResourceURLs: ["/metrics"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ${SA}-metrics
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ${SA}-metrics
subjects:
  - kind: ServiceAccount
    name: ${SA}
    namespace: ${NAMESPACE}
YAML
  say "rbac: ${SA} granted read-only /metrics (for prometheus; no other cluster grant)"

  # ---- kubeconfig for the API container --------------------------------
  # Point at the kind-network address, not the host loopback. The apiserver
  # certificate carries that IP as a SAN, so TLS verifies properly. Connecting
  # through host.docker.internal would need hostname verification turned off,
  # which is exactly the kind of shortcut this project should not take.
  cp_ip=$(docker inspect "${CLUSTER}-control-plane" \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
  ca_b64=$(kubectl config view --raw --minify \
    -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
  printf '%s' "${ca_b64}" | base64 -d > "${STATE_DIR}/ca.crt"
  token=$(kubectl -n "${NAMESPACE}" create token "${SA}" --duration=24h)

  cat > "${KUBECONFIG_OUT}" <<YAML
apiVersion: v1
kind: Config
clusters:
  - name: proofops
    cluster:
      server: https://${cp_ip}:6443
      certificate-authority: /live/ca.crt
contexts:
  - name: live
    context: {cluster: proofops, user: ${SA}, namespace: ${NAMESPACE}}
current-context: live
users:
  - name: ${SA}
    user:
      token: ${token}
YAML
  # Prometheus needs the same credential to scrape the apiserver, and it is not
  # running in-cluster, so it cannot use a projected service-account token.
  printf '%s' "${token}" > "${STATE_DIR}/token"
  say "kubeconfig -> ${KUBECONFIG_OUT} (server https://${cp_ip}:6443, TLS verified)"

  # ---- kube-state-metrics ------------------------------------------------
  # The real state of real workloads. Without it the only metrics in Prometheus
  # describe the apiserver, so a verifier asking "are N/N replicas available?"
  # has nothing real to query and is pushed back onto the mock's own opinion --
  # which is the dishonesty this project is arguing against.
  if kubectl get clusterrole proofops-kube-state-metrics >/dev/null 2>&1; then
    say "reconciling kube-state-metrics RBAC (read set drifts as versions add kinds)"
  else
    say "deploying kube-state-metrics (real workload state)"
  fi
  # Applied unconditionally: `apply` is the reconciliation. Gating it on
  # "does it exist" meant a change to the read set or to hostNetwork was never
  # applied to an already-present install.
  kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kube-state-metrics
  namespace: ${NAMESPACE}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: proofops-kube-state-metrics
rules:
  - apiGroups: [""]
    resources: ["configmaps", "endpoints", "pods", "secrets", "services",
                "limitranges", "persistentvolumeclaims", "replicationcontrollers",
                "resourcequotas", "serviceaccounts", "nodes"]
    verbs: ["list", "watch"]
  - apiGroups: ["apps"]
    resources: ["daemonsets", "deployments", "replicasets", "statefulsets"]
    verbs: ["list", "watch"]
  - apiGroups: ["batch"]
    resources: ["cronjobs", "jobs"]
    verbs: ["list", "watch"]
  - apiGroups: ["autoscaling"]
    resources: ["horizontalpodautoscalers"]
    verbs: ["list", "watch"]
  - apiGroups: ["policy"]
    resources: ["poddisruptionbudgets"]
    verbs: ["list", "watch"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["storageclasses", "volumeattachments"]
    verbs: ["list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: proofops-kube-state-metrics
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: proofops-kube-state-metrics
subjects:
  - kind: ServiceAccount
    name: kube-state-metrics
    namespace: ${NAMESPACE}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kube-state-metrics
  namespace: ${NAMESPACE}
  labels: {app: kube-state-metrics}
spec:
  replicas: 1
  selector:
    matchLabels: {app: kube-state-metrics}
  template:
    metadata:
      labels: {app: kube-state-metrics}
    spec:
      serviceAccountName: kube-state-metrics
      # Host networking so the metrics endpoint lands on the node address, which
      # is reachable from the Prometheus container on the kind docker network. A
      # Kubernetes Service is only resolvable from inside the cluster, and
      # Prometheus runs outside it, so without this the target is unresolvable.
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      containers:
        - name: kube-state-metrics
          image: registry.k8s.io/kube-state-metrics/kube-state-metrics:v2.13.0
          args: ["--port=8080"]
          ports: [{name: http, containerPort: 8080}]
          resources:
            requests: {cpu: 10m, memory: 32Mi}
---
apiVersion: v1
kind: Service
metadata:
  name: kube-state-metrics
  namespace: ${NAMESPACE}
spec:
  selector: {app: kube-state-metrics}
  ports: [{name: http, port: 8080, targetPort: 8080}]
YAML
  kubectl -n "${NAMESPACE}" rollout status deploy/kube-state-metrics \
    --timeout=180s >/dev/null 2>&1 \
    || say "  (kube-state-metrics not ready yet; continuing)"

  # ---- prometheus ------------------------------------------------------
  # The apiserver address is templated in, so the config always points at the
  # cluster this script just built rather than a stale IP. kube-state-metrics
  # runs host-networked, so it answers on the node address too.
  sed -e "s|__APISERVER__|${cp_ip}:6443|" -e "s|__KUBE_STATE_METRICS__|${cp_ip}:8080|" \
    telemetry/prometheus.yml > "${STATE_DIR}/prometheus.yml"

  if docker ps --format '{{.Names}}' | grep -qx "${PROM_CONTAINER}"; then
    say "reconfiguring prometheus"
    docker rm -f "${PROM_CONTAINER}" >/dev/null 2>&1 || true
  fi
  say "starting real prometheus on :${PROM_PORT} (scraping ${cp_ip}:6443)"
  docker run -d --name "${PROM_CONTAINER}" \
    --network "${NETWORK}" \
    -p "${PROM_PORT}:${PROM_NET_PORT}" \
    -v "${PWD}/${STATE_DIR}:/live:ro" \
    prom/prometheus:latest \
    --config.file=/live/prometheus.yml \
    --storage.tsdb.retention.time=2h >/dev/null
  say "prometheus -> http://host.docker.internal:${PROM_PORT}"
  status
}

# Report only what is actually true right now. No green ticks for things that
# are not connected: a badge that lies is worse than a badge that is amber.
status() {
  printf '\n  === live tier status ===\n'
  if kind get clusters 2>/dev/null | grep -qx "${CLUSTER}"; then
    node=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo '?')
    ver=$(kubectl version -o json 2>/dev/null \
      | grep -o '"gitVersion": *"[^"]*"' | head -1 | cut -d'"' -f4)
    say "kubernetes : REAL   ${CLUSTER} (${ver:-unknown}) node=${node}"
  else
    say "kubernetes : OFF    no kind cluster"
  fi

  sa="system:serviceaccount:${NAMESPACE}:${SA}"
  if kubectl auth can-i patch deployments --as="${sa}" -n "${NAMESPACE}" >/dev/null 2>&1; then
    can_scale=$(kubectl auth can-i patch deployments --as="${sa}" -n "${NAMESPACE}" 2>/dev/null || echo no)
    can_del=$(kubectl auth can-i delete namespaces --as="${sa}" 2>/dev/null || echo no)
    can_sec=$(kubectl auth can-i get secrets --as="${sa}" -n "${NAMESPACE}" 2>/dev/null || echo no)
    say "rbac        : scale=${can_scale}  delete_namespace=${can_del}  read_secrets=${can_sec}"
  fi

  if curl -sf "http://127.0.0.1:${PROM_PORT}/-/ready" >/dev/null 2>&1; then
    targets=$(curl -sf "http://127.0.0.1:${PROM_PORT}/api/v1/targets" 2>/dev/null \
      | grep -o '"health":"[a-z]*"' | sort | uniq -c | tr '\n' ' ')
    say "prometheus  : REAL   :${PROM_PORT} targets: ${targets:-none}"
  else
    say "prometheus  : OFF    not responding on :${PROM_PORT}"
  fi
  printf '\n'
}

down() {
  say "removing prometheus"
  docker rm -f "${PROM_CONTAINER}" >/dev/null 2>&1 || true
  say "deleting kind cluster '${CLUSTER}'"
  kind delete cluster --name "${CLUSTER}" >/dev/null 2>&1 || true
  say "done"
}

case "${1:-up}" in
  up) up ;;
  status) status ;;
  down) down ;;
  *) fail "usage: bash scripts/live_tier.sh {up|status|down}" ;;
esac
