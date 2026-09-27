#!/usr/bin/env bash
# Provision the real live tier: a genuine Kubernetes API server, a genuine
# Prometheus, and a genuine instrumented workload -- all on this machine, with no
# cloud account and no credentials.
#
# Why KIND rather than a real cloud account: the safety claims this project makes
# are about the control plane, not about whose cloud it runs in. KIND gives real
# API-server authorization, so `delete namespace` is refused by actual Kubernetes
# rather than only by our policy engine. Two independent boundaries, no billing,
# no keys, and it runs offline for a demo.
#
# What it creates:
#   - kind cluster (real API server, real RBAC)
#   - namespace proofops-demo with a deployment to act on
#   - ServiceAccount + namespaced Role: may read and scale workloads, and is
#     structurally unable to delete namespaces, read secrets, or mutate RBAC
#   - kube-state-metrics, so the real state of real workloads is measurable
#   - an instrumented demo workload that returns 5xx while unhealthy and
#     publishes the error rate the verifier's SLO already asks for
#   - a Prometheus scraping all of the above
#
# Usage:  bash scripts/live_tier.sh up      # provision everything
#         bash scripts/live_tier.sh status  # report what is real right now
#         bash scripts/live_tier.sh down    # tear down
set -euo pipefail

# On a Windows host under Git Bash, MSYS rewrites any argument that looks like a
# POSIX absolute path into a Windows one, so /live/prometheus.yml becomes
# C:/Program Files/Git/live/prometheus.yml and Prometheus cannot find its own
# config. Disabling the conversion is the fix.
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
#: Ports on the node address. Prometheus runs on the kind *docker* network, which
#: cannot route to the CNI pod network, so everything it scrapes is host-networked
#: and addressed by the node IP. kube-state-metrics keeps 8080 and also binds 8081 for its own self-signed
#: endpoint, so the demo workload takes 8082 to avoid a host-port collision.
KSM_PORT=8080
DEMO_PORT=8082

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
  kubectl config use-context "kind-${CLUSTER}" >/dev/null

  cp_ip=$(docker inspect "${CLUSTER}-control-plane" \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
  say "node address ${cp_ip}"

  # ---- the workload an incident acts on ----------------------------------
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
  # The policy engine already denies destructive actions, but that is our own code
  # reasoning about our own inputs -- necessary, not sufficient. This Role makes
  # the *cluster* refuse independently.
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
  say "rbac: ${SA} may read+scale workloads; delete/secrets/rbac NOT granted"

  # Prometheus reads the apiserver's /metrics, a non-resource URL denied by
  # default (hence the 403 it originally returned). Smallest possible grant:
  # read-only, one path, and it widens no namespaced permission.
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
  say "rbac: ${SA} granted read-only /metrics for prometheus"

  # ---- kubeconfig for the API container ----------------------------------
  # Point at the node address, not host loopback: it is a SAN on the apiserver
  # certificate, so TLS verifies for real. Going via host.docker.internal would
  # require disabling verification, which this project should never do.
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
  printf '%s' "${token}" > "${STATE_DIR}/token"
  say "kubeconfig -> ${KUBECONFIG_OUT} (https://${cp_ip}:6443, TLS verified)"

  # ---- the instrumented demo workload -----------------------------------
  # A real service that returns 5xx while unhealthy and publishes the error rate
  # the verifier's SLO already asks for. Without it the error-rate check has no
  # real signal and rides the fallback path -- one honest check resting on
  # nothing, which is the same defect as having no check at all.
  say "building and loading the instrumented demo workload"
  docker build -q -f telemetry/demo_service.Dockerfile \
    -t proofops-demo-service:latest . >/dev/null
  kind load docker-image proofops-demo-service:latest --name "${CLUSTER}" >/dev/null

  # Applied unconditionally: `apply` is the reconciliation. Gating on "does it
  # exist" meant a changed port or hostNetwork was silently never applied to an
  # already-present install.
  kubectl -n "${NAMESPACE}" apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-service
  namespace: ${NAMESPACE}
  labels: {app: demo-service}
spec:
  # One replica on the host network: two pods cannot share a host port, and at
  # this scale the point is a measurable signal, not throughput.
  replicas: 1
  selector:
    matchLabels: {app: demo-service}
  template:
    metadata:
      labels: {app: demo-service}
    spec:
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      containers:
        - name: demo-service
          image: proofops-demo-service:latest
          imagePullPolicy: Never
          ports: [{name: http, containerPort: ${DEMO_PORT}}]
          env:
            - {name: DEMO_SERVICE, value: checkout-api}
            - {name: DEMO_FAIL_RATE, value: "1.0"}
            - {name: PORT, value: "${DEMO_PORT}"}
          resources:
            requests: {cpu: 10m, memory: 24Mi}
          readinessProbe:
            httpGet: {path: /healthz, port: ${DEMO_PORT}}
            initialDelaySeconds: 2
---
apiVersion: v1
kind: Service
metadata:
  name: demo-service
  namespace: ${NAMESPACE}
spec:
  selector: {app: demo-service}
  ports: [{name: http, port: ${DEMO_PORT}, targetPort: ${DEMO_PORT}}]
YAML
  kubectl -n "${NAMESPACE}" rollout status deploy/demo-service \
    --timeout=180s >/dev/null 2>&1 \
    || say "  (demo-service not ready yet; continuing)"

  # ---- kube-state-metrics ------------------------------------------------
  # The real state of real workloads. Without it the only metrics describe the
  # apiserver, so "are N/N replicas available?" has no real answer and the
  # verifier is pushed back onto the mock's own opinion.
  if kubectl get clusterrole proofops-kube-state-metrics >/dev/null 2>&1; then
    say "reconciling kube-state-metrics RBAC (read set drifts as versions add kinds)"
  else
    say "deploying kube-state-metrics (real workload state)"
  fi
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
                "limitranges", "persistentvolumeclaims",
                "replicationcontrollers", "resourcequotas", "serviceaccounts",
                "nodes"]
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
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      containers:
        - name: kube-state-metrics
          image: registry.k8s.io/kube-state-metrics/kube-state-metrics:v2.13.0
          args: ["--port=${KSM_PORT}"]
          ports: [{name: http, containerPort: ${KSM_PORT}}]
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
  ports: [{name: http, port: ${KSM_PORT}, targetPort: ${KSM_PORT}}]
YAML
  kubectl -n "${NAMESPACE}" rollout status deploy/kube-state-metrics \
    --timeout=180s >/dev/null 2>&1 \
    || say "  (kube-state-metrics not ready yet; continuing)"

  # ---- prometheus -------------------------------------------------------
  # Addresses are templated in, so the config always points at the cluster this
  # script just built rather than a stale IP.
  sed -e "s|__APISERVER__|${cp_ip}:6443|" \
      -e "s|__KUBE_STATE_METRICS__|${cp_ip}:${KSM_PORT}|" \
      -e "s|__DEMO_SERVICE__|${cp_ip}:${DEMO_PORT}|" \
    telemetry/prometheus.yml > "${STATE_DIR}/prometheus.yml"

  if docker ps --format '{{.Names}}' | grep -qx "${PROM_CONTAINER}"; then
    say "reconfiguring prometheus"
    docker rm -f "${PROM_CONTAINER}" >/dev/null 2>&1 || true
  fi
  say "starting real prometheus on :${PROM_PORT}"
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
    can_del=$(kubectl auth can-i delete namespaces --as="${sa}" 2>/dev/null | tail -1 || echo no)
    can_sec=$(kubectl auth can-i get secrets --as="${sa}" -n "${NAMESPACE}" 2>/dev/null || echo no)
    say "rbac        : scale=${can_scale}  delete_namespace=${can_del}  read_secrets=${can_sec}"
  fi

  if curl -sf "http://127.0.0.1:${PROM_PORT}/-/ready" >/dev/null 2>&1; then
    targets=$(curl -sf "http://127.0.0.1:${PROM_PORT}/api/v1/targets" 2>/dev/null \
      | grep -o '"health":"[a-z]*"' | sort | uniq -c | tr '\n' ' ')
    say "prometheus  : REAL   :${PROM_PORT} targets: ${targets:-none}"
    # The signal that decides whether verification is real or assumed.
    err=$(curl -sf --get --data-urlencode \
      'query=sum(rate(http_requests_total{status=~"5.."}[2m])) / sum(rate(http_requests_total[2m]))' \
      "http://127.0.0.1:${PROM_PORT}/api/v1/query" 2>/dev/null \
      | grep -o '"value":\["[^"]*","[0-9.e-]*"\]' | tail -1 \
      | sed 's/.*,"//; s/"\]//' || true)
    if [ -n "${err}" ]; then
      say "error rate  : MEASURED  ${err} (from the instrumented workload)"
    else
      say "error rate  : UNMEASURED  no series yet; verification will refuse RESOLVED"
    fi
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
