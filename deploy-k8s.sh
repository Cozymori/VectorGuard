#!/usr/bin/env bash
# =============================================================================
# VectorGuard Kubernetes Deployer
# =============================================================================
# Usage:
#   ./deploy-k8s.sh [OPTIONS]
#
# Options:
#   --namespace  NS       Target namespace (default: vectorguard)
#   --helm                Use Helm (default if helm is available)
#   --kubectl             Use raw kubectl manifests
#   --adapter    BACKEND  Adapter backend: tetragon|falco|auditd|native_ebpf
#                         (default: tetragon)
#   --tetragon-endpoint URL  Tetragon gRPC endpoint
#   --include-ns NS,...   Comma-separated K8s namespaces to monitor
#   --exclude-ns NS,...   Comma-separated K8s namespaces to exclude
#   --no-qdrant           Skip Qdrant deployment
#   --image      IMAGE    Custom image (default: ghcr.io/cozymori/vectorguard:latest)
#   --dry-run             Print what would be applied without applying
#   --uninstall           Remove VectorGuard from the cluster
# =============================================================================
set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
NAMESPACE="vectorguard"
USE_HELM=""
ADAPTER="tetragon"
TETRAGON_ENDPOINT="http://tetragon.kube-system.svc.cluster.local:54321"
INCLUDE_NS=""
EXCLUDE_NS="kube-system,kube-public,kube-node-lease"
NO_QDRANT=0
IMAGE="ghcr.io/cozymori/vectorguard:latest"
DRY_RUN=0
UNINSTALL=0
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Color output ──────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${BLUE}[INFO]${RESET}  $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
die()     { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }
section() { echo -e "\n${BOLD}══ $* ══${RESET}"; }

# ── Arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace)         NAMESPACE="$2"; shift ;;
    --helm)              USE_HELM=1 ;;
    --kubectl)           USE_HELM=0 ;;
    --adapter)           ADAPTER="$2"; shift ;;
    --tetragon-endpoint) TETRAGON_ENDPOINT="$2"; shift ;;
    --include-ns)        INCLUDE_NS="$2"; shift ;;
    --exclude-ns)        EXCLUDE_NS="$2"; shift ;;
    --no-qdrant)         NO_QDRANT=1 ;;
    --image)             IMAGE="$2"; shift ;;
    --dry-run)           DRY_RUN=1 ;;
    --uninstall)         UNINSTALL=1 ;;
    -h|--help)
      sed -n '/^# Usage/,/^# ===/p' "$0" | grep -v "^# ===" | sed 's/^# //'
      exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
  shift
done

# ── Tool detection ────────────────────────────────────────────────────────────
section "Detecting tools"

command -v kubectl &>/dev/null || die "kubectl not found. Install kubectl first."
ok "kubectl: $(kubectl version --client --short 2>/dev/null | head -1)"

# Check cluster connectivity
kubectl cluster-info &>/dev/null || die "Cannot connect to K8s cluster. Check your kubeconfig."
CONTEXT=$(kubectl config current-context 2>/dev/null || echo "unknown")
ok "Cluster context: $CONTEXT"

# Auto-detect Helm preference
if [[ -z "$USE_HELM" ]]; then
  if command -v helm &>/dev/null; then
    USE_HELM=1
  else
    USE_HELM=0
  fi
fi

if [[ $USE_HELM -eq 1 ]]; then
  command -v helm &>/dev/null || die "helm not found. Install helm or use --kubectl flag."
  ok "helm: $(helm version --short 2>/dev/null)"
fi

# ── Uninstall ─────────────────────────────────────────────────────────────────
if [[ $UNINSTALL -eq 1 ]]; then
  section "Uninstalling VectorGuard from namespace: $NAMESPACE"

  if [[ $USE_HELM -eq 1 ]]; then
    helm uninstall vectorguard -n "$NAMESPACE" 2>/dev/null && ok "Helm release removed" \
      || warn "Helm release not found"
  else
    kubectl delete -f "$SCRIPT_DIR/deploy/k8s/" --ignore-not-found -n "$NAMESPACE" 2>/dev/null || true
    ok "K8s resources removed"
  fi

  read -rp "Delete namespace '$NAMESPACE'? [y/N] " yn
  if [[ "${yn,,}" == "y" ]]; then
    kubectl delete namespace "$NAMESPACE" --ignore-not-found
    ok "Namespace deleted"
  fi
  exit 0
fi

# ── Convert comma lists → JSON arrays ─────────────────────────────────────────
csv_to_json_array() {
  local csv="$1"
  if [[ -z "$csv" ]]; then echo "[]"; return; fi
  echo "$csv" | tr ',' '\n' | awk 'NF{print "\""$0"\""}' | paste -sd',' | sed 's/^/[/;s/$/]/'
}

INCLUDE_NS_JSON=$(csv_to_json_array "$INCLUDE_NS")
EXCLUDE_NS_JSON=$(csv_to_json_array "$EXCLUDE_NS")

# ── Apply ─────────────────────────────────────────────────────────────────────
APPLY_CMD="kubectl apply"
[[ $DRY_RUN -eq 1 ]] && APPLY_CMD="kubectl apply --dry-run=client"

# ── Deploy with Helm ──────────────────────────────────────────────────────────
deploy_helm() {
  section "Deploying with Helm"

  HELM_ARGS=(
    upgrade --install vectorguard
    "$SCRIPT_DIR/deploy/helm/vectorguard"
    --namespace "$NAMESPACE"
    --create-namespace
    --set "image.repository=$(echo "$IMAGE" | cut -d: -f1)"
    --set "image.tag=$(echo "$IMAGE" | cut -d: -f2)"
    --set "config.adapter.backend=$ADAPTER"
    --set "config.adapter.tetragon.endpoint=$TETRAGON_ENDPOINT"
  )

  # Scope
  [[ -n "$INCLUDE_NS" ]] && {
    IFS=',' read -ra NS_ARR <<< "$INCLUDE_NS"
    for i in "${!NS_ARR[@]}"; do
      HELM_ARGS+=("--set" "config.scope.includeNamespaces[$i]=${NS_ARR[$i]}")
    done
  }
  IFS=',' read -ra EX_ARR <<< "$EXCLUDE_NS"
  for i in "${!EX_ARR[@]}"; do
    HELM_ARGS+=("--set" "config.scope.excludeNamespaces[$i]=${EX_ARR[$i]}")
  done

  [[ $NO_QDRANT -eq 1 ]] && HELM_ARGS+=("--set" "qdrant.enabled=false")
  [[ $DRY_RUN  -eq 1 ]] && HELM_ARGS+=("--dry-run")

  info "Running: helm ${HELM_ARGS[*]}"
  helm "${HELM_ARGS[@]}"
}

# ── Deploy with kubectl ───────────────────────────────────────────────────────
deploy_kubectl() {
  section "Deploying with kubectl"

  # Namespace
  $APPLY_CMD -f "$SCRIPT_DIR/deploy/k8s/namespace.yaml"

  # Patch and apply ConfigMap (inject scope settings)
  TMP_CM=$(mktemp /tmp/vectorguard-cm-XXXXXX.yaml)
  cp "$SCRIPT_DIR/deploy/k8s/configmap.yaml" "$TMP_CM"
  # Update adapter backend and scope inside the configmap data
  sed -i "s|backend = \"tetragon\"|backend = \"$ADAPTER\"|" "$TMP_CM"

  $APPLY_CMD -f "$TMP_CM"
  rm "$TMP_CM"

  $APPLY_CMD -f "$SCRIPT_DIR/deploy/k8s/rbac.yaml"

  [[ $NO_QDRANT -eq 0 ]] && $APPLY_CMD -f "$SCRIPT_DIR/deploy/k8s/qdrant.yaml"

  # Patch DaemonSet image
  TMP_DS=$(mktemp /tmp/vectorguard-ds-XXXXXX.yaml)
  sed "s|ghcr.io/cozymori/vectorguard:latest|$IMAGE|g" \
    "$SCRIPT_DIR/deploy/k8s/daemonset.yaml" > "$TMP_DS"
  $APPLY_CMD -f "$TMP_DS"
  rm "$TMP_DS"
}

if [[ $USE_HELM -eq 1 ]]; then
  deploy_helm
else
  deploy_kubectl
fi

# ── Wait for rollout ──────────────────────────────────────────────────────────
if [[ $DRY_RUN -eq 0 ]]; then
  section "Waiting for rollout"
  info "Waiting for DaemonSet to be ready (timeout: 120s)..."
  kubectl rollout status daemonset/vectorguard -n "$NAMESPACE" --timeout=120s \
    && ok "DaemonSet rollout complete" \
    || warn "Rollout timed out — check: kubectl get pods -n $NAMESPACE"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
section "Deployment complete"
echo -e "
  ${BOLD}VectorGuard deployed to namespace: $NAMESPACE${RESET}
  Adapter:            $ADAPTER
  Include namespaces: ${INCLUDE_NS:-<all>}
  Exclude namespaces: $EXCLUDE_NS
  Qdrant:             $([ $NO_QDRANT -eq 1 ] && echo disabled || echo enabled)
  Image:              $IMAGE

  ${BOLD}Useful commands:${RESET}
    Pod status:    kubectl get pods -n $NAMESPACE
    Logs:          kubectl logs -n $NAMESPACE -l app.kubernetes.io/name=vectorguard -f
    Config reload: kubectl rollout restart daemonset/vectorguard -n $NAMESPACE
    Uninstall:     ./deploy-k8s.sh --uninstall

  ${BOLD}Scope configuration (edit values then re-run this script):${RESET}
    Monitor only 'production' namespace:
      ./deploy-k8s.sh --include-ns production

    Monitor all except system namespaces:
      ./deploy-k8s.sh --exclude-ns kube-system,kube-public,monitoring
"
