#!/usr/bin/env bash
# deploy-zen.sh — Build the mcpgateway image locally and deploy it to any Kubernetes/OCP cluster and namespace.
#
# Usage:
#   ./scripts/deploy-zen.sh [IMAGE_TAG]
#
# Environment variables that can be overridden (or defined in .env.local):
#   IMAGE_TAG       The tag of the image to build and deploy (default: zen-jwt)
#   NAMESPACE       The target namespace (default: mcp-gateway)
#   OCP_REGISTRY    The registry URL to push the image to (auto-detected on OpenShift)
#   DEPLOYMENT      The target deployment name (auto-detected if mcpgateway deployment exists)
#   CONTAINER       The container name in the deployment (default: mcp-context-forge)
#   INTERNAL_IMAGE  The internal image path pulled by the pods (auto-configured)
#   HELM_RELEASE    The helm release name to upgrade (default: mcp-gateway)
#
# Prerequisites:
#   - docker (or podman aliased to docker)
#   - oc or kubectl CLI logged into the cluster
#   - Containerfile present at project root

set -euo pipefail

# ── Helpers ───────────────────────────────────────────────────────────────────
log()  { echo "▸ $*"; }
ok()   { echo "✅ $*"; }
fail() { echo "❌ $*" >&2; exit 1; }

# ── Find Project Root ─────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ── Load local environment file if present ────────────────────────────────────
if [ -f "${PROJECT_ROOT}/.env.local" ]; then
  log "Loading configuration from .env.local..."
  set -a
  source "${PROJECT_ROOT}/.env.local"
  set +a
elif [ -f "${PROJECT_ROOT}/.env" ]; then
  log "Loading configuration from .env..."
  set -a
  source "${PROJECT_ROOT}/.env"
  set +a
fi

# ── Preflight checks ──────────────────────────────────────────────────────────
log "Checking prerequisites..."
command -v docker >/dev/null 2>&1 || fail "docker not found"

if command -v oc >/dev/null 2>&1; then
  KCLI="oc"
elif command -v kubectl >/dev/null 2>&1; then
  KCLI="kubectl"
else
  fail "Neither oc nor kubectl CLI found. Please install one of them."
fi

log "Using CLI tool: ${KCLI}"

# ── Configuration ────────────────────────────────────────────────────────────
IMAGE_TAG="${1:-${IMAGE_TAG:-zen-jwt}}"
NAMESPACE="${NAMESPACE:-mcp-gateway}"

# Auto-detect OpenShift image registry route if using OpenShift
AUTO_REGISTRY=""
if [ "${KCLI}" = "oc" ]; then
  AUTO_REGISTRY=$(oc get route default-route -n openshift-image-registry -o jsonpath='{.spec.host}' 2>/dev/null || echo "")
fi

OCP_REGISTRY="${OCP_REGISTRY:-${AUTO_REGISTRY}}"
if [ -z "${OCP_REGISTRY}" ]; then
  if [ "${KCLI}" = "oc" ]; then
    OCP_REGISTRY="default-route-openshift-image-registry.apps.mycluster.example.com"
  else
    OCP_REGISTRY="docker.io"
  fi
fi

# Auto-detect deployment name
AUTO_DEPLOYMENT=$(${KCLI} get deployment -n "${NAMESPACE}" -o name 2>/dev/null | grep mcpgateway | head -n1 | cut -d'/' -f2 || echo "")
DEPLOYMENT="${DEPLOYMENT:-${AUTO_DEPLOYMENT}}"
if [ -z "${DEPLOYMENT}" ]; then
  DEPLOYMENT="mcp-gateway-mcp-stack-mcpgateway"
fi

CONTAINER="${CONTAINER:-mcp-context-forge}"
LOCAL_IMAGE="mcpgateway/mcpgateway:${IMAGE_TAG}"
REMOTE_IMAGE="${OCP_REGISTRY}/${NAMESPACE}/mcpgateway:${IMAGE_TAG}"

if [ -z "${INTERNAL_IMAGE:-}" ]; then
  if [ "${KCLI}" = "oc" ] || [[ "${OCP_REGISTRY}" == *openshift* ]]; then
    INTERNAL_IMAGE="image-registry.openshift-image-registry.svc:5000/${NAMESPACE}/mcpgateway:${IMAGE_TAG}"
  else
    INTERNAL_IMAGE="${REMOTE_IMAGE}"
  fi
fi

CONTAINER_FILE="${CONTAINER_FILE:-Containerfile}"

# Verify active session
if [ "${KCLI}" = "oc" ]; then
  oc whoami >/dev/null 2>&1 || fail "Not logged into OCP cluster — run: oc login <api-url>"
  KUSER=$(oc whoami)
else
  kubectl cluster-info >/dev/null 2>&1 || fail "Cannot communicate with Kubernetes cluster — verify your kubeconfig"
  KUSER="k8s-user"
fi

log "Cluster user: ${KUSER}"
log "Namespace:    ${NAMESPACE}"
log "Image tag:    ${IMAGE_TAG}"
log "Deployment:   ${DEPLOYMENT}"
log "Registry:     ${OCP_REGISTRY}"
log "Remote Image: ${REMOTE_IMAGE}"
log "Pull Image:   ${INTERNAL_IMAGE}"

# ── Step 1 — Build image ──────────────────────────────────────────────────────
log "Building image ${LOCAL_IMAGE} from ${CONTAINER_FILE}..."
cd "${PROJECT_ROOT}"
docker build \
  --platform linux/amd64 \
  -f "${CONTAINER_FILE}" \
  --build-arg ENABLE_RUST=false \
  --build-arg ENABLE_RUST_MCP_RMCP=false \
  --build-arg ENABLE_PROFILING=false \
  -t "${LOCAL_IMAGE}" \
  .
ok "Image built: ${LOCAL_IMAGE}"

# ── Step 2 — Login to OCP image registry ─────────────────────────────────────
if [ "${KCLI}" = "oc" ]; then
  log "Logging into OCP registry ${OCP_REGISTRY}..."
  if oc whoami -t >/dev/null 2>&1; then
    oc whoami -t | docker login "${OCP_REGISTRY}" -u unused --password-stdin
    ok "Registry login successful"
  else
    log "Could not obtain token with 'oc whoami -t'. Skipping registry login (assuming already authenticated)."
  fi
else
  log "Skipping OCP registry login (assuming already authenticated to ${OCP_REGISTRY})."
fi

# ── Step 3 — Tag and push ─────────────────────────────────────────────────────
log "Tagging as ${REMOTE_IMAGE}..."
docker tag "${LOCAL_IMAGE}" "${REMOTE_IMAGE}"

log "Pushing to cluster registry..."
docker push "${REMOTE_IMAGE}"
ok "Image pushed: ${REMOTE_IMAGE}"

# ── Step 4 (Optional) — Run Helm upgrade if personal values file exists ───────
HELM_CHART="charts/mcp-stack"
HELM_RELEASE="${HELM_RELEASE:-mcp-gateway}"
PERSONAL_VALUES=""

# Search for personal values file
if [ -f "${PROJECT_ROOT}/${HELM_CHART}/values-personal.yaml" ]; then
  PERSONAL_VALUES="${PROJECT_ROOT}/${HELM_CHART}/values-personal.yaml"
elif [ -f "${PROJECT_ROOT}/${HELM_CHART}/values-local.yaml" ]; then
  PERSONAL_VALUES="${PROJECT_ROOT}/${HELM_CHART}/values-local.yaml"
elif [ -f "${PROJECT_ROOT}/values-personal.yaml" ]; then
  PERSONAL_VALUES="${PROJECT_ROOT}/values-personal.yaml"
elif [ -f "${PROJECT_ROOT}/values-local.yaml" ]; then
  PERSONAL_VALUES="${PROJECT_ROOT}/values-local.yaml"
fi

if [ -n "${PERSONAL_VALUES}" ] && command -v helm >/dev/null 2>&1; then
  log "Found personal Helm values file: ${PERSONAL_VALUES}"
  log "Running helm upgrade..."
  helm upgrade --install "${HELM_RELEASE}" "${PROJECT_ROOT}/${HELM_CHART}" \
    -f "${PROJECT_ROOT}/${HELM_CHART}/values.yaml" \
    -f "${PERSONAL_VALUES}" \
    -n "${NAMESPACE}"
  ok "Helm release upgraded successfully"
elif [ -n "${PERSONAL_VALUES}" ]; then
  log "Found personal values file ${PERSONAL_VALUES} but helm CLI was not found. Skipping Helm upgrade."
else
  log "No personal values-personal.yaml or values-local.yaml found. Skipping automatic Helm upgrade."
fi

# ── Step 5 — Set image & rollout ─────────────────────────────────────────────
log "Updating deployment image to ${INTERNAL_IMAGE}..."
# First verify deployment exists before attempting to set image
if ${KCLI} get deployment "${DEPLOYMENT}" -n "${NAMESPACE}" >/dev/null 2>&1; then
  ${KCLI} set image deployment/"${DEPLOYMENT}" \
    "${CONTAINER}=${INTERNAL_IMAGE}" \
    -n "${NAMESPACE}"
  ok "Deployment image patched to ${INTERNAL_IMAGE}"

  # ── Step 6 — Wait for rollout ─────────────────────────────────────────────────
  log "Waiting for rollout to complete..."
  ${KCLI} rollout status deployment/"${DEPLOYMENT}" -n "${NAMESPACE}" --timeout=180s
  ok "Rollout complete"

  # ── Step 7 — Verify ───────────────────────────────────────────────────────────
  log "Running pods:"
  ${KCLI} get pods -n "${NAMESPACE}" | grep "${DEPLOYMENT##*-}" | grep -v build || true

  echo ""
  log "Verifying SSO_ZEN_ENABLED in pod env..."
  ${KCLI} exec -n "${NAMESPACE}" deployment/"${DEPLOYMENT}" -- env 2>/dev/null | grep "SSO_ZEN\|SSO_ENABLED" | sort || true
else
  log "Deployment '${DEPLOYMENT}' not found in namespace '${NAMESPACE}'. Skipping image set and rollout verification (make sure Helm deployed it first)."
fi

echo ""
ok "Deploy done — image ${IMAGE_TAG} is live"
