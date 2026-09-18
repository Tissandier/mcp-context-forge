#!/usr/bin/env bash
# deploy-zen.sh — Build the mcpgateway image locally and deploy it to the OCP cluster.
#
# Usage:
#   ./scripts/deploy-zen.sh [IMAGE_TAG]
#
# Defaults:
#   IMAGE_TAG       zen-jwt
#   NAMESPACE       mcp-gateway
#   DEPLOYMENT      mcp-gateway-mcp-stack-mcpgateway
#   CONTAINER       mcp-context-forge
#   OCP_REGISTRY    default-route-openshift-image-registry.apps.manutiss.cp.fyre.ibm.com
#   HELM_RELEASE    mcp-gateway-mcp-stack
#   HELM_CHART      charts/mcp-stack
#
# Prerequisites:
#   - docker (or podman aliased to docker)
#   - oc CLI logged into the cluster (oc login ...)
#   - helm CLI (optional — used for values sync; skipped if not found)
#   - Containerfile.lite present at project root

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
IMAGE_TAG="${1:-zen-jwt}"
NAMESPACE="mcp-gateway"
DEPLOYMENT="mcp-gateway-mcp-stack-mcpgateway"
CONTAINER="mcp-context-forge"
LOCAL_IMAGE="mcpgateway/mcpgateway:${IMAGE_TAG}"
OCP_REGISTRY="default-route-openshift-image-registry.apps.manutiss.cp.fyre.ibm.com"
REMOTE_IMAGE="${OCP_REGISTRY}/${NAMESPACE}/mcpgateway:${IMAGE_TAG}"
INTERNAL_IMAGE="image-registry.openshift-image-registry.svc:5000/${NAMESPACE}/mcpgateway:${IMAGE_TAG}"
CONTAINER_FILE="${CONTAINER_FILE:-Containerfile}"
HELM_RELEASE="mcp-gateway"
HELM_CHART="charts/mcp-stack"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ── Helpers ───────────────────────────────────────────────────────────────────
log()  { echo "▸ $*"; }
ok()   { echo "✅ $*"; }
fail() { echo "❌ $*" >&2; exit 1; }

# ── Preflight checks ──────────────────────────────────────────────────────────
log "Checking prerequisites..."
command -v docker >/dev/null 2>&1 || fail "docker not found"
command -v oc     >/dev/null 2>&1 || fail "oc CLI not found — run: oc login <api-url>"
oc whoami >/dev/null 2>&1         || fail "Not logged into OCP cluster — run: oc login <api-url>"

OCP_USER=$(oc whoami)
log "OCP user:   ${OCP_USER}"
log "Namespace:  ${NAMESPACE}"
log "Image tag:  ${IMAGE_TAG}"

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
log "Logging into OCP registry ${OCP_REGISTRY}..."
oc whoami -t | docker login "${OCP_REGISTRY}" -u unused --password-stdin
ok "Registry login successful"

# ── Step 3 — Tag and push ─────────────────────────────────────────────────────
log "Tagging as ${REMOTE_IMAGE}..."
docker tag "${LOCAL_IMAGE}" "${REMOTE_IMAGE}"

log "Pushing to cluster registry..."
docker push "${REMOTE_IMAGE}"
ok "Image pushed: ${REMOTE_IMAGE}"

# ── Step 4 — Set image & rollout ─────────────────────────────────────────────
log "Updating deployment image to ${INTERNAL_IMAGE}..."
oc set image deployment/"${DEPLOYMENT}" \
  "${CONTAINER}=${INTERNAL_IMAGE}" \
  -n "${NAMESPACE}"
ok "Deployment image patched to ${INTERNAL_IMAGE}"

# ── Step 5 — Wait for rollout ─────────────────────────────────────────────────
log "Waiting for rollout to complete..."
oc rollout status deployment/"${DEPLOYMENT}" -n "${NAMESPACE}" --timeout=180s
ok "Rollout complete"

# ── Step 6 — Verify ───────────────────────────────────────────────────────────
log "Running pods:"
oc get pods -n "${NAMESPACE}" | grep "${DEPLOYMENT##*-}" | grep -v build || true

echo ""
log "Verifying SSO_ZEN_ENABLED in pod env..."
oc exec -n "${NAMESPACE}" deployment/"${DEPLOYMENT}" -- env 2>/dev/null | grep "SSO_ZEN\|SSO_ENABLED" | sort

echo ""
ok "Deploy done — image ${IMAGE_TAG} is live on ${DEPLOYMENT}"
