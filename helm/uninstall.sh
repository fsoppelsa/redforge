#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-redforge}"
RELEASE="${RELEASE:-redforge}"

# ── Validate ──────────────────────────────────────────────────────────────────

for cmd in oc helm; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: '$cmd' not found in PATH."
    exit 1
  fi
done

if ! oc get namespace "$NAMESPACE" &>/dev/null; then
  echo "Namespace '$NAMESPACE' does not exist — nothing to do."
  exit 0
fi

# ── Helm uninstall ────────────────────────────────────────────────────────────

if helm status "$RELEASE" --namespace "$NAMESPACE" &>/dev/null; then
  echo "Uninstalling Helm release '$RELEASE'..."
  helm uninstall "$RELEASE" --namespace "$NAMESPACE"
else
  echo "Release '$RELEASE' not found in '$NAMESPACE' — skipping helm uninstall."
fi

# ── PVCs (not removed by helm uninstall) ─────────────────────────────────────

echo "Deleting PVCs in '$NAMESPACE'..."
kubectl delete pvc redforge-data redforge-virtuoso-db \
  -n "$NAMESPACE" --ignore-not-found

# ── Namespace ─────────────────────────────────────────────────────────────────

echo "Deleting namespace '$NAMESPACE'..."
oc delete project "$NAMESPACE"

echo ""
echo "Done. '$NAMESPACE' has been removed."
