#!/usr/bin/env bash
# Run this ONCE as cluster-admin before the first install.
# It grants the anyuid SCC to the redforge service account so that
# the Virtuoso pod (upstream image runs as root) can start on OpenShift.
set -euo pipefail

NAMESPACE="${NAMESPACE:-redforge}"

if ! oc whoami &>/dev/null; then
  echo "ERROR: not logged in to OpenShift."
  exit 1
fi

echo "Creating namespace '$NAMESPACE' (if absent)..."
oc new-project "$NAMESPACE" 2>/dev/null || oc project "$NAMESPACE"

echo "Pre-creating service account 'redforge'..."
oc create serviceaccount redforge -n "$NAMESPACE" 2>/dev/null || true

echo "Granting anyuid SCC to 'redforge' in '$NAMESPACE'..."
oc adm policy add-scc-to-user anyuid -z redforge -n "$NAMESPACE"

echo ""
echo "Done. A normal user with admin rights on '$NAMESPACE' can now run install.sh."
