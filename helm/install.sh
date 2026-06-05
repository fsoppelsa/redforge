#!/usr/bin/env bash
# Installs RedForge into an existing namespace.
# Requires no cluster-admin rights — but setup-scc.sh must have been run once
# by a cluster admin beforehand.
set -euo pipefail

NAMESPACE="${NAMESPACE:-redforge}"
RELEASE="${RELEASE:-redforge}"
CHART_DIR="$(cd "$(dirname "$0")" && pwd)"
NVD_API_KEY="${NVD_API_KEY:-}"
HELM_VERSION="${HELM_VERSION:-v3.17.3}"

# ── Helm bootstrap (RHEL 9 has no helm RPM) ───────────────────────────────────

_install_helm() {
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64)  arch="amd64" ;;
    aarch64) arch="arm64" ;;
    *)
      echo "ERROR: unsupported architecture '$arch'."
      exit 1
      ;;
  esac

  local url="https://get.helm.sh/helm-${HELM_VERSION}-linux-${arch}.tar.gz"
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  echo "Downloading helm ${HELM_VERSION} (${arch})..."
  curl -fsSL "$url" | tar -xz -C "$tmp"

  # Install to /usr/local/bin if writable, otherwise ~/.local/bin
  local dest
  if [[ -w /usr/local/bin ]]; then
    dest=/usr/local/bin
  else
    dest="$HOME/.local/bin"
    mkdir -p "$dest"
    # Make sure it's on PATH for the rest of this script
    export PATH="$dest:$PATH"
  fi

  mv "$tmp/linux-${arch}/helm" "$dest/helm"
  chmod +x "$dest/helm"
  echo "helm installed to $dest/helm"
}

# ── Validate ──────────────────────────────────────────────────────────────────

if [[ -z "$NVD_API_KEY" ]]; then
  echo "ERROR: NVD_API_KEY is not set."
  echo "  Export it or pass it inline:"
  echo "    NVD_API_KEY=<your-key> $0"
  exit 1
fi

if ! command -v oc &>/dev/null; then
  echo "ERROR: 'oc' not found in PATH."
  exit 1
fi

if ! command -v helm &>/dev/null; then
  echo "'helm' not found — installing..."
  _install_helm
fi

if ! oc get namespace "$NAMESPACE" &>/dev/null; then
  echo "ERROR: namespace '$NAMESPACE' does not exist."
  echo "  Ask a cluster admin to run: NAMESPACE=$NAMESPACE ./setup-scc.sh"
  exit 1
fi

# ── Helm install ──────────────────────────────────────────────────────────────

echo "Installing Helm release '$RELEASE' in namespace '$NAMESPACE'..."
helm install "$RELEASE" "$CHART_DIR" \
  --namespace "$NAMESPACE" \
  --set credentials.nvdApiKey="$NVD_API_KEY" \
  --wait --timeout 5m \
  --atomic

# ── Done ─────────────────────────────────────────────────────────────────────

echo ""
echo "Install complete. The ingest Job is running in the background."
echo ""
echo "Watch progress:"
echo "  kubectl get deploy,pod,job -n $NAMESPACE -w"
echo ""
echo "Ingest logs:"
echo "  kubectl logs -n $NAMESPACE -l app=redforge-ingest -c ingest -f"
echo "  kubectl logs -n $NAMESPACE -l app=redforge-ingest -c load-virtuoso -f"
echo ""
echo "Routes:"
oc get routes -n "$NAMESPACE" 2>/dev/null || true
