VERSION    ?= 0.1.0
IMAGE_REG  ?= quay.io/fsoppelsa
APP_IMAGE  ?= $(IMAGE_REG)/redforge:$(VERSION)
NAMESPACE  ?= redforge
HELM_CHART  = ./helm
HELM_RELEASE = redforge

.PHONY: build push helm-install helm-upgrade helm-uninstall helm-dry-run \
        kind-up kind-down kind-load kind-test

# ── Container image ───────────────────────────────────────────────────────────

build:
	podman build -f Containerfile.redforge -t $(APP_IMAGE) .

push: build
	podman push $(APP_IMAGE)

# ── Helm (OpenShift) ──────────────────────────────────────────────────────────
#
# Before first install, grant anyuid SCC to the service account:
#   oc adm policy add-scc-to-serviceaccount anyuid -z redforge -n $(NAMESPACE)

helm-install:
	oc new-project $(NAMESPACE) 2>/dev/null || true
	oc adm policy add-scc-to-serviceaccount anyuid -z redforge -n $(NAMESPACE) 2>/dev/null || true
	helm install $(HELM_RELEASE) $(HELM_CHART) \
	  --namespace $(NAMESPACE) \
	  --set credentials.nvdApiKey="$(NVD_API_KEY)"

helm-upgrade:
	helm upgrade $(HELM_RELEASE) $(HELM_CHART) \
	  --namespace $(NAMESPACE) \
	  --set credentials.nvdApiKey="$(NVD_API_KEY)"

helm-uninstall:
	helm uninstall $(HELM_RELEASE) --namespace $(NAMESPACE) || true
	kubectl delete pvc redforge-data redforge-virtuoso-db -n $(NAMESPACE) --ignore-not-found

helm-dry-run:
	helm install $(HELM_RELEASE) $(HELM_CHART) \
	  --namespace $(NAMESPACE) \
	  --set credentials.nvdApiKey="test-key" \
	  --dry-run --debug
