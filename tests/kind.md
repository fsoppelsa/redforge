# RedForge Operator — kind Testing Guide

Test the operator end-to-end in a local kind cluster. No Route support, but everything else works.

## 1. Prerequisites

```bash
brew install kind kubectl      # macOS
podman --version
```

## 2. Create the cluster

```bash
kind create cluster --name redforge-test
kubectl cluster-info
```

## 3. Build and load the operator image

```bash
podman build -f operator/Containerfile -t quay.io/fsoppelsa/redforge-operator:0.1.0 .
podman save quay.io/fsoppelsa/redforge-operator:0.1.0 -o /tmp/redforge-operator.tar
kind load image-archive /tmp/redforge-operator.tar --name redforge-test
```

## 4. Install the operator

```bash
kubectl create ns redforge
kubectl apply -f operator/config/crd/bases/redforge.io_redforges.yaml
kubectl apply -f operator/config/rbac/service_account.yaml
kubectl apply -f operator/config/rbac/role.yaml
kubectl apply -f operator/config/manager/manager.yaml

kubectl get pods -n redforge -w
```

If the operator pod is `ImagePullBackOff`, edit `operator/config/manager/manager.yaml` and add `imagePullPolicy: IfNotPresent` under the container. In kind the image is cached locally but the default pull policy (`Always` for `:latest` tags) may still try to pull from the registry.

## 5. Create a RedForge instance

```bash
kubectl config set-context --current --namespace=redforge
kubectl apply -f operator/config/samples/v1alpha1_redforge.yaml
kubectl get redforge,deploy,svc,pod,cm,pvc -n redforge -w
```

Expected output over ~2 minutes:

```
NAME                                     READY   STATUS
pod/redforge-operator-xxx                1/1     Running
pod/redforge-web-xxx                     0/1     Init:0/1   ← init container running
pod/redforge-web-xxx                     0/1     PodInitializing
pod/redforge-web-xxx                     1/1     Running    ← ready
pod/redforge-mcp-xxx                     0/1     Init:0/1
pod/redforge-mcp-xxx                     1/1     Running

deployment/redforge-web                  1/1
deployment/redforge-mcp                  1/1
service/redforge-web                     ClusterIP
service/redforge-mcp                     ClusterIP
configmap/redforge-config
pvc/redforge-data                        Bound
redforge/redforge                        Running
```

## 6. Verify it works

```bash
kubectl get redforge redforge -o jsonpath='{.status.phase}'     # → Running
kubectl get cm redforge-config -o jsonpath='{.data.redforge\.toml}' | head -5
kubectl port-forward svc/redforge-web 8501:8501                  # → http://localhost:8501
kubectl exec deploy/redforge-web -- ls /app/data/raw/ | head -10 # check downloaded data
```

## 7. Debugging

```bash
kubectl logs deploy/redforge-operator -n redforge --tail=50
kubectl logs deploy/redforge-web -n redforge -c init-download-ingest
kubectl describe redforge redforge -n redforge
kubectl get events -n redforge --sort-by='.lastTimestamp'

# Redeploy after changes
kubectl delete redforge redforge -n redforge
kubectl apply -f operator/config/samples/v1alpha1_redforge.yaml
```

## 8. Cleanup

```bash
kubectl delete redforge redforge -n redforge --ignore-not-found
kubectl delete crd redforges.redforge.io --ignore-not-found
kind delete cluster --name redforge-test
```

## What works in kind

| Feature | Status |
|---------|--------|
| CRD install | yes |
| Operator deployment | yes |
| ConfigMap from CR spec | yes |
| PVC (with default storage class) | yes |
| Init container (download + ingest) | yes |
| Web Deployment + Service | yes |
| MCP Deployment + Service | yes |
| Status reconciliation | yes |
| OpenShift Route | no (OpenShift only) |
| Red Hat Insights | needs token in CR |

## Production push

```bash
podman build -f operator/Containerfile -t quay.io/fsoppelsa/redforge-operator:0.1.0 .
podman push quay.io/fsoppelsa/redforge-operator:0.1.0
```

Then update all image references (`operator/config/manager/manager.yaml`, `operator/bundle/manifests/redforge.clusterserviceversion.yaml`) to point to `quay.io/fsoppelsa/redforge-operator:0.1.0` before committing.
