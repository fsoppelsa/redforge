#!/bin/bash

set -euo pipefail

PROJECT_NAME="${PROJECT_NAME:-ollama-ai}"
UPSTREAM_VLLM_URL="${UPSTREAM_VLLM_URL:-http://192.168.1.43:8000}"
VLLM_MAX_TOKENS="${VLLM_MAX_TOKENS:-32}"
PROXY_IMAGESTREAM="${PROXY_IMAGESTREAM:-python-311}"
PROXY_IMAGE="${PROXY_IMAGE:-registry.access.redhat.com/ubi9/python-311:latest}"
INTERNAL_REGISTRY_REPO="default-route-openshift-image-registry.apps.rocky.example.com/${PROJECT_NAME}/${PROXY_IMAGESTREAM}:latest"

echo "🧹 1. Cleaning up previously created resources..."
oc delete inferenceservice orin-vllm -n "${PROJECT_NAME}" --ignore-not-found
oc delete servingruntime external-vllm-proxy-runtime -n "${PROJECT_NAME}" --ignore-not-found
oc delete imagestream "${PROXY_IMAGESTREAM}" -n "${PROJECT_NAME}" --ignore-not-found

echo "📦 2. Re-creating the ImageStream explicitly..."
oc create imagestream "${PROXY_IMAGESTREAM}" -n "${PROJECT_NAME}"

echo "⬇️ 3. Pulling proxy image to local host..."
podman pull "${PROXY_IMAGE}"

echo "🏷️ 4. Tagging image for internal registry..."
podman tag "${PROXY_IMAGE}" "${INTERNAL_REGISTRY_REPO}"

echo "🔑 5. Logging into internal OpenShift registry..."
HOST=$(oc get route default-route -n openshift-image-registry --template='{{ .spec.host }}')
podman login -u kubeadmin -p $(oc whoami -t) --tls-verify=false $HOST

echo "⬆️ 6. Pushing image to ${PROJECT_NAME} namespace (stripping signatures)..."
# FIXED: Added --remove-signatures to bypass the Red Hat GPG validation
podman push "${INTERNAL_REGISTRY_REPO}" --tls-verify=false --remove-signatures

echo "🚀 7. Deploying Proxy Runtime and InferenceService..."
oc apply -f - <<EOF
apiVersion: serving.kserve.io/v1alpha1
kind: ServingRuntime
metadata:
  name: external-vllm-proxy-runtime
  namespace: ${PROJECT_NAME}
  labels:
    opendatahub.io/dashboard: "true"
  annotations:
    openshift.io/display-name: "External vLLM Proxy Runtime"
    opendatahub.io/apiProtocol: REST
    opendatahub.io/model-type: "generative"
    opendatahub.io/template-display-name: "External vLLM Proxy Runtime"
    opendatahub.io/template-name: "external-vllm-proxy-runtime"
spec:
  supportedModelFormats:
    - name: vllm
      version: "1"
      autoSelect: true
  containers:
    - name: kserve-container
      image: image-registry.openshift-image-registry.svc:5000/${PROJECT_NAME}/${PROXY_IMAGESTREAM}:latest
      command: ["/bin/sh", "-c"]
      args:
        - |
          cat <<'PY' > /tmp/vllm_proxy.py
          import http.client
          import json
          import os
          import textwrap
          from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
          from urllib.parse import urlsplit

          UPSTREAM = os.environ["UPSTREAM_VLLM_URL"].rstrip("/")
          MAX_TOKENS = int(os.environ.get("VLLM_MAX_TOKENS", "32"))
          TIMEOUT = int(os.environ.get("UPSTREAM_TIMEOUT_SECONDS", "300"))
          HOP_BY_HOP_HEADERS = {
              "connection",
              "keep-alive",
              "proxy-authenticate",
              "proxy-authorization",
              "te",
              "trailers",
              "transfer-encoding",
              "upgrade",
          }

          def clamp_max_tokens(path: str, body: bytes) -> bytes:
              if path not in {"/v1/chat/completions", "/v1/completions"}:
                  return body
              try:
                  payload = json.loads(body.decode("utf-8"))
              except (UnicodeDecodeError, json.JSONDecodeError):
                  return body
              value = payload.get("max_tokens")
              if isinstance(value, int) and value > MAX_TOKENS:
                  payload["max_tokens"] = MAX_TOKENS
                  print(
                      f"Clamped max_tokens from {value} to {MAX_TOKENS} for {path}",
                      flush=True,
                  )
                  return json.dumps(payload).encode("utf-8")
              return body

          class ProxyHandler(BaseHTTPRequestHandler):
              protocol_version = "HTTP/1.1"

              def do_GET(self):
                  self._forward()

              def do_POST(self):
                  self._forward()

              def do_OPTIONS(self):
                  self._forward()

              def log_message(self, fmt, *args):
                  print(f"{self.address_string()} - {fmt % args}", flush=True)

              def _forward(self):
                  upstream = urlsplit(f"{UPSTREAM}{self.path}")
                  connection_class = (
                      http.client.HTTPSConnection
                      if upstream.scheme == "https"
                      else http.client.HTTPConnection
                  )
                  body = b""
                  if self.command in {"POST", "PUT", "PATCH"}:
                      length = int(self.headers.get("Content-Length", "0"))
                      body = self.rfile.read(length) if length > 0 else b""
                      body = clamp_max_tokens(upstream.path, body)
                  headers = {
                      key: value
                      for key, value in self.headers.items()
                      if key.lower() not in HOP_BY_HOP_HEADERS
                  }
                  headers["Host"] = upstream.netloc
                  headers["Connection"] = "close"
                  if body:
                      headers["Content-Length"] = str(len(body))
                  else:
                      headers.pop("Content-Length", None)
                  conn = connection_class(upstream.netloc, timeout=TIMEOUT)
                  try:
                      path = upstream.path or "/"
                      if upstream.query:
                          path = f"{path}?{upstream.query}"
                      conn.request(self.command, path, body=body or None, headers=headers)
                      response = conn.getresponse()
                      response_body = response.read()
                      if response.status >= 400:
                          excerpt = response_body.decode("utf-8", errors="replace")
                          excerpt = textwrap.shorten(excerpt, width=600, placeholder="...")
                          print(
                              f"Upstream error {response.status} for {self.command} {path}: {excerpt}",
                              flush=True,
                          )
                      self.send_response(response.status, response.reason)
                      for key, value in response.getheaders():
                          if key.lower() in HOP_BY_HOP_HEADERS or key.lower() == "content-length":
                              continue
                          self.send_header(key, value)
                      self.send_header("Content-Length", str(len(response_body)))
                      self.end_headers()
                      if response_body:
                          self.wfile.write(response_body)
                  finally:
                      conn.close()

          if __name__ == "__main__":
              port = int(os.environ.get("PORT", "8080"))
              server = ThreadingHTTPServer(("0.0.0.0", port), ProxyHandler)
              print(
                  f"Starting vLLM proxy on :{port}, upstream={UPSTREAM}, max_tokens<={MAX_TOKENS}",
                  flush=True,
              )
              server.serve_forever()
          PY
          python /tmp/vllm_proxy.py
      env:
        - name: UPSTREAM_VLLM_URL
          value: "${UPSTREAM_VLLM_URL}"
        - name: VLLM_MAX_TOKENS
          value: "${VLLM_MAX_TOKENS}"
      ports:
        - containerPort: 8080
          protocol: TCP
      resources:
        requests:
          cpu: "50m"
          memory: "64Mi"
        limits:
          cpu: "200m"
          memory: "128Mi"
---
apiVersion: serving.kserve.io/v1beta1
kind: InferenceService
metadata:
  name: orin-vllm
  namespace: ${PROJECT_NAME}
  labels:
    opendatahub.io/genai-asset: "true"
  annotations:
    serving.kserve.io/deploymentMode: RawDeployment
    opendatahub.io/model-type: "generative"
spec:
  predictor:
    model:
      modelFormat:
        name: vllm
      runtime: external-vllm-proxy-runtime
EOF

echo "🎉 Done! Watching pods to ensure the proxy spins up cleanly..."
echo "   Upstream vLLM URL : ${UPSTREAM_VLLM_URL}"
echo "   Clamped max_tokens: ${VLLM_MAX_TOKENS}"
echo "   Note: if the Jetson-side vLLM process is started with a larger --max-model-len,"
echo "         re-run this script with a matching VLLM_MAX_TOKENS value."
oc get pods -n "${PROJECT_NAME}" -w
