#!/bin/sh

oc create rolebinding mcp-server-ollama-viewer \
  --clusterrole=view \
  --serviceaccount=agent-demo:mcp-server \
  -n ollama-ai
