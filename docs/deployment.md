# Deployment

Production deployment guide for RedForge.

## Prerequisites

- Python 3.11+
- Podman or Docker (Podman recommended)
- Red Hat Enterprise Linux 9+ (or compatible)

## Quickstart

```bash
./install.sh
```

## Containerized deployment

RedForge ships with a `podman-compose.yml` stack:

```bash
# Build all images
python3 scripts/stack.py build

# Start minimal profile (dashboard + virtuoso triplestore)
python3 scripts/stack.py start --profile minimal

# Start full profile (dashboard + MCP + virtuoso + pellet)
python3 scripts/stack.py start --profile full

# Check status
python3 scripts/stack.py status

# View logs
python3 scripts/stack.py logs

# Load RDF data into the triplestore
python3 scripts/stack.py load
```

### Service ports

| Service | Port | Protocol |
| ------- | ---- | -------- |
| Streamlit dashboard | 8501 | HTTP |
| MCP server | 8000 | HTTP/SSE |
| Virtuoso SPARQL | 8890 | HTTP |
| Virtuoso admin | 1111 | HTTP |

## OpenShift deployment

Create a `BuildConfig` and `DeploymentConfig` from the root `Containerfile.redforge`.

```yaml
# Template available in scripts/openshift-deploy.yml
oc apply -f scripts/openshift-deploy.yml
```

## Production hardening

- Run containers as non-root (UID 1001)
- Use Red Hat UBI 9 as the base image
- Mount `redforge.toml` as a ConfigMap or Secret
- Use a persistent volume for `data/` directory
- Enable TLS termination at the ingress/reverse proxy layer
- Set `PYTHONHASHSEED=random` for hash randomization

## Configuration

Copy `redforge.toml.example` to `redforge.toml` and edit:

```toml
[pipeline]
data_dir = "/data/raw"
rdf_dir  = "/data/rdf"

[insights]
enabled = true
offline_token = "your-offline-token"

[credentials]
nvd_api_key = "your-nvd-api-key"
```
