#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${SCRIPT_DIR}"
CONFIG_EXAMPLE="${REPO_ROOT}/redforge.toml.example"
CONFIG_FILE="${REPO_ROOT}/redforge.toml"
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=11

log() {
  printf '[install] %s\n' "$1"
}

warn() {
  printf '[install] warning: %s\n' "$1" >&2
}

fail() {
  printf '[install] error: %s\n' "$1" >&2
  exit 1
}

require_command() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    fail "${cmd} not found in PATH"
  fi
}

resolve_python() {
  if [[ -n "${CONDA_PREFIX:-}" ]] && command -v python >/dev/null 2>&1; then
    printf '%s\n' "python"
    return 0
  fi

  if command -v conda >/dev/null 2>&1; then
    fail "Conda is installed but no environment is active; run 'conda activate <env>' before ./install.sh"
  fi

  local candidate
  for candidate in python3.11 python3 python; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done

  fail "Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ is required"
}

check_python_version() {
  local python_bin="$1"
  local version
  version="$("${python_bin}" -c 'import sys; print(f"{sys.version_info.major} {sys.version_info.minor} {sys.version_info.micro}")')"

  local major minor micro
  read -r major minor micro <<<"${version}"

  if (( major < MIN_PYTHON_MAJOR )) || (( major == MIN_PYTHON_MAJOR && minor < MIN_PYTHON_MINOR )); then
    fail "found Python ${major}.${minor}.${micro}; need Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+"
  fi

  if [[ -n "${CONDA_PREFIX:-}" ]]; then
    log "Using active Conda environment at ${CONDA_PREFIX}"
  fi

  log "Using Python ${major}.${minor}.${micro} via ${python_bin}"
}

install_requirements() {
  local python_bin="$1"

  if [[ -n "${CONDA_PREFIX:-}" ]]; then
    log "Installing Python dependencies into the active Conda environment"
    "${python_bin}" -m pip install --upgrade pip
    "${python_bin}" -m pip install -r "${REPO_ROOT}/requirements.txt"
    return 0
  fi

  log "Installing Python dependencies into the user site-packages"
  "${python_bin}" -m pip install --user --break-system-packages --upgrade pip
  "${python_bin}" -m pip install --user --break-system-packages -r "${REPO_ROOT}/requirements.txt"
}

check_user_base_path() {
  local python_bin="$1"
  local user_base user_bin path_entry found=1
  user_base="$("${python_bin}" -m site --user-base)"
  user_bin="${user_base}/bin"

  IFS=':' read -r -a path_entry <<<"${PATH}"
  found=0
  for entry in "${path_entry[@]}"; do
    if [[ "${entry}" == "${user_bin}" ]]; then
      found=1
      break
    fi
  done

  if (( found == 0 )); then
    warn "${user_bin} is not on PATH; user-installed Python entrypoints may not be directly runnable"
    return 0
  fi

  log "User Python bin directory is on PATH: ${user_bin}"
}

check_podman() {
  require_command podman

  if ! podman compose version >/dev/null 2>&1; then
    fail "podman compose is not available; install podman-compose or enable the compose plugin"
  fi

  if ! podman info >/dev/null 2>&1; then
    fail "podman is installed but not running; start the Podman service or machine and rerun install.sh"
  fi

  log "Podman is installed and reachable"
}

ensure_config() {
  if [[ -f "${CONFIG_FILE}" ]]; then
    log "Keeping existing $(basename "${CONFIG_FILE}")"
    return 0
  fi

  if [[ ! -f "${CONFIG_EXAMPLE}" ]]; then
    fail "missing ${CONFIG_EXAMPLE}"
  fi

  cp "${CONFIG_EXAMPLE}" "${CONFIG_FILE}"
  log "Created $(basename "${CONFIG_FILE}") from $(basename "${CONFIG_EXAMPLE}")"
}

main() {
  cd "${REPO_ROOT}"

  local python_bin
  python_bin="$(resolve_python)"

  check_python_version "${python_bin}"
  if [[ -z "${CONDA_PREFIX:-}" ]]; then
    check_user_base_path "${python_bin}"
  fi
  install_requirements "${python_bin}"
  check_podman
  ensure_config

  cat <<EOF

RedForge installation completed.

Next steps:
  ./scripts/stack.py build
  ${python_bin} redforge.py --help
EOF
}

main "$@"
