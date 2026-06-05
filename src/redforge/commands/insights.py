"""Red Hat Insights / Lightspeed Remediations API integration.

plan_insights_core      — resolve host, verify CVEs, create remediation plan
remediate_insights_core — trigger or dry-run a remediation playbook run

All endpoint constants are marked VERIFY so paths are easy to correct when
tested against a live account. Full request/response is logged to stderr on
any non-2xx so mismatches are immediately visible.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any

import requests

# ── Endpoint constants — VERIFY all paths against live OpenAPI specs ──────────
# Inventory:    https://console.redhat.com/api/inventory/v1/openapi.json
# Vulnerability: https://console.redhat.com/api/vulnerability/v1/openapi.json
# Remediations: https://console.redhat.com/api/remediations/v1/openapi.json

_SSO_TOKEN_URL = (  # VERIFY
    "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
)
_SSO_CLIENT_ID = "rhsm-api"  # VERIFY

_CONSOLE_BASE = "https://console.redhat.com"

_INVENTORY_HOSTS_PATH = "/api/inventory/v1/hosts"  # VERIFY
# VERIFY: response shape — {"total": N, "results": [{"id": "uuid", "fqdn": "...", ...}]}

_VULN_SYSTEM_CVES_PATH = "/api/vulnerability/v1/systems/{system_id}/cves"
# response: {"data": [{"id": "CVE-...", "attributes": {"advisory_available": bool, "remediation": int, ...}}],
#            "meta": {"total_items": N}}
# Supported filter: advisory_available=true (reduces to only patchable CVEs)

_REMEDIATIONS_PATH = "/api/remediations/v1/remediations"  # VERIFY
# VERIFY: POST payload — {"name": "...", "add": {"issues": [{"id": "vulnerabilities:CVE-...", "systems": ["uuid"]}]}}
# VERIFY: POST response — {"id": "uuid"}

_REMEDIATION_PATH = "/api/remediations/v1/remediations/{remediation_id}"  # VERIFY
# VERIFY: GET response — {"id": "...", "name": "...", "archived": bool, "issue_count": N, "system_count": N, ...}

_PLAYBOOK_RUNS_PATH = "/api/remediations/v1/remediations/{remediation_id}/playbook_runs"  # VERIFY
# VERIFY: POST response — {"id": "run-uuid"}

_PLAYBOOK_RUN_PATH = (  # VERIFY
    "/api/remediations/v1/remediations/{remediation_id}/playbook_runs/{run_id}"
)
# VERIFY: GET response — {"id": "...", "status": "pending|running|success|failure|canceled",
#                          "created_at": "...", "updated_at": "..."}

_VULN_ISSUE_PREFIX = "vulnerabilities"  # VERIFY: issue ID prefix in remediations API

_RUN_TERMINAL_STATES = {"success", "failure", "canceled"}  # VERIFY: status enum values

# VERIFY: human-readable console URL for a remediation plan
_CONSOLE_REMEDIATION_URL = "https://console.redhat.com/insights/remediations/{remediation_id}"

_DEFAULT_POLL_TIMEOUT = int(os.environ.get("INSIGHTS_RUN_TIMEOUT", "600"))
_DEFAULT_POLL_INTERVAL = int(os.environ.get("INSIGHTS_POLL_INTERVAL", "10"))

_session = requests.Session()
_session.headers.update({"Accept": "application/json"})


# ── Error type ────────────────────────────────────────────────────────────────

class InsightsError(Exception):
    """API-layer error. stage identifies where in the pipeline it occurred."""

    def __init__(
        self,
        message: str,
        stage: str,
        status_code: int | None = None,
        endpoint: str = "",
        body: Any = None,
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.status_code = status_code
        self.endpoint = endpoint
        self.body = body

    def to_dict(self) -> dict:
        return {
            "error": True,
            "stage": self.stage,
            "message": str(self),
            "status_code": self.status_code,
            "endpoint": self.endpoint,
            "body": self.body,
        }


# ── Auth ──────────────────────────────────────────────────────────────────────

class _TokenCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._token: str | None = None
        self._expires_at: float = 0.0

    def get(self) -> str | None:
        with self._lock:
            if self._token and time.time() < self._expires_at:
                return self._token
            return None

    def set(self, token: str, expires_in: int) -> None:
        with self._lock:
            self._token = token
            self._expires_at = time.time() + expires_in - 60  # refresh ~60s before expiry


_token_cache = _TokenCache()


def get_access_token() -> str:
    """Exchange RH_OFFLINE_TOKEN for a short-lived access token. Caches until near-expiry."""
    cached = _token_cache.get()
    if cached:
        return cached

    offline_token = os.environ.get("RH_OFFLINE_TOKEN", "")
    if not offline_token:
        raise InsightsError(
            "RH_OFFLINE_TOKEN environment variable is not set. "
            "Populate the redforge-rh-offline-token Secret and restart the MCP pod.",
            stage="auth",
        )

    resp = _session.post(
        _SSO_TOKEN_URL,
        data={
            "grant_type": "refresh_token",
            "client_id": _SSO_CLIENT_ID,
            "refresh_token": offline_token,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=15,
    )

    if not resp.ok:
        body = _safe_json(resp)
        error_code = body.get("error") if isinstance(body, dict) else ""
        if error_code == "invalid_grant":
            raise InsightsError(
                "Offline token is expired or revoked. "
                "Regenerate it at https://console.redhat.com/openshift/token "
                "then update the redforge-rh-offline-token Secret and restart the MCP pod.",
                stage="auth",
                status_code=resp.status_code,
                endpoint=_SSO_TOKEN_URL,
                body={"error": error_code},  # never log token values
            )
        _log_api_error("POST", _SSO_TOKEN_URL, resp)
        raise InsightsError(
            f"Token exchange failed (HTTP {resp.status_code})",
            stage="auth",
            status_code=resp.status_code,
            endpoint=_SSO_TOKEN_URL,
            body=body,
        )

    data = resp.json()
    access_token: str = data["access_token"]
    expires_in = int(data.get("expires_in", 300))
    _token_cache.set(access_token, expires_in)
    return access_token


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _safe_json(resp: requests.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return resp.text[:2000]


def _log_api_error(method: str, url: str, resp: requests.Response) -> None:
    print(
        f"[insights] {method} {url} → HTTP {resp.status_code}\n"
        f"  response: {resp.text[:2000]}",
        file=sys.stderr,
        flush=True,
    )


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _api_get(
    path: str, token: str, params: dict | None = None, stage: str = "api"
) -> Any:
    url = _CONSOLE_BASE + path
    resp = _session.get(url, headers=_auth_headers(token), params=params, timeout=30)
    if not resp.ok:
        _log_api_error("GET", url, resp)
        raise InsightsError(
            f"GET {path} failed (HTTP {resp.status_code})",
            stage=stage,
            status_code=resp.status_code,
            endpoint=url,
            body=_safe_json(resp),
        )
    return resp.json()


def _api_post(
    path: str, token: str, payload: dict, stage: str = "api"
) -> Any:
    url = _CONSOLE_BASE + path
    resp = _session.post(url, headers=_auth_headers(token), json=payload, timeout=30)
    if not resp.ok:
        _log_api_error("POST", url, resp)
        raise InsightsError(
            f"POST {path} failed (HTTP {resp.status_code})",
            stage=stage,
            status_code=resp.status_code,
            endpoint=url,
            body=_safe_json(resp),
        )
    return resp.json() if resp.content else {}


# ── Inventory ─────────────────────────────────────────────────────────────────

def resolve_host(token: str, fqdn: str) -> str:
    """Return the inventory UUID for the given FQDN. Errors on zero or multiple matches."""
    data = _api_get(
        _INVENTORY_HOSTS_PATH, token, params={"fqdn": fqdn}, stage="inventory"
    )
    # VERIFY: field names — expecting {"total": N, "results": [{"id": "uuid", ...}]}
    total = data.get("total", 0)
    results = data.get("results", [])

    if total == 0 or not results:
        raise InsightsError(
            f"Host '{fqdn}' not found in Insights inventory. "
            "Verify the host is registered with insights-client and has checked in recently.",
            stage="inventory",
            endpoint=_CONSOLE_BASE + _INVENTORY_HOSTS_PATH,
        )
    if total > 1:
        ids = [r.get("id") for r in results]
        raise InsightsError(
            f"FQDN '{fqdn}' matched {total} inventory records: {ids}. "
            "Use a more specific hostname.",
            stage="inventory",
            endpoint=_CONSOLE_BASE + _INVENTORY_HOSTS_PATH,
        )

    system_id = results[0].get("id")
    if not system_id:
        raise InsightsError(
            f"Inventory record for '{fqdn}' has no 'id' field — unexpected response shape.",
            stage="inventory",
        )
    return str(system_id)


# ── Vulnerability ─────────────────────────────────────────────────────────────

def fetch_cves_for_system(
    token: str, system_id: str, cve_ids: list[str]
) -> dict[str, dict]:
    """
    Return {CVE-ID: attributes} for the requested CVEs that affect this system
    and have an advisory available (i.e. are patchable).

    Queries the system CVEs endpoint filtered to advisory_available=true, which
    the API supports and dramatically reduces the result set. Paginates until all
    patchable CVEs are fetched, then cross-references with the requested list.
    """
    path = _VULN_SYSTEM_CVES_PATH.format(system_id=system_id)
    wanted = {c.upper() for c in cve_ids}
    result: dict[str, dict] = {}
    page = 1

    while True:
        data = _api_get(
            path, token,
            params={"advisory_available": "true", "page": page, "page_size": 100},
            stage="vulnerability",
        )
        for item in data.get("data", []):
            cve_id = str(item.get("id", "")).strip().upper()
            if cve_id in wanted:
                result[cve_id] = item.get("attributes", {})

        meta = data.get("meta", {})
        total = meta.get("total_items", 0)
        fetched = page * 100
        if fetched >= total or not data.get("data") or len(result) == len(wanted):
            break
        page += 1

    return result


def _cve_is_resolvable(attributes: dict) -> bool:
    """True if the vulnerability API reports a package-level fix is available.
    advisory_available is a bool; remediation is an int (0=none, non-zero=fix exists).
    """
    if attributes.get("advisory_available"):
        return True
    remediation = attributes.get("remediation", 0)
    return bool(remediation and remediation != 0)


# ── Remediations ──────────────────────────────────────────────────────────────

def create_remediation(
    token: str,
    issues: list[dict],
    system_id: str,
    name: str = "",
) -> str:
    """Create a remediation plan and return its UUID.

    VERIFY: payload shape — issues[].id format and systems field placement.
    """
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    payload = {
        "name": name or f"redforge-{ts}",
        "add": {
            "issues": [
                {
                    "id": issue["issue_id"],  # VERIFY: field name "id"
                    "systems": [system_id],
                }
                for issue in issues
            ]
        },
    }
    data = _api_post(_REMEDIATIONS_PATH, token, payload, stage="plan_creation")
    # VERIFY: response field — expecting {"id": "uuid"}
    remediation_id = data.get("id") or data.get("remediation_id")
    if not remediation_id:
        raise InsightsError(
            "Remediations API returned no ID in create response — unexpected response shape.",
            stage="plan_creation",
            endpoint=_CONSOLE_BASE + _REMEDIATIONS_PATH,
            body=data,
        )
    return str(remediation_id)


def get_remediation(token: str, remediation_id: str) -> dict:
    """Fetch an existing remediation plan. VERIFY: response shape."""
    path = _REMEDIATION_PATH.format(remediation_id=remediation_id)
    return _api_get(path, token, stage="plan_validation")


def trigger_run(token: str, remediation_id: str) -> str:
    """Trigger a playbook run and return the run UUID. VERIFY: response field name."""
    path = _PLAYBOOK_RUNS_PATH.format(remediation_id=remediation_id)
    data = _api_post(path, token, payload={}, stage="execution")
    # VERIFY: response field — expecting {"id": "run-uuid"}
    run_id = data.get("id") or data.get("run_id")
    if not run_id:
        raise InsightsError(
            "Playbook runs API returned no run ID — unexpected response shape.",
            stage="execution",
            endpoint=_CONSOLE_BASE + path,
            body=data,
        )
    return str(run_id)


def poll_run(
    token: str,
    remediation_id: str,
    run_id: str,
    timeout: int = _DEFAULT_POLL_TIMEOUT,
    interval: int = _DEFAULT_POLL_INTERVAL,
) -> dict:
    """Poll a playbook run until terminal state or timeout.

    VERIFY: status field name and enum values — "pending"|"running"|"success"|"failure"|"canceled"
    """
    path = _PLAYBOOK_RUN_PATH.format(remediation_id=remediation_id, run_id=run_id)
    deadline = time.time() + timeout
    started_at: str | None = None

    while True:
        data = _api_get(path, token, stage="execution_poll")
        # VERIFY: field names "status", "created_at", "updated_at"
        status = str(data.get("status", "")).lower()
        if not started_at:
            started_at = data.get("created_at")

        if status in _RUN_TERMINAL_STATES:
            return {
                "run_id": run_id,
                "status": status,
                "started_at": started_at,
                "finished_at": data.get("updated_at"),
                "console_url": _CONSOLE_REMEDIATION_URL.format(
                    remediation_id=remediation_id
                ),
            }

        if time.time() > deadline:
            return {
                "run_id": run_id,
                "status": "timeout",
                "started_at": started_at,
                "finished_at": None,
                "console_url": _CONSOLE_REMEDIATION_URL.format(
                    remediation_id=remediation_id
                ),
                "message": (
                    f"Polling timed out after {timeout}s. "
                    "The run may still be in progress — check the console_url."
                ),
            }

        time.sleep(interval)


# ── Public pipeline entry points ──────────────────────────────────────────────

def plan_insights_core(
    cves: list[dict],
    target_host: str,
) -> dict[str, Any]:
    """
    1. Resolve FQDN → inventory UUID
    2. Fetch all CVEs affecting the system from the Vulnerability API
    3. Cross-reference with requested CVEs; skip those not applicable or unfixable
    4. Create a remediation plan for the resolvable subset

    Never invents issue IDs, fix versions, or resolutions — only confirmed API data.
    """
    token = get_access_token()
    system_uuid = resolve_host(token, target_host)
    requested_ids = [str(e.get("cve_id", "")).strip().upper() for e in cves if e.get("cve_id")]
    system_cve_map = fetch_cves_for_system(token, system_uuid, requested_ids)

    matched: list[dict] = []
    skipped: list[dict] = []

    for entry in cves:
        cve_id = str(entry.get("cve_id", "")).strip().upper()
        if not cve_id:
            skipped.append({"cve_id": cve_id, "reason": "empty cve_id in input"})
            continue

        if cve_id not in system_cve_map:
            skipped.append({
                "cve_id": cve_id,
                "reason": "not applicable to this system per Vulnerability API",
            })
            continue

        attrs = system_cve_map[cve_id]
        if not _cve_is_resolvable(attrs):
            remediation_val = attrs.get("remediation", "unknown")  # VERIFY: field name
            skipped.append({
                "cve_id": cve_id,
                "reason": f"no package-level fix available (remediation={remediation_val!r})",
            })
            continue

        issue_id = f"{_VULN_ISSUE_PREFIX}:{cve_id}"  # VERIFY: format
        matched.append({"cve_id": cve_id, "issue_id": issue_id})

    if not matched:
        return {
            "error": True,
            "stage": "plan_creation",
            "message": "No resolvable CVEs found for this host — nothing to plan.",
            "system_uuid": system_uuid,
            "matched": [],
            "skipped": skipped,
            "coverage_summary": {
                "requested": len(cves),
                "matched": 0,
                "skipped": len(skipped),
            },
        }

    remediation_id = create_remediation(token, matched, system_uuid)

    return {
        "remediation_id": remediation_id,
        "system_uuid": system_uuid,
        "matched": matched,
        "skipped": skipped,
        "coverage_summary": {
            "requested": len(cves),
            "matched": len(matched),
            "skipped": len(skipped),
        },
    }


def remediate_insights_core(
    remediation_id: str,
    dry_run: bool = False,
    poll_timeout: int = _DEFAULT_POLL_TIMEOUT,
    poll_interval: int = _DEFAULT_POLL_INTERVAL,
) -> dict[str, Any]:
    """
    Trigger execution of a remediation plan, or validate it (dry_run=True).

    dry_run: fetches the plan metadata and confirms it is non-empty and
    not archived — without dispatching any playbook run.
    """
    token = get_access_token()

    if dry_run:
        plan = get_remediation(token, remediation_id)
        # VERIFY: field names "issue_count", "system_count", "archived", "name"
        issue_count = plan.get("issue_count", len(plan.get("issues", [])))
        system_count = plan.get("system_count", 0)
        archived = plan.get("archived", False)
        name = plan.get("name", "")
        runnable = issue_count > 0 and not archived
        return {
            "dry_run": True,
            "remediation_id": remediation_id,
            "runnable": runnable,
            "name": name,
            "issue_count": issue_count,
            "system_count": system_count,
            "archived": archived,
            "message": (
                "Plan is runnable."
                if runnable
                else "Plan has no issues or is archived — cannot execute."
            ),
            "console_url": _CONSOLE_REMEDIATION_URL.format(
                remediation_id=remediation_id
            ),
        }

    run_id = trigger_run(token, remediation_id)
    return poll_run(
        token, remediation_id, run_id,
        timeout=poll_timeout,
        interval=poll_interval,
    )
