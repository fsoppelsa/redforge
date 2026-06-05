"""Red Hat Insights API client for vulnerability and system data."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

import requests

logger = logging.getLogger(__name__)

INSIGHTS_BASE_URL = "https://console.redhat.com/api"


@dataclass
class InsightsHost:
    """Represents a registered RHEL host in Red Hat Insights inventory."""

    host_id: str
    display_name: str
    fqdn: str
    rhel_version: str
    last_seen: str
    tags: list[dict[str, str]]


@dataclass
class InsightsCveDetail:
    """CVE detail from Red Hat Insights vulnerability service."""

    cve_id: str
    cvss3_score: float | None
    severity: str
    public_date: str
    description: str
    affected_systems: int
    advisories: list[str]


class InsightsClient:
    """Client for the Red Hat Insights API.

    Authenticates via an offline token (see https://access.redhat.com/articles/3565281).

    Example:
        client = InsightsClient(offline_token="...")
        hosts = client.list_hosts()
        cves = client.get_cves_for_system(hosts[0].host_id)
    """

    def __init__(self, offline_token: str, base_url: str = INSIGHTS_BASE_URL) -> None:
        self._base_url = base_url.rstrip("/")
        self._offline_token = offline_token
        self._access_token: str | None = None
        self._token_expiry: float = 0.0

    def _get_access_token(self) -> str:
        now = time.time()
        if self._access_token and now < self._token_expiry - 60:
            return self._access_token

        resp = requests.post(
            "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token",
            data={
                "grant_type": "refresh_token",
                "client_id": "rhsm-api",
                "refresh_token": self._offline_token,
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        self._access_token = data["access_token"]
        self._token_expiry = now + data.get("expires_in", 900)
        return self._access_token

    def _get(self, path: str, params: dict | None = None) -> dict[str, Any]:
        token = self._get_access_token()
        resp = requests.get(
            f"{self._base_url}{path}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
            params=params,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    def list_hosts(self, per_page: int = 50, page: int = 1) -> list[InsightsHost]:
        """List registered hosts from the Insights inventory."""
        data = self._get("/inventory/v1/hosts", params={"per_page": per_page, "page": page})
        hosts: list[InsightsHost] = []
        for entry in data.get("results", []):
            system_profile = entry.get("system_profile", {}) or {}
            hosts.append(
                InsightsHost(
                    host_id=entry.get("id", ""),
                    display_name=entry.get("display_name", ""),
                    fqdn=entry.get("fqdn", ""),
                    rhel_version=system_profile.get("operating_system", {}).get("release", ""),
                    last_seen=entry.get("updated", ""),
                    tags=entry.get("tags", []),
                )
            )
        return hosts

    def get_cves_for_system(self, system_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """Get CVEs affecting a specific registered system."""
        data = self._get(
            f"/vulnerability/v1/systems/{system_id}/cves",
            params={"limit": limit},
        )
        return data.get("data", [])

    def get_cve_detail(self, cve_id: str) -> InsightsCveDetail | None:
        """Get detailed CVE information from Insights."""
        try:
            data = self._get(f"/vulnerability/v1/cves/{cve_id}")
            attrs = data.get("data", {}).get("attributes", {})
            return InsightsCveDetail(
                cve_id=cve_id,
                cvss3_score=attrs.get("cvss3_score"),
                severity=attrs.get("severity", ""),
                public_date=attrs.get("public_date", ""),
                description=attrs.get("description", ""),
                affected_systems=attrs.get("affected_systems_count", 0),
                advisories=attrs.get("advisory_ids", []),
            )
        except requests.HTTPError as exc:
            if exc.response.status_code == 404:
                return None
            raise
