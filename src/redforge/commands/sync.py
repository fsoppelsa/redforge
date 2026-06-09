"""Sync remote sources into the local cache."""

from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import re
import tarfile
import time
from collections.abc import Callable
from pathlib import Path
from tempfile import TemporaryDirectory
from xml.etree import ElementTree as ET

try:
    import requests
except ModuleNotFoundError as exc:
    if exc.name == "certifi":
        import sys

        raise ModuleNotFoundError(
            "Missing dependency: 'certifi' (required by requests). "
            f"Interpreter in use: {sys.executable}. "
            "Install it in the same interpreter with: "
            f"'{sys.executable} -m pip install certifi' "
            "or "
            f"'{sys.executable} -m pip install -r requirements.txt'"
        ) from exc
    raise

logger = logging.getLogger(__name__)

_USER_AGENT = "RedForge/1.0 (https://github.com/fsoppelsa/fsoppelsa-opendata)"
_CHUNK = 65_536
_TIMEOUT_SIMPLE = 120   # large files (e.g. Metasploit ~500 MB)
_TIMEOUT_API    = 30    # paginated APIs
_TIMEOUT_CONNECT = 12
_RETRIES_SIMPLE = 3


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = _USER_AGENT
    return s


def _atomic_write_bytes(dest: Path, data: bytes) -> None:
    tmp = dest.with_name(f".{dest.name}.tmp")
    tmp.write_bytes(data)
    tmp.replace(dest)


def _atomic_write_text(dest: Path, text: str) -> None:
    _atomic_write_bytes(dest, text.encode("utf-8"))


def _fetch_simple(
    sess: requests.Session,
    url: str,
    dest: Path,
    on_progress: Callable[[str], None] | None = None,
    on_step: Callable[[int], None] | None = None,
) -> None:
    """Download a single URL to *dest* using streaming I/O."""
    if on_step:
        on_step(0)
    if on_progress:
        on_progress("connecting...")
    last_exc: Exception | None = None
    resp = None
    for attempt in range(1, _RETRIES_SIMPLE + 1):
        try:
            if on_progress:
                on_progress(f"attempt {attempt}/{_RETRIES_SIMPLE}")
            resp = sess.get(url, timeout=(_TIMEOUT_CONNECT, _TIMEOUT_SIMPLE), stream=True)
            resp.raise_for_status()
            break
        except requests.RequestException as exc:
            last_exc = exc
            if on_progress:
                on_progress(f"attempt {attempt}/{_RETRIES_SIMPLE} failed: {type(exc).__name__}")
            if attempt < _RETRIES_SIMPLE:
                time.sleep(1.0)
    if resp is None:
        assert last_exc is not None
        raise last_exc
    total = int(resp.headers.get("content-length", 0))
    received = 0
    last_pct = 0
    tmp = dest.with_name(f".{dest.name}.tmp")
    with open(tmp, "wb") as fh:
        for chunk in resp.iter_content(chunk_size=_CHUNK):
            if not chunk:
                continue
            fh.write(chunk)
            received += len(chunk)
            if total:
                pct = received * 100 // total
                if on_step and pct > last_pct:
                    on_step(pct)
                    last_pct = pct
                if on_progress:
                    on_progress(f"  {received // 1024:,} KB / {total // 1024:,} KB  ({pct}%)")
            else:
                # Some endpoints do not expose Content-Length; use heuristic progress.
                pct = min(95, 1 + (received // (1024 * 1024)))
                if on_step and pct > last_pct:
                    on_step(pct)
                    last_pct = pct
                if on_progress:
                    on_progress(f"  {received // 1024:,} KB downloaded")
    tmp.replace(dest)


def _fetch_packetstorm(
    sess: requests.Session,
    url: str,
    dest: Path,
    on_progress: Callable[[str], None] | None = None,
    on_step: Callable[[int], None] | None = None,
) -> None:
    """Download the Packet Storm XML feed and normalize it to JSON CVE mappings."""
    if on_step:
        on_step(1)
    resp = sess.get(url, timeout=_TIMEOUT_SIMPLE)
    resp.raise_for_status()
    if on_step:
        on_step(35)
    xml_text = resp.text
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        # Packet Storm sometimes returns malformed XML/HTML (or a WAF page).
        # Be resilient: try a minimal sanitization pass, otherwise produce an empty mapping.
        cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", xml_text)
        try:
            root = ET.fromstring(cleaned)
        except ET.ParseError as exc:
            _atomic_write_text(dest, "[]")
            if on_step:
                on_step(100)
            if on_progress:
                on_progress(f"  invalid XML ({exc}) - saved empty mapping")
            return

    rows: list[dict] = []
    items = root.findall(".//item")
    total_items = max(len(items), 1)
    for idx, item in enumerate(items, 1):
        if on_step and idx % 20 == 0:
            on_step(min(35 + (idx * 60 // total_items), 95))
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        descr = (item.findtext("description") or "").strip()
        text = f"{title} {descr}"
        cves = [c.upper() for c in _CVE_RE.findall(text)]
        # preserve order, dedupe
        seen: set[str] = set()
        cves_u: list[str] = []
        for c in cves:
            if c not in seen:
                seen.add(c)
                cves_u.append(c)
        for cve_id in cves_u:
            rows.append({"cve_id": cve_id, "packetstorm_title": title or None, "packetstorm_url": link or None})

    _atomic_write_text(dest, json.dumps(rows))
    if on_step:
        on_step(100)
    if on_progress:
        on_progress(f"  complete: {len(rows)} CVE mappings")


def _fetch_github_advisory_db(
    sess: requests.Session,
    url: str,
    dest: Path,
    on_progress: Callable[[str], None] | None = None,
    on_step: Callable[[int], None] | None = None,
) -> None:
    """Download a GitHub advisory snapshot and extract CVE→GHSA mappings."""
    with TemporaryDirectory(prefix="redforge-ghsa-") as tmp:
        tar_path = Path(tmp) / "advisory-database.tar.gz"
        _fetch_simple(sess, url, tar_path, on_progress=on_progress, on_step=on_step)

        out: list[dict] = []
        with tarfile.open(tar_path, "r:gz") as tf:
            members = [m for m in tf.getmembers() if m.isfile()]
            total = max(len(members), 1)
            for i, m in enumerate(members, 1):
                if on_step and i % 200 == 0:
                    on_step(min(i * 100 // total, 99))

                name = m.name
                if "/advisories/" not in name:
                    continue
                if not (name.endswith(".json") or name.endswith(".yml") or name.endswith(".yaml")):
                    continue

                fh = tf.extractfile(m)
                if fh is None:
                    continue
                raw = fh.read()
                try:
                    text = raw.decode("utf-8", errors="ignore")
                except Exception:
                    continue

                ghsa_id = ""
                # Common path fragment: .../GHSA-xxxx-xxxx-xxxx/...
                m_ghsa = re.search(r"(GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4})", name)
                if m_ghsa:
                    ghsa_id = m_ghsa.group(1).upper()

                cves = [c.upper() for c in _CVE_RE.findall(text)]
                if not cves:
                    continue
                seen: set[str] = set()
                cves_u: list[str] = []
                for c in cves:
                    if c not in seen:
                        seen.add(c)
                        cves_u.append(c)

                for cve_id in cves_u:
                    out.append(
                        {
                            "cve_id": cve_id,
                            "ghsa_id": ghsa_id or None,
                            "ghsa_url": (f"https://github.com/advisories/{ghsa_id}" if ghsa_id else None),
                        }
                    )

        _atomic_write_text(dest, json.dumps(out))
        if on_progress:
            on_progress(f"  complete: {len(out)} CVE mappings")


def _fetch_epss(
    sess: requests.Session,
    url: str,
    dest: Path,
    on_progress: Callable[[str], None] | None = None,
    on_step: Callable[[int], None] | None = None,
) -> None:
    """Download EPSS scores (gzip CSV) and normalize to JSON list."""
    if on_step:
        on_step(1)
    resp = sess.get(url, timeout=(_TIMEOUT_CONNECT, _TIMEOUT_SIMPLE), stream=True)
    resp.raise_for_status()
    if on_step:
        on_step(40)

    raw = b"".join(resp.iter_content(chunk_size=_CHUNK))
    with gzip.open(io.BytesIO(raw)) as gz:
        text = gz.read().decode("utf-8")

    if on_step:
        on_step(70)

    rows: list[dict] = []
    reader = csv.DictReader(
        (line for line in text.splitlines() if not line.startswith("#")),
    )
    for row in reader:
        rows.append({
            "cve_id": row["cve"].upper(),
            "epss": float(row["epss"]),
            "percentile": float(row["percentile"]),
        })

    _atomic_write_text(dest, json.dumps(rows))
    if on_step:
        on_step(100)
    if on_progress:
        on_progress(f"  complete: {len(rows)} EPSS entries")


def _fetch_redhat_cve(
    sess: requests.Session,
    url: str,
    dest: Path,
    per_page: int,
    max_pages: int,
    product: str = "",
    on_progress: Callable[[str], None] | None = None,
    on_step: Callable[[int], None] | None = None,
) -> None:
    """Download Red Hat CVEs by concatenating paginated API results.

    Runs the recency window (newest-first, all severities), then a
    severity-priority pass for Critical and Important CVEs so high-severity
    entries are never evicted by the page cap, no matter how new the product
    is. Results are de-duplicated by CVE id.
    """
    items: list = []
    seen: set = set()
    pages_done = 0
    total_pages = max_pages * 3  # recency pass + one pass per priority severity

    def _collect(extra_params: dict) -> None:
        nonlocal pages_done
        for page in range(1, max_pages + 1):
            if on_step:
                on_step(min(pages_done * 100 // total_pages, 99))
            params: dict = {"page": page, "per_page": per_page, **extra_params}
            if product:
                params["product"] = product
            resp = sess.get(url, params=params, timeout=_TIMEOUT_API)
            resp.raise_for_status()
            page_data: list = resp.json()
            pages_done += 1
            if not page_data:
                break
            for cve in page_data:
                cid = cve.get("CVE")
                if cid is not None and cid in seen:
                    continue
                if cid is not None:
                    seen.add(cid)
                items.append(cve)
            if len(page_data) < per_page:
                break
            time.sleep(0.5)

    for label, extra in (
        ("recency", {}),
        ("critical", {"severity": "critical"}),
        ("important", {"severity": "important"}),
    ):
        if on_progress:
            on_progress(f"  {label} pass  ({len(items)} CVEs so far)")
        _collect(extra)

    _atomic_write_text(dest, json.dumps(items))
    if on_progress:
        on_progress(f"  complete: {len(items)} CVEs total")


def _fetch_nvd(
    sess: requests.Session,
    url: str,
    dest: Path,
    per_page: int,
    max_pages: int,
    api_key: str = "",
    on_progress: Callable[[str], None] | None = None,
    on_step: Callable[[int], None] | None = None,
) -> None:
    """Download the paginated NVD CVE feed."""
    results_per_page = min(per_page, 2000)
    pause = 0.6 if api_key else 6.0
    headers = {"apiKey": api_key} if api_key else {}
    vulns: list = []
    total_results = 0

    for i in range(max_pages):
        start = i * results_per_page
        if on_progress:
            on_progress(f"  startIndex={start}  ({len(vulns)}/{total_results or '?'} entries)")
        resp = sess.get(
            url,
            params={"resultsPerPage": results_per_page, "startIndex": start},
            headers=headers,
            timeout=_TIMEOUT_API,
        )
        resp.raise_for_status()
        data = resp.json()
        page_vulns = data.get("vulnerabilities", [])
        vulns.extend(page_vulns)

        total_results = data.get("totalResults", 0)
        if on_step and total_results:
            on_step(min(len(vulns) * 100 // total_results, 99))
        if start + results_per_page >= total_results:
            break
        time.sleep(pause)

    combined = {"totalResults": len(vulns), "vulnerabilities": vulns}
    _atomic_write_text(dest, json.dumps(combined))
    if on_progress:
        on_progress(f"  complete: {len(vulns)} entries total")


def _iter_products(config: dict):
    """Yield ``(short, api_product_name)`` for each configured product version.

    Respects optional TOML fields:
      api_name          — overrides the display name for API queries
      api_version_major — if true, strips to first version segment only (e.g. "1.1" → "1")
    """
    for label, info in config.get("products", {}).items():
        if label == "families" or not isinstance(info, dict):
            continue
        api_name = info.get("api_name") or info["name"]
        major_only = bool(info.get("api_version_major", False))
        for version in info.get("versions", []):
            api_ver = version.split(".")[0] if major_only else version
            yield label + version.replace(".", ""), f"{api_name} {api_ver}"


def run_sync(
    config: dict,
    force: bool = False,
    on_progress: Callable[[str], None] | None = None,
    on_step: Callable[[str, int], None] | None = None,
) -> dict[str, Path]:
    """Download all configured sources into ``data_dir``."""
    sources: dict[str, str] = config.get("sources", {})
    pipeline = config.get("pipeline", {})
    data_dir = Path(pipeline.get("data_dir", "data/raw"))
    per_page = int(pipeline.get("per_page", 100))
    max_pages = int(pipeline.get("max_pages", 50))
    nvd_api_key: str = config.get("credentials", {}).get("nvd_api_key", "")

    data_dir.mkdir(parents=True, exist_ok=True)
    sess = _session()
    downloaded: dict[str, Path] = {}

    def _emit(msg: str) -> None:
        if on_progress:
            on_progress(msg)

    def _run_download(task_name: str, dest: Path, fetch_fn) -> None:
        """Run fetch, update on_step, and record the result."""
        _emit(f"[{task_name}] starting download")

        def _step(pct: int, _n: str = task_name) -> None:
            if on_step:
                on_step(_n, max(0, min(int(pct), 100)))

        def _progress(msg: str, _n: str = task_name) -> None:
            _emit(f"[{_n}] {msg}")

        try:
            fetch_fn(_step, _progress)
            if on_step:
                on_step(task_name, 100)
            downloaded[task_name] = dest
            _emit(f"[{task_name}] saved to {dest}")
        except requests.HTTPError as exc:
            logger.error("%s: HTTP %s", task_name, exc.response.status_code)
            _emit(f"[{task_name}] HTTP error {exc.response.status_code} - skipping")
        except requests.RequestException as exc:
            logger.error("%s: network error - %s", task_name, exc)
            _emit(f"[{task_name}] network error - skipping")
        except Exception as exc:
            logger.exception("%s: unexpected error", task_name)
            _emit(f"[{task_name}] unexpected error: {exc} - skipping")

    for name, url in sources.items():
        if name == "redhat_cve":
            # One file per product: redhat_cve_{short}.json
            for short, product_name in _iter_products(config):
                task_name = f"redhat_cve_{short}"
                dest = data_dir / f"{task_name}.json"
                if dest.exists() and not force:
                    _emit(f"[{task_name}] already cached - skipping")
                    if on_step:
                        on_step(task_name, 100)
                    downloaded[task_name] = dest
                    continue
                _run_download(
                    task_name, dest,
                    lambda _step, _progress, _url=url, _pn=product_name:
                        _fetch_redhat_cve(sess, _url, dest, per_page, max_pages,
                                          product=_pn, on_progress=_progress, on_step=_step),
                )
        else:
            if name == "packetstorm":
                dest = data_dir / "packetstorm.json"
            elif name == "github_advisory_db":
                dest = data_dir / "github_advisories.json"
            elif name == "epss":
                dest = data_dir / "epss.json"
            else:
                suffix = Path(url.split("?")[0]).suffix or ".json"
                dest = data_dir / f"{name}{suffix}"
            if dest.exists() and not force:
                _emit(f"[{name}] already cached - skipping")
                if on_step:
                    on_step(name, 100)
                downloaded[name] = dest
                continue
            _run_download(
                name, dest,
                lambda _step, _progress, _name=name, _url=url:
                    (_fetch_nvd(sess, _url, dest, per_page, max_pages, nvd_api_key,
                                _progress, _step)
                     if _name == "nvd_cvss"
                     else _fetch_packetstorm(sess, _url, dest, _progress, _step)
                     if _name == "packetstorm"
                     else _fetch_github_advisory_db(sess, _url, dest, _progress, _step)
                     if _name == "github_advisory_db"
                     else _fetch_epss(sess, _url, dest, _progress, _step)
                     if _name == "epss"
                     else _fetch_simple(sess, _url, dest, _progress, _step)),
            )

    return downloaded
