"""Download configured sources from a TOML config to local disk."""

from __future__ import annotations

import logging
import tomllib
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

_USER_AGENT = "RedForge/1.0 datakit (https://github.com/fsoppelsa/fsoppelsa-opendata)"
_CHUNK = 65_536


def _fetch(url: str, dest: Path, session: requests.Session) -> None:
    resp = session.get(url, timeout=30, stream=True)
    resp.raise_for_status()
    with open(dest, "wb") as fh:
        for chunk in resp.iter_content(chunk_size=_CHUNK):
            fh.write(chunk)


def download_sources(
    config: dict | str | Path,
    data_dir: str | Path | None = None,
    force: bool = False,
) -> dict[str, Path]:
    """Download all URLs listed in [sources] from *config* to *data_dir*.

    Args:
        config: Already-parsed configuration dict, or path to a TOML file.
        data_dir: Destination directory. Falls back to ``config[pipeline][data_dir]``,
            then ``"data/raw"``.
        force: Re-download even if the file already exists on disk.

    Returns:
        Mapping source name → local path for each source in the config.
    """
    if not isinstance(config, dict):
        config_path = Path(config)
        with open(config_path, "rb") as fh:
            config = tomllib.load(fh)

    sources: dict[str, str] = config.get("sources", {})
    if not sources:
        logger.warning("download_sources: no [sources] entries found in config")
        return {}

    if data_dir is None:
        data_dir = config.get("pipeline", {}).get("data_dir", "data/raw")
    dest_dir = Path(data_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    session = requests.Session()
    session.headers["User-Agent"] = _USER_AGENT

    downloaded: dict[str, Path] = {}
    for name, url in sources.items():
        suffix = Path(url.split("?")[0]).suffix or ".json"
        dest = dest_dir / f"{name}{suffix}"

        if dest.exists() and not force:
            logger.info("download_sources: '%s' cached at %s (skip)", name, dest)
            downloaded[name] = dest
            continue

        logger.info("download_sources: downloading '%s' from %s", name, url)
        _fetch(url, dest, session)
        logger.info("download_sources: saved '%s' -> %s", name, dest)
        downloaded[name] = dest

    return downloaded
