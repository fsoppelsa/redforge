"""Lettore JSON per datakit."""

from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd

logger = logging.getLogger(__name__)


def read_json(
    path: str | Path,
    orient: str = "records",
    **kwargs,
) -> pd.DataFrame:
    """Legge un file JSON in un DataFrame."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not path.is_file():
        raise ValueError(f"Path is not a file: {path}")

    try:
        df = pd.read_json(path, orient=orient, **kwargs)
    except Exception as exc:
        raise ValueError(f"Cannot parse '{path}' as JSON: {exc}") from exc

    logger.info("read_json: loaded %s - shape %s", path.name, df.shape)
    return df
