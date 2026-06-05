"""Lettore CSV per datakit."""

from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd

logger = logging.getLogger(__name__)


def read_csv(
    path: str | Path,
    encoding: str = "utf-8",
    separator: str = ",",
    **kwargs,
) -> pd.DataFrame:
    """Legge un file CSV in un DataFrame."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not path.is_file():
        raise ValueError(f"Path is not a file: {path}")

    try:
        df = pd.read_csv(path, encoding=encoding, sep=separator, **kwargs)
    except Exception as exc:
        raise ValueError(f"Cannot parse '{path}' as CSV: {exc}") from exc

    logger.info("read_csv: loaded %s - shape %s", path.name, df.shape)
    return df
