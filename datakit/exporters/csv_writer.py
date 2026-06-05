"""Scrittore CSV per datakit."""

from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd

logger = logging.getLogger(__name__)


def save_csv(
    df: pd.DataFrame,
    path: str | Path,
    separator: str = ",",
    encoding: str = "utf-8",
    index: bool = False,
    **kwargs,
) -> pd.DataFrame:
    """Salva un DataFrame in CSV e lo restituisce invariato."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, sep=separator, encoding=encoding, index=index, **kwargs)
    logger.info("save_csv: written %s rows to '%s'", len(df), path)
    return df
