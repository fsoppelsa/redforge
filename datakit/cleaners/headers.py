"""Header normalization utilities for datakit."""

from __future__ import annotations

import logging
import re
from typing import Literal

import pandas as pd

logger = logging.getLogger(__name__)


def normalize_headers(
    df: pd.DataFrame,
    case: Literal["snake", "lower", "upper"] = "snake",
) -> pd.DataFrame:
    """Normalize DataFrame column names.

    The default ``snake`` mode fits CVE/CVSS datasets well.
    """
    if case not in ("snake", "lower", "upper"):
        raise ValueError(f"Invalid case '{case}'. Choose 'snake', 'lower', or 'upper'.")

    def _to_snake(name: str) -> str:
        name = str(name).strip()
        name = re.sub(r"[\s\-./\\]+", "_", name)
        name = re.sub(r"[^\w]", "_", name)
        name = re.sub(r"_+", "_", name)
        name = name.strip("_")
        return name.lower()

    if case == "snake":
        mapping = {col: _to_snake(col) for col in df.columns}
    elif case == "lower":
        mapping = {col: str(col).strip().lower() for col in df.columns}
    else:
        mapping = {col: str(col).strip().upper() for col in df.columns}

    result = df.rename(columns=mapping)
    changed = [f"'{old}' -> '{new}'" for old, new in mapping.items() if old != new]
    if changed:
        logger.info("normalize_headers: renamed %d column(s): %s", len(changed), ", ".join(changed))
    return result


def drop_unnamed_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Remove unnamed or index-artifact columns."""
    columns = [col for col in df.columns if not str(col).startswith("Unnamed:")]
    return df.loc[:, columns].copy()
