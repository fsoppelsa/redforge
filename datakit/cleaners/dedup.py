"""Deduplication utilities for datakit."""

from __future__ import annotations

from typing import Literal

import pandas as pd


def drop_duplicates(
    df: pd.DataFrame,
    subset: list[str] | None = None,
    keep: Literal["first", "last"] = "first",
) -> pd.DataFrame:
    """Remove duplicate rows."""
    return df.drop_duplicates(subset=subset, keep=keep).copy()


def flag_duplicates(df: pd.DataFrame, subset: list[str] | None = None) -> pd.DataFrame:
    """Add a boolean flag marking duplicate rows."""
    result = df.copy()
    result["is_duplicate"] = result.duplicated(subset=subset, keep=False)
    return result
