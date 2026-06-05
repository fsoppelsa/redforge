"""Type handling utilities for datakit."""

from __future__ import annotations

import pandas as pd


def infer_and_cast_types(df: pd.DataFrame, strict: bool = False) -> pd.DataFrame:
    """Best-effort type conversion for clearly numeric columns."""
    result = df.copy()
    for column in result.columns:
        if result[column].dtype == "object":
            converted = pd.to_numeric(result[column], errors="coerce")
            if converted.notna().sum() > 0:
                result[column] = converted
    return result


def cast_column(df: pd.DataFrame, column: str, dtype: str) -> pd.DataFrame:
    """Cast a single column to the given dtype."""
    result = df.copy()
    result[column] = result[column].astype(dtype)
    return result


def parse_dates(df: pd.DataFrame, columns: list[str], format: str | None = None) -> pd.DataFrame:
    """Interpret a list of columns as datetime."""
    result = df.copy()
    for column in columns:
        result[column] = pd.to_datetime(result[column], format=format, errors="coerce")
    return result
