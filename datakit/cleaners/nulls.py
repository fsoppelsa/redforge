"""Null value handling utilities for datakit."""

from __future__ import annotations

from typing import Literal

import pandas as pd


def drop_null_rows(df: pd.DataFrame, threshold: float = 1.0) -> pd.DataFrame:
    """Remove rows whose null ratio exceeds the given threshold."""
    if not 0 < threshold <= 1:
        raise ValueError("threshold must be in the interval (0, 1].")
    limit = int(df.shape[1] * threshold)
    return df.dropna(thresh=limit).copy()


def fill_nulls(
    df: pd.DataFrame,
    strategy: Literal["mean", "median", "mode", "constant"],
    value=None,
) -> pd.DataFrame:
    """Fill null values with a simple strategy."""
    result = df.copy()
    if strategy == "constant":
        return result.fillna(value)
    numeric_columns = result.select_dtypes(include="number").columns
    if strategy == "mean":
        for column in numeric_columns:
            result[column] = result[column].fillna(result[column].mean())
    elif strategy == "median":
        for column in numeric_columns:
            result[column] = result[column].fillna(result[column].median())
    elif strategy == "mode":
        for column in result.columns:
            mode = result[column].mode(dropna=True)
            if not mode.empty:
                result[column] = result[column].fillna(mode.iloc[0])
    return result


def flag_nulls(df: pd.DataFrame, columns: list[str] | None = None) -> pd.DataFrame:
    """Add boolean *_is_null flags for the selected columns."""
    result = df.copy()
    target_columns = columns or list(result.columns)
    for column in target_columns:
        result[f"{column}_is_null"] = result[column].isna()
    return result
