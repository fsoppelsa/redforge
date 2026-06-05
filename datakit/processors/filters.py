"""Filtering functions for datakit."""

from __future__ import annotations

import pandas as pd


def filter_rows(df: pd.DataFrame, condition: str) -> pd.DataFrame:
    """Filter rows using a pandas query expression."""
    return df.query(condition).copy()


def select_columns(df: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    """Keep only the selected columns."""
    return df.loc[:, columns].copy()


def drop_columns(df: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    """Remove the selected columns."""
    return df.drop(columns=columns).copy()
