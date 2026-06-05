"""Arricchimento generico basato su lookup per datakit."""

from __future__ import annotations

import pandas as pd


def add_lookup_value(
    df: pd.DataFrame,
    lookup_df: pd.DataFrame,
    source_column: str,
    lookup_column: str,
    value_column: str,
    output_column: str,
) -> pd.DataFrame:
    """Arricchisce un DataFrame con un valore proveniente da una tabella di lookup."""
    if source_column not in df.columns:
        raise KeyError(f"Source column '{source_column}' not found in input DataFrame.")
    if lookup_column not in lookup_df.columns:
        raise KeyError(f"Lookup column '{lookup_column}' not found in lookup DataFrame.")
    if value_column not in lookup_df.columns:
        raise KeyError(f"Value column '{value_column}' not found in lookup DataFrame.")

    lookup = (
        lookup_df[[lookup_column, value_column]]
        .drop_duplicates(subset=[lookup_column])
        .rename(columns={lookup_column: source_column, value_column: output_column})
    )
    return df.merge(lookup, on=source_column, how="left")
