"""CVE-specific enrichment functions for datakit."""

from __future__ import annotations

import pandas as pd

from datakit.enrichers.lookup_enricher import add_lookup_value


def add_cve_metadata(
    df: pd.DataFrame,
    lookup_df: pd.DataFrame,
    source_column: str = "cve_id",
    lookup_column: str = "cve_id",
    value_column: str = "kev",
    output_column: str = "is_kev",
) -> pd.DataFrame:
    """Convenience wrapper for common CVE/KEV enrichment workflows."""
    return add_lookup_value(
        df=df,
        lookup_df=lookup_df,
        source_column=source_column,
        lookup_column=lookup_column,
        value_column=value_column,
        output_column=output_column,
    )
