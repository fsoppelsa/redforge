"""Ranking functions for datakit."""

from __future__ import annotations

import pandas as pd


def rank_vulnerabilities(
    df: pd.DataFrame,
    score_column: str = "risk_score",
    rank_column: str = "priority_rank",
    ascending: bool = False,
) -> pd.DataFrame:
    """Rank vulnerabilities by score."""
    result = df.copy()
    result[rank_column] = result[score_column].rank(method="dense", ascending=ascending)
    return result.sort_values(by=score_column, ascending=ascending).reset_index(drop=True)
