"""CLI output formatting for DataFrames."""

from __future__ import annotations

import pandas as pd


def print_df(df: pd.DataFrame, fmt: str = "table") -> None:
    """Print *df* in the requested format (table, json, csv)."""
    if df.empty:
        print("No results.")
        return

    if fmt == "json":
        print(df.to_json(orient="records", indent=2))
    elif fmt == "csv":
        print(df.to_csv(index=False), end="")
    else:
        _rich_table(df)


def _rich_table(df: pd.DataFrame) -> None:
    try:
        from rich.console import Console
        from rich.table import Table

        table = Table(show_header=True, header_style="bold cyan")
        for col in df.columns:
            table.add_column(str(col))
        for _, row in df.iterrows():
            table.add_row(*[str(v) for v in row])
        Console().print(table)
    except ImportError:
        print(df.to_string(index=False))
