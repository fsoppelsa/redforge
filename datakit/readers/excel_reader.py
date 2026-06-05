"""Excel reader placeholder for datakit."""

from __future__ import annotations

from pathlib import Path

import pandas as pd


def read_excel(path: str | Path, sheet_name: str | int = 0, **kwargs) -> pd.DataFrame:
    """Excel reader placeholder.

    Excel import is deferred as a future MVP extension.
    """
    raise NotImplementedError(
        "read_excel is a placeholder in datakit for now. "
        "Implement it when Excel support is needed."
    )
