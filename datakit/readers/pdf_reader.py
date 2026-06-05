"""PDF reader placeholder for datakit."""

from __future__ import annotations

from pathlib import Path

import pandas as pd


def read_pdf(path: str | Path, page: int | list[int] | None = None, **kwargs) -> pd.DataFrame:
    """PDF reader placeholder.

    PDF import is deferred as a future MVP extension.
    """
    raise NotImplementedError(
        "read_pdf is a placeholder in datakit for now. "
        "Implement it when PDF support is needed."
    )
