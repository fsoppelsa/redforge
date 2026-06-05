"""Report functions for datakit."""

from __future__ import annotations

from pathlib import Path


def export_html(figures: list[object], path: str, title: str = "Report") -> None:
    """HTML export placeholder for a collection of figures.

    The first implementation creates a simple HTML shell so that
    the structure is ready without adding extra dependencies.
    """
    path_obj = Path(path)
    path_obj.parent.mkdir(parents=True, exist_ok=True)
    html = [
        "<html>",
        "<head>",
        f"<title>{title}</title>",
        "</head>",
        "<body>",
        f"<h1>{title}</h1>",
        f"<p>Figures generated: {len(figures)}</p>",
        "</body>",
        "</html>",
    ]
    path_obj.write_text("\n".join(html), encoding="utf-8")
