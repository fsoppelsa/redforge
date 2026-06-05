"""Funzioni di grafici per datakit."""

from __future__ import annotations

from typing import Any

import pandas as pd


def _plt() -> Any:
    try:
        import matplotlib.pyplot as plt
    except ImportError as exc:  # pragma: no cover - dipendenza mancante
        raise ImportError("matplotlib is required for datakit.visualizer") from exc
    return plt


def plot_bar(df: pd.DataFrame, x: str, y: str, title: str = "", color: str | None = None) -> object:
    plt = _plt()
    fig, ax = plt.subplots()
    ax.bar(df[x], df[y], color=color)
    ax.set_title(title)
    ax.set_xlabel(x)
    ax.set_ylabel(y)
    fig.tight_layout()
    return fig


def plot_line(df: pd.DataFrame, x: str, y: str | list[str], title: str = "") -> object:
    plt = _plt()
    fig, ax = plt.subplots()
    if isinstance(y, list):
        for col in y:
            ax.plot(df[x], df[col], label=col)
        ax.legend()
    else:
        ax.plot(df[x], df[y])
    ax.set_title(title)
    ax.set_xlabel(x)
    ax.set_ylabel(y if isinstance(y, str) else "value")
    fig.tight_layout()
    return fig


def plot_scatter(df: pd.DataFrame, x: str, y: str, hue: str | None = None) -> object:
    plt = _plt()
    fig, ax = plt.subplots()
    if hue and hue in df.columns:
        for label, group in df.groupby(hue):
            ax.scatter(group[x], group[y], label=str(label))
        ax.legend()
    else:
        ax.scatter(df[x], df[y])
    ax.set_xlabel(x)
    ax.set_ylabel(y)
    fig.tight_layout()
    return fig


def plot_histogram(df: pd.DataFrame, column: str, bins: int = 30) -> object:
    plt = _plt()
    fig, ax = plt.subplots()
    ax.hist(df[column].dropna(), bins=bins)
    ax.set_xlabel(column)
    ax.set_ylabel("count")
    fig.tight_layout()
    return fig


def plot_heatmap(df: pd.DataFrame, title: str = "") -> object:
    plt = _plt()
    fig, ax = plt.subplots()
    corr = df.select_dtypes(include="number").corr()
    im = ax.imshow(corr, cmap="viridis")
    ax.set_xticks(range(len(corr.columns)))
    ax.set_xticklabels(corr.columns, rotation=45, ha="right")
    ax.set_yticks(range(len(corr.columns)))
    ax.set_yticklabels(corr.columns)
    ax.set_title(title)
    fig.colorbar(im, ax=ax)
    fig.tight_layout()
    return fig
