"""Main pipeline orchestration for datakit."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Literal

import pandas as pd

logger = logging.getLogger(__name__)


@dataclass
class StepLog:
    """Execution record for a single pipeline step."""

    step_name: str
    duration_ms: float
    shape_in: tuple[int, int]
    shape_out: tuple[int, int]


@dataclass
class StepError:
    """Captured error record when ``on_error`` is not ``"raise"``."""

    step_name: str
    error: Exception


@dataclass
class PipelineResult:
    """Output produced by :meth:`Pipeline.run`."""

    df: pd.DataFrame
    steps_log: list[StepLog] = field(default_factory=list)
    errors: list[StepError] = field(default_factory=list)
    figures: list[Any] = field(default_factory=list)
    rdf_graphs: list[Any] = field(default_factory=list)


class Pipeline:
    """Composable data pipeline with a fluent interface.

    The pipeline is designed for cybersecurity datasets like CVE, CVSS, and
    KEV feeds, but remains generic for any tabular source.

    Auxiliary sources registered via :meth:`source` are materialized once
    at the start of :meth:`run` and injected as keyword arguments into every
    step; step-specific kwargs take priority in case of name conflicts.
    """

    def __init__(self, on_error: Literal["raise", "skip", "warn"] = "raise") -> None:
        self._on_error = on_error
        self._reader: tuple[Callable, tuple, dict] | None = None
        self._steps: list[tuple[str, Callable, dict]] = []
        self._source_defs: dict[str, tuple[Callable, tuple, dict] | pd.DataFrame] = {}

    def source(
        self,
        name: str,
        fn_or_df: Callable[..., pd.DataFrame] | pd.DataFrame,
        *args: Any,
        **kwargs: Any,
    ) -> Pipeline:
        """Register a named auxiliary source, available to all steps.

        *fn_or_df* can be a callable (executed once at runtime)
        or an already-materialized DataFrame (used as-is, avoiding
        redundant fetches when the same source feeds multiple pipelines).
        """
        if callable(fn_or_df):
            self._source_defs[name] = (fn_or_df, args, kwargs)
        else:
            self._source_defs[name] = fn_or_df
        return self

    def download(
        self,
        config: "dict | str | Path",
        force: bool = False,
    ) -> Pipeline:
        """Download all URLs in [sources] from *config* to disk and return self.

        Files are written to the directory given by ``config[pipeline][data_dir]``
        (default ``data/raw``). Existing files are skipped unless
        *force* is ``True``. The ``name -> local Path`` mapping is saved in
        ``self.downloaded`` for later inspection.
        """
        from pathlib import Path as _Path
        from datakit.downloader.fetcher import download_sources
        self.downloaded: "dict[str, _Path]" = download_sources(config, force=force)
        return self

    def read(self, reader_fn: Callable, *args: Any, **kwargs: Any) -> Pipeline:
        """Register the data source."""
        self._reader = (reader_fn, args, kwargs)
        return self

    def clean(self, cleaner_fn: Callable, **kwargs: Any) -> Pipeline:
        """Append a cleaning step."""
        self._steps.append(("clean", cleaner_fn, kwargs))
        return self

    def enrich(self, enricher_fn: Callable, **kwargs: Any) -> Pipeline:
        """Append an enrichment step.

    The callable receives ``fn(df, **sources, **kwargs)`` where *sources* is the
    dictionary of all registered sources. If the enricher uses only a
    subset of sources, declare ``**_`` in the signature to absorb
    those not needed.
    """
        self._steps.append(("enrich", enricher_fn, kwargs))
        return self

    def process(self, processor_fn: Callable, **kwargs: Any) -> Pipeline:
        """Append a processing step."""
        self._steps.append(("process", processor_fn, kwargs))
        return self

    def visualize(self, viz_fn: Callable, **kwargs: Any) -> Pipeline:
        """Append a visualization step."""
        self._steps.append(("visualize", viz_fn, kwargs))
        return self

    def write(self, writer_fn: Callable, **kwargs: Any) -> Pipeline:
        """Append an export step."""
        self._steps.append(("write", writer_fn, kwargs))
        return self

    def rdfize(self, rdfizer_fn: Callable, **kwargs: Any) -> Pipeline:
        """Append an RDF conversion step.

        The callable receives ``fn(df, **kwargs)`` and must return an
        ``rdflib.Graph``. The graph is appended to :attr:`PipelineResult.rdf_graphs`
        without modifying the current DataFrame.
        """
        self._steps.append(("rdfize", rdfizer_fn, kwargs))
        return self

    def run(self) -> PipelineResult:
        """Execute all registered steps in sequence.

        Sources registered via :meth:`source` are materialized first
        and injected as keyword arguments into every step callable.
        """
        if self._reader is None:
            raise RuntimeError("No reader registered. Call .read() before .run().")

        logs: list[StepLog] = []
        errors: list[StepError] = []
        figures: list[Any] = []
        rdf_graphs: list[Any] = []

        # ── source materialization ────────────────────────────────────
        fetched_sources: dict[str, pd.DataFrame] = {}
        for name, defn in self._source_defs.items():
            if isinstance(defn, pd.DataFrame):
                fetched_sources[name] = defn
                logs.append(StepLog(f"source:{name}", 0.0, (0, 0), defn.shape))
                logger.info("source '%s': already materialized %s", name, defn.shape)
            else:
                fn, args, kwargs = defn
                t0 = time.perf_counter()
                df_src = fn(*args, **kwargs)
                duration_ms = (time.perf_counter() - t0) * 1000
                fetched_sources[name] = df_src
                logs.append(StepLog(f"source:{name}", duration_ms, (0, 0), df_src.shape))
                logger.info("source '%s': %s (%.1f ms)", name, df_src.shape, duration_ms)

        # ── reader ────────────────────────────────────────────────────────
        reader_fn, args, kwargs = self._reader
        reader_name = reader_fn.__name__
        logger.info("Pipeline started - reader: %s", reader_name)

        t0 = time.perf_counter()
        df: pd.DataFrame = reader_fn(*args, **kwargs)
        duration_ms = (time.perf_counter() - t0) * 1000
        logs.append(StepLog(reader_name, duration_ms, (0, 0), df.shape))

        # ── steps ──────────────────────────────────────────────────────────
        for phase, fn, step_kwargs in self._steps:
            step_name = fn.__name__
            shape_in = df.shape
            # Sources are injected only in enrich steps.
            injected = fetched_sources if phase == "enrich" else {}
            merged_kwargs = {**injected, **step_kwargs}
            try:
                t0 = time.perf_counter()
                result = fn(df, **merged_kwargs)
                duration_ms = (time.perf_counter() - t0) * 1000

                if phase == "visualize":
                    figures.append(result)
                    shape_out = shape_in
                elif phase == "rdfize":
                    rdf_graphs.append(result)
                    shape_out = shape_in
                elif phase == "write" and isinstance(result, pd.DataFrame):
                    df = result
                    shape_out = df.shape
                else:
                    df = result
                    shape_out = df.shape

                logs.append(StepLog(step_name, duration_ms, shape_in, shape_out))
                logger.info(
                    "step '%s': %s -> %s (%.1f ms)",
                    step_name,
                    shape_in,
                    shape_out,
                    duration_ms,
                )
            except Exception as exc:
                errors.append(StepError(step_name, exc))
                if self._on_error == "raise":
                    raise
                if self._on_error == "warn":
                    logger.warning("step '%s' failed: %s - skipped", step_name, exc)

        logger.info("Pipeline complete - final shape: %s", df.shape)
        return PipelineResult(df=df, steps_log=logs, errors=errors, figures=figures, rdf_graphs=rdf_graphs)
