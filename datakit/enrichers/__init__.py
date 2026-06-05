"""Funzioni di arricchimento dati per datakit."""

from datakit.enrichers.cve_enricher import add_cve_metadata
from datakit.enrichers.lookup_enricher import add_lookup_value

__all__ = ["add_cve_metadata", "add_lookup_value"]
