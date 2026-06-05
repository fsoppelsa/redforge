"""Load the RedForge ontology into an rdflib Graph."""

from __future__ import annotations

from pathlib import Path

from rdflib import Graph

ONTOLOGY_PATH = Path(__file__).parent / "vuln.ttl"


def load() -> Graph:
    g = Graph()
    g.parse(str(ONTOLOGY_PATH), format="turtle")
    return g
