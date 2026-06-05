"""Tests for pipeline SPARQL query."""

import sys
import importlib
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
if "redforge" in sys.modules and not hasattr(sys.modules["redforge"], "__path__"):
    del sys.modules["redforge"]


def _sample_graph():
    from rdflib import Graph, Namespace, RDF, Literal
    from rdflib.namespace import DCTERMS
    VS = Namespace("http://redforge.local/ontology#")
    RES = Namespace("http://redforge.local/resource/")
    g = Graph()
    g.bind("vs", VS)
    vuln = RES["CVE-2021-44228"]
    g.add((vuln, RDF.type, VS.Vulnerability))
    g.add((vuln, DCTERMS.identifier, Literal("CVE-2021-44228")))
    return g


def test_query_returns_dataframe():
    query = importlib.import_module("src.redforge.pipeline").query
    g = _sample_graph()
    df = query(g, "SELECT ?cve WHERE { ?cve a <http://redforge.local/ontology#Vulnerability> }")
    assert isinstance(df, pd.DataFrame)
    assert "cve" in df.columns
    assert len(df) == 1


def test_query_empty_result():
    query = importlib.import_module("src.redforge.pipeline").query
    g = _sample_graph()
    df = query(g, "SELECT ?x WHERE { ?x a <http://redforge.local/ontology#ExploitModule> }")
    assert isinstance(df, pd.DataFrame)
    assert len(df) == 0


def test_normalize_sparql_input_fixes_common_iri_escapes():
    normalize_sparql_input = importlib.import_module("src.redforge.commands.query").normalize_sparql_input

    sparql = (
        r"PREFIX vs: <http://redforge.local/ontology\#\> "
        r"PREFIX dct: <http://purl.org/dc/terms/\> "
        r"SELECT ?cve WHERE { ?cve a vs:Vulnerability . }"
    )

    normalized = normalize_sparql_input(sparql)

    assert r"\#" not in normalized
    assert r"\>" not in normalized
    assert "<http://redforge.local/ontology#>" in normalized
    assert "<http://purl.org/dc/terms/>" in normalized


def test_query_falls_back_when_rdflib_order_by_type_errors():
    from rdflib import Graph, Namespace, RDF, Literal
    from rdflib.namespace import DCTERMS, XSD
    query = importlib.import_module("src.redforge.pipeline").query

    vs = Namespace("http://redforge.local/ontology#")
    res = Namespace("http://redforge.local/resource/")
    g = Graph()

    for idx, days in enumerate(["10", "2", None], start=1):
        vuln = res[f"CVE-2024-000{idx}"]
        metric = res[f"metric-{idx}"]
        kev = res[f"kev-{idx}"]
        g.add((vuln, RDF.type, vs.Vulnerability))
        g.add((vuln, DCTERMS.identifier, Literal(f"CVE-2024-000{idx}")))
        g.add((vuln, DCTERMS.issued, Literal("2024-01-01", datatype=XSD.date)))
        g.add((vuln, vs.hasCvssMetric, metric))
        g.add((metric, vs.baseScore, Literal(str(10 - idx), datatype=XSD.decimal)))
        g.add((vuln, vs.hasKEVEntry, kev))
        g.add((kev, DCTERMS.date, Literal("2024-01-11", datatype=XSD.date)))
        if days is not None:
            g.add((vuln, vs.severityLabel, Literal(days)))

    sparql = (
        "PREFIX vs: <http://redforge.local/ontology#> "
        "PREFIX dct: <http://purl.org/dc/terms/> "
        "PREFIX xsd: <http://www.w3.org/2001/XMLSchema#> "
        "SELECT ?cveId ?cvss ?daysToKev WHERE { "
        "?cve a vs:Vulnerability ; dct:identifier ?cveId ; vs:hasKEVEntry ?kev ; vs:hasCvssMetric ?metric . "
        "?metric vs:baseScore ?cvss . "
        "OPTIONAL { ?cve vs:severityLabel ?daysToKev . } "
        "} ORDER BY ASC(xsd:integer(?daysToKev)) DESC(?cvss) LIMIT 2"
    )

    df = query(g, sparql)

    assert list(df["cveId"]) == ["CVE-2024-0002", "CVE-2024-0001"]
