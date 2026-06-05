"""Tests for pipeline step 2 (RDF conversion)."""

import sys
import importlib
from pathlib import Path

import pandas as pd
import pytest
from rdflib import RDF, Literal, Namespace, URIRef, XSD
from rdflib.namespace import RDFS

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

VS = Namespace("http://redforge.local/ontology#")
_RES = Namespace("http://redforge.local/resource/")


def test_ontology_loads():
    g = importlib.import_module("src.redforge.ontology").load()
    assert len(g) > 0


def test_empty_data_returns_empty_graph():
    g = importlib.import_module("src.redforge.pipeline").build_graph({}, {})
    assert len(g) == 0


def test_single_cve_basic_triples():
    build_graph = importlib.import_module("src.redforge.pipeline").build_graph
    df = pd.DataFrame([{
        "cve_id":        "CVE-2021-44228",
        "cve_url":       "https://access.redhat.com/security/cve/CVE-2021-44228",
        "public_date":   "2021-12-10",
        "cvss_score":    10.0,
        "rh_severity":   "critical",
        "priority_class": "1-Act",
        "priority_score": 37.5,
        "in_kev":        True,
        "kev_date_added": "2021-12-10",
        "in_metasploit": False,
        "msf_module_name": None,
    }])
    g = build_graph({"rhel8": df}, {})

    vuln = _RES["CVE-2021-44228"]
    assert (vuln, RDF.type, VS.Vulnerability) in g
    assert (vuln, VS.severity, VS.CriticalSeverity) in g
    assert (vuln, VS.affectsProduct, VS[f"product-rhel8"]) in g
    assert (vuln, VS.hasKEVEntry, VS["kev-CVE-2021-44228"]) in g
    assert (vuln, VS.priorityClass, Literal("1-Act")) in g
    assert (vuln, VS.priorityScore, Literal(37.5, datatype=XSD.decimal)) in g
    assert (vuln, RDFS.seeAlso, URIRef("https://access.redhat.com/security/cve/CVE-2021-44228")) in g


def test_severity_mapping_important():
    build_graph = importlib.import_module("src.redforge.pipeline").build_graph
    df = pd.DataFrame([{
        "cve_id": "CVE-2024-0001", "cve_url": "https://access.redhat.com/security/cve/CVE-2024-0001", "public_date": None,
        "cvss_score": 8.1, "rh_severity": "important",
        "in_kev": False, "kev_date_added": None,
        "in_metasploit": False, "msf_module_name": None,
    }])
    g = build_graph({"rhel9": df}, {})
    vuln = _RES["CVE-2024-0001"]
    assert (vuln, VS.severity, VS.HighSeverity) in g


def test_metasploit_exploit_linked():
    build_graph = importlib.import_module("src.redforge.pipeline").build_graph
    df = pd.DataFrame([{
        "cve_id": "CVE-2017-0144", "cve_url": "https://access.redhat.com/security/cve/CVE-2017-0144", "public_date": "2017-03-14",
        "cvss_score": 9.3, "rh_severity": "critical",
        "in_kev": False, "kev_date_added": None,
        "in_metasploit": True, "msf_module_name": "exploit/windows/smb/ms17_010_eternalblue",
    }])
    g = build_graph({"rhel8": df}, {})
    vuln = _RES["CVE-2017-0144"]
    exploit_triples = list(g.triples((vuln, VS.hasExploit, None)))
    assert len(exploit_triples) == 1


def test_rows_with_null_cve_skipped():
    build_graph = importlib.import_module("src.redforge.pipeline").build_graph
    df = pd.DataFrame([
        {"cve_id": None, "public_date": None, "cvss_score": None,
         "cve_url": None, "rh_severity": None, "in_kev": False, "kev_date_added": None,
         "in_metasploit": False, "msf_module_name": None},
        {"cve_id": "CVE-2024-9999", "cve_url": "https://access.redhat.com/security/cve/CVE-2024-9999", "public_date": None, "cvss_score": 7.5,
         "rh_severity": "high", "in_kev": False, "kev_date_added": None,
         "in_metasploit": False, "msf_module_name": None},
    ])
    g = build_graph({"rhel9": df}, {})
    vuln_triples = list(g.triples((None, RDF.type, VS.Vulnerability)))
    assert len(vuln_triples) == 1
