"""Core DataFrame → RDF conversion logic for the RedForge ontology.

The public entry point is :func:`rdfize_product`, which converts a single
product's CVE DataFrame (as produced by ``step1_pull``) into an rdflib Graph.
Callers that need a combined multi-product graph should call this per-product
and merge: ``combined = graph_a + graph_b``.
"""

from __future__ import annotations

import logging
import re

import pandas as pd
from rdflib import XSD, BNode, Graph, Literal, Namespace, RDF, URIRef
from rdflib.namespace import DCTERMS, RDFS

logger = logging.getLogger(__name__)

VS  = Namespace("http://redforge.local/ontology#")
RES = Namespace("http://redforge.local/resource/")

# Red Hat severity labels → ontology individuals.
# "important" is Red Hat's term for CVSS "High".
_SEVERITY_MAP: dict[str, URIRef] = {
    "critical":  VS.CriticalSeverity,
    "important": VS.HighSeverity,
    "high":      VS.HighSeverity,
    "moderate":  VS.MediumSeverity,
    "medium":    VS.MediumSeverity,
    "low":       VS.LowSeverity,
    "none":      VS.NoneSeverity,
}

_PRODUCT_CATEGORY_MAP: dict[str, URIRef] = {
    "rhel": VS.OperatingSystem,
    "rhel8": VS.OperatingSystem,
    "rhel9": VS.OperatingSystem,
    "rhel10": VS.OperatingSystem,
    "openshift": VS.ContainerPlatform,
    "quay": VS.ContainerPlatform,
    "jboss-eap": VS.Middleware,
    "quarkus": VS.Middleware,
    "fuse": VS.Middleware,
    "camel": VS.Middleware,
    "keycloak": VS.SecurityProduct,
    "rhacs": VS.SecurityProduct,
    "ceph": VS.DataPlatform,
    "datagrid": VS.DataPlatform,
    "kafka": VS.DataPlatform,
    "amq-streams": VS.DataPlatform,
    "ansible": VS.ManagementPlatform,
    "satellite": VS.ManagementPlatform,
    "rhacm": VS.ManagementPlatform,
    "openstack": VS.CloudPlatform,
    "rhel-ai": VS.CloudPlatform,
}


def _cve_uri(cve_id: str) -> URIRef:
    return RES[cve_id.upper().replace(":", "-")]


def _slug(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "-", text).strip("-")


def rdfize_product(df: pd.DataFrame, *, product: str) -> Graph:
    """Convert one product's CVE DataFrame to an rdflib Graph.

    Args:
        df:      DataFrame produced by ``step1_pull.pull()`` for a single
                 product — columns: cve_id, cve_url, public_date, cvss_score,
                 rh_severity, in_kev, kev_date_added, in_metasploit,
                 msf_module_name, in_exploitdb, exploitdb_id, exploitdb_title,
                 in_packetstorm, packetstorm_title, packetstorm_url,
                 in_github_advisory, ghsa_id, ghsa_url.
        product: Short product label used to mint the vs:Product URI
                 (e.g. ``"rhel8"``).

    Returns:
        An rdflib.Graph bound to the VS and DCTERMS namespaces.
    """
    g = Graph()
    g.bind("vs",      VS)
    g.bind("dcterms", DCTERMS)
    g.bind("xsd",     XSD)

    product_uri = VS[f"product-{product}"]
    g.add((product_uri, RDF.type,   VS.Product))
    product_type = _PRODUCT_CATEGORY_MAP.get(product.lower().strip())
    if product_type is not None:
        g.add((product_uri, RDF.type, product_type))
    g.add((product_uri, RDFS.label, Literal(product)))

    logger.info("rdfize_product '%s': %d rows", product, len(df))

    for _, row in df.iterrows():
        cve_id = row.get("cve_id")
        if not cve_id or pd.isna(cve_id):
            continue

        vuln = _cve_uri(str(cve_id))

        g.add((vuln, RDF.type,           VS.Vulnerability))
        g.add((vuln, DCTERMS.identifier, Literal(str(cve_id))))
        g.add((vuln, VS.affectsProduct,  product_uri))

        cve_url = row.get("cve_url")
        if cve_url is not None and not pd.isna(cve_url) and str(cve_url).strip():
            g.add((vuln, RDFS.seeAlso, URIRef(str(cve_url).strip())))

        pub = row.get("public_date")
        if pub is not None and not pd.isna(pub):
            g.add((vuln, DCTERMS.issued, Literal(str(pub)[:10], datatype=XSD.date)))

        sev_raw = str(row.get("rh_severity") or "").lower().strip()
        sev_uri = _SEVERITY_MAP.get(sev_raw, VS.NoneSeverity)
        g.add((vuln, VS.severity, sev_uri))

        priority_class = row.get("priority_class")
        if priority_class is not None and not pd.isna(priority_class) and str(priority_class).strip():
            g.add((vuln, VS.priorityClass, Literal(str(priority_class).strip())))

        priority_score = row.get("priority_score")
        if priority_score is not None and not pd.isna(priority_score):
            g.add((vuln, VS.priorityScore, Literal(float(priority_score), datatype=XSD.decimal)))

        score = row.get("cvss_score")
        if score is not None and not pd.isna(score):
            metric = BNode()
            g.add((metric, RDF.type,         VS.CVSSMetric))
            g.add((metric, RDF.type,         VS.CVSSv3Metric))
            g.add((metric, VS.baseScore,     Literal(float(score), datatype=XSD.decimal)))
            g.add((metric, VS.cvssVersion,   Literal("3.1")))
            g.add((metric, VS.baseSeverity,  sev_uri))
            g.add((vuln,   VS.hasCvssMetric, metric))

        if row.get("in_kev"):
            kev = VS[f"kev-{_slug(str(cve_id))}"]
            g.add((kev, RDF.type, VS.KEVEntry))
            kev_date = row.get("kev_date_added")
            if kev_date is not None and not pd.isna(kev_date):
                g.add((kev, DCTERMS.date, Literal(str(kev_date)[:10], datatype=XSD.date)))
            g.add((vuln, VS.hasKEVEntry, kev))

        has_exploit = False
        if row.get("in_metasploit"):
            msf_name = row.get("msf_module_name")
            if msf_name is not None and not pd.isna(msf_name):
                exploit = VS[f"exploit-{_slug(str(msf_name))}"]
                g.add((exploit, RDF.type,   VS.ExploitModule))
                g.add((exploit, RDF.type,   VS.MetasploitModule))
                g.add((exploit, RDFS.label, Literal(str(msf_name))))
                g.add((vuln, VS.hasExploit, exploit))
                has_exploit = True

        if row.get("in_exploitdb"):
            edb_id = row.get("exploitdb_id")
            edb_title = row.get("exploitdb_title")
            # Prefer stable numeric ID when available; fall back to title slug.
            if edb_id is not None and not pd.isna(edb_id) and str(edb_id).strip():
                exploit = VS[f"exploitdb-{_slug(str(edb_id))}"]
                label = f"ExploitDB:{str(edb_id).strip()}"
            elif edb_title is not None and not pd.isna(edb_title) and str(edb_title).strip():
                exploit = VS[f"exploitdb-{_slug(str(edb_title))}"]
                label = f"ExploitDB:{str(edb_title).strip()}"
            else:
                exploit = None
                label = None
            if exploit is not None:
                g.add((exploit, RDF.type,   VS.ExploitModule))
                g.add((exploit, RDF.type,   VS.ExploitDBModule))
                if label is not None:
                    g.add((exploit, RDFS.label, Literal(label)))
                g.add((vuln, VS.hasExploit, exploit))
                has_exploit = True

        if row.get("in_packetstorm"):
            ps_url = row.get("packetstorm_url")
            ps_title = row.get("packetstorm_title")
            if ps_url is not None and not pd.isna(ps_url) and str(ps_url).strip():
                exploit = VS[f"packetstorm-{_slug(str(ps_url))}"]
                g.add((exploit, RDF.type, VS.ExploitModule))
                g.add((exploit, RDF.type, VS.PacketStormModule))
                g.add((exploit, RDFS.label, Literal(f"PacketStorm:{str(ps_title or ps_url).strip()}")))
                g.add((vuln, VS.hasExploit, exploit))
                has_exploit = True

        if row.get("in_github_advisory"):
            ghsa_id = row.get("ghsa_id")
            ghsa_url = row.get("ghsa_url")
            if ghsa_id is not None and not pd.isna(ghsa_id) and str(ghsa_id).strip():
                exploit = VS[f"ghsa-{_slug(str(ghsa_id))}"]
                g.add((exploit, RDF.type, VS.ExploitModule))
                g.add((exploit, RDF.type, VS.GitHubAdvisoryModule))
                g.add((exploit, RDFS.label, Literal(f"GHSA:{str(ghsa_id).strip()}")))
                g.add((vuln, VS.hasExploit, exploit))
                has_exploit = True
            elif ghsa_url is not None and not pd.isna(ghsa_url) and str(ghsa_url).strip():
                exploit = VS[f"ghsa-{_slug(str(ghsa_url))}"]
                g.add((exploit, RDF.type, VS.ExploitModule))
                g.add((exploit, RDF.type, VS.GitHubAdvisoryModule))
                g.add((exploit, RDFS.label, Literal(f"GHSA:{str(ghsa_url).strip()}")))
                g.add((vuln, VS.hasExploit, exploit))
                has_exploit = True

        if row.get("in_kev") or has_exploit:
            g.add((vuln, RDF.type, VS.ActivelyExploitedVulnerability))
        else:
            g.add((vuln, RDF.type, VS.LatentVulnerability))

    logger.info("rdfize_product '%s': %d triples", product, len(g))
    return g
