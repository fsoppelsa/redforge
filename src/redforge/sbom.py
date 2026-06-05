"""CycloneDX SBOM parsing and normalization helpers."""

from __future__ import annotations

import json
from typing import Any
import xml.etree.ElementTree as ET


def parse_cyclonedx_sbom(data: bytes | str | dict[str, Any]) -> list[dict[str, str]]:
    """Parse a CycloneDX JSON SBOM and return normalized component records."""
    if isinstance(data, dict):
        obj = data
    else:
        raw = data if isinstance(data, (bytes, str)) else ""
        raw_text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
        raw_strip = raw_text.lstrip()
        if raw_strip.startswith("<"):
            return _parse_cyclonedx_xml(raw_text)
        try:
            obj = json.loads(raw_text)
        except Exception as exc:  # pragma: no cover - JSON parser details are not stable
            raise ValueError("Invalid SBOM (expected CycloneDX JSON or XML).") from exc

    # CycloneDX JSON
    if str(obj.get("bomFormat", "")).lower() != "cyclonedx":
        raise ValueError("Only CycloneDX SBOMs are supported (JSON or XML).")

    components: list[dict[str, str]] = []
    for component in obj.get("components", []):
        if not isinstance(component, dict):
            continue
        name = str(component.get("name") or "").strip()
        if not name:
            continue
        components.append(
            {
                "name": name,
                "version": str(component.get("version") or "").strip(),
                "purl": str(component.get("purl") or "").strip(),
                "bom_ref": str(component.get("bom-ref") or component.get("bom_ref") or "").strip(),
                "type": str(component.get("type") or "").strip(),
            }
        )

    return components


def _parse_cyclonedx_xml(xml_text: str) -> list[dict[str, str]]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:  # pragma: no cover
        raise ValueError("Invalid SBOM XML.") from exc

    if not root.tag.endswith("bom"):
        raise ValueError("Only CycloneDX SBOMs are supported (JSON or XML).")

    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}", 1)[0].lstrip("{")

    def q(name: str) -> str:
        return f"{{{ns}}}{name}" if ns else name

    out: list[dict[str, str]] = []
    comps_parent = root.find(q("components"))
    if comps_parent is None:
        return out

    for comp in comps_parent.findall(q("component")):
        if not isinstance(comp.tag, str):
            continue
        name_el = comp.find(q("name"))
        name = (name_el.text or "").strip() if name_el is not None else ""
        if not name:
            continue
        ver_el = comp.find(q("version"))
        purl_el = comp.find(q("purl"))
        out.append(
            {
                "name": name,
                "version": (ver_el.text or "").strip() if ver_el is not None else "",
                "purl": (purl_el.text or "").strip() if purl_el is not None else "",
                "bom_ref": str(comp.attrib.get("bom-ref") or comp.attrib.get("bom_ref") or "").strip(),
                "type": str(comp.attrib.get("type") or "").strip(),
            }
        )

    return out
