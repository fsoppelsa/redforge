"""Vulnerability scoring functions for datakit."""

from __future__ import annotations

import pandas as pd

# Thresholds from the KEV+EPSS+CVSS algorithm (arXiv:2506.01220v1)
T_EPSS_HIGH: float = 0.088   # "high" threshold — aligned with the paper
T_EPSS_MED:  float = 0.010   # "medium" threshold — attention signal
T_CVSS:      float = 7.0

# Backward-compatible alias used by earlier steps
T_EPSS = T_EPSS_HIGH

_PRIORITY_SCORE: dict[str, int] = {
    "1-Act":    10,
    "2-Attend":  7,
    "3-Track":   4,
    "4-Defer":   1,
}


def compute_vulnerability_score(
    df: pd.DataFrame,
    cvss_column: str = "cvss_score",
    kev_column: str = "is_kev",
    score_column: str = "risk_score",
) -> pd.DataFrame:
    """Compute a simple risk score from CVSS and KEV presence.

    The formula is deliberately lightweight: CVSS is the base score
    and KEV presence adds a fixed bonus.
    """
    result = df.copy()
    cvss = pd.to_numeric(result[cvss_column], errors="coerce").fillna(0.0)
    kev = result[kev_column].fillna(False).astype(bool)
    result[score_column] = (cvss + kev.astype(int) * 2).clip(upper=10)
    return result


def classify_vulnerability(
    df: pd.DataFrame,
    kev_column: str = "in_kev",
    epss_column: str = "epss_score",
    cvss_column: str = "cvss_score",
    class_column: str = "priority_class",
    score_column: str = "priority_score",
) -> pd.DataFrame:
    """Classify each CVE as Act/Attend/Track/Defer (SSVC-inspired, arXiv:2506.01220v1).

    Decision tree:
      Act    — high threat (KEV or EPSS >= 0.088) AND CVSS >= 7  → apply immediately
      Attend — high threat with CVSS < 7, or medium EPSS
               (0.01 <= EPSS < 0.088) with CVSS >= 7            → schedule soon
      Track  — no significant threat signal, CVSS >= 7            → monitor
      Defer  — low threat and CVSS < 7                            → defer
    """
    result = df.copy()

    kev = (
        result[kev_column].fillna(False).astype(bool)
        if kev_column in result.columns
        else pd.Series(False, index=result.index)
    )
    epss = pd.to_numeric(
        result.get(epss_column, pd.Series(0.0, index=result.index)),
        errors="coerce",
    ).fillna(0.0)
    cvss = pd.to_numeric(
        result[cvss_column] if cvss_column in result.columns else pd.Series(0.0, index=result.index),
        errors="coerce",
    ).fillna(0.0)

    high_threat = kev | (epss >= T_EPSS_HIGH)
    med_threat  = epss >= T_EPSS_MED
    high_cvss   = cvss >= T_CVSS

    classes = pd.Series("4-Defer", index=result.index, dtype="object")
    classes[~high_threat & high_cvss]                      = "3-Track"
    classes[~high_threat & med_threat & high_cvss]         = "2-Attend"
    classes[high_threat & ~high_cvss]                      = "2-Attend"
    classes[high_threat & high_cvss]                       = "1-Act"

    result[class_column] = classes.astype("string")
    result[score_column] = classes.map(_PRIORITY_SCORE).fillna(1).astype(int)
    return result
