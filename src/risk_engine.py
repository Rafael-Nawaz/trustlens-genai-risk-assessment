"""
risk_engine.py - risk scoring, readiness scoring and consulting prioritisation.

Methodology (see docs/methodology.md)
------------------------------------
Risk Score = Likelihood (1-5) x Impact (1-5)  ->  1-25
    20-25 Critical | 15-19 High | 8-14 Medium | 1-7 Low

Organisational readiness (0-100) = 100 - (sum of severity-weighted finding
penalties / normalisation constant), clamped to 0-100.  A per-domain readiness
score is calculated the same way over each domain's findings.

Prioritisation ranks remediation initiatives by "risk points removed per unit of
effort" and places each on a quick-win / strategic / low-priority quadrant.
"""

from __future__ import annotations

import statistics

import config
from control_tests import Finding

_BP = {(f["control_id"], f["business_unit"]): f for f in config.FINDINGS_BLUEPRINT}


# ---------------------------------------------------------------------------
# Finding-level scoring
# ---------------------------------------------------------------------------

def score_findings(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        bp = _BP[(f.control_id, f.business_unit)]
        f.likelihood = bp["likelihood"]
        f.impact = bp["impact"]
        f.risk_score = f.likelihood * f.impact
        f.severity = config.severity_from_score(f.risk_score)
        f.estimated_risk_reduction = bp["estimated_risk_reduction"]
        f.target_remediation_days = bp["target_remediation_days"]
        f.risk_rationale = (
            f"Likelihood {f.likelihood}/5: {f.affected_assets} affected "
            f"{f.dataset.replace('_', ' ')} in {f.business_unit}, control gap is "
            f"{'directly exploitable' if f.likelihood >= 4 else 'exploitable under common conditions' if f.likelihood == 3 else 'exploitable in limited conditions'}. "
            f"Impact {f.impact}/5: {f.domain} weakness affecting the GenAI "
            f"platform's exposure to customer data and enterprise systems."
        )
        # blueprint / re-detected severity must agree
        assert f.severity == bp["severity"], (
            f"{f.finding_id}: severity {f.severity} != blueprint {bp['severity']}")
    return findings


# ---------------------------------------------------------------------------
# Readiness scoring
# ---------------------------------------------------------------------------

def _penalty(findings: list[Finding]) -> float:
    return sum(config.READINESS_SEVERITY_PENALTY[f.severity] for f in findings)


def compute_readiness(findings: list[Finding]) -> dict:
    overall = 100.0 - _penalty(findings) / config.READINESS_PENALTY_DIVISOR
    overall = round(max(0.0, min(100.0, overall)), 1)

    by_domain = {}
    for domain in config.DOMAINS:
        dfs = [f for f in findings if f.domain == domain]
        score = 100.0 - _penalty(dfs) / config.READINESS_DOMAIN_DIVISOR
        by_domain[domain] = round(max(0.0, min(100.0, score)), 1)

    return {"overall": overall, "by_domain": by_domain, "band": readiness_band(overall)}


def readiness_band(score: float) -> str:
    if score >= 85:
        return "LOW RISK"
    if score >= 75:
        return "MODERATE RISK"
    if score >= 60:
        return "HIGH RISK"
    return "CRITICAL RISK"


# ---------------------------------------------------------------------------
# Initiative prioritisation
# ---------------------------------------------------------------------------

def prioritize(findings: list[Finding]) -> list[dict]:
    """Aggregate findings into remediation initiatives and rank them."""
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.initiative, []).append(f)

    rows = []
    for initiative, items in groups.items():
        total_risk = sum(f.risk_score for f in items)
        risk_points_removed = round(
            sum(f.risk_score * f.estimated_risk_reduction / 100 for f in items), 1)
        efforts = [config.EFFORT_RANK[f.remediation_effort] for f in items]
        effort_rank = round(statistics.mean(efforts))
        effort_label = {1: "Low", 2: "Medium", 3: "High"}[effort_rank]
        severities = [f.severity for f in items]
        rows.append({
            "initiative": initiative,
            "domains": ", ".join(sorted({f.domain for f in items})),
            "findings": len(items),
            "critical_high": sum(s in ("Critical", "High") for s in severities),
            "total_risk_score": total_risk,
            "avg_risk_reduction_pct": round(
                statistics.mean(f.estimated_risk_reduction for f in items), 1),
            "risk_points_removed": risk_points_removed,
            "implementation_effort": effort_label,
            "effort_rank": effort_rank,
            # weight critical/high exposure heavily - "fund what stops the worst outcomes"
            "priority_score": round(
                (risk_points_removed + 6 * sum(s in ("Critical", "High")
                                               for s in severities)) / effort_rank, 1),
            "owner": statistics.mode(f.owner for f in items),
            "target_days": max(f.target_remediation_days for f in items),
        })

    median_removed = statistics.median(r["risk_points_removed"] for r in rows)
    for r in rows:
        # an initiative is "high value" if it removes above-median risk points
        # OR it addresses at least one Critical/High finding
        high_value = (r["risk_points_removed"] >= median_removed
                      or r["critical_high"] >= 1)
        low_effort = r["effort_rank"] <= 1
        if high_value and low_effort:
            r["quadrant"] = "Quick Win"
        elif high_value and not low_effort:
            r["quadrant"] = "Strategic Initiative"
        elif not high_value and not low_effort:
            r["quadrant"] = "Low Priority"
        else:
            r["quadrant"] = "Fill-In"

    rows.sort(key=lambda r: r["priority_score"], reverse=True)
    for i, r in enumerate(rows, 1):
        r["rank"] = i
    return rows


def top_initiatives(findings: list[Finding], n: int = 10) -> list[dict]:
    return prioritize(findings)[:n]


def top_risks(findings: list[Finding], n: int = 10) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (f.risk_score, f.affected_assets, -ord(f.finding_id[-1])),
        reverse=True,
    )[:n]
