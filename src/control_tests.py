"""
control_tests.py - the automated control-testing engine.

For each of the 48 controls this module:
  1. selects the relevant synthetic dataset
  2. applies the control's scope + detection rule (from config, via rules.py)
  3. groups the violating records by business unit
  4. emits one finding per (control, business unit) group, with the affected
     record IDs and affected-asset count

The result is a list of 137 findings that is then scored by risk_engine.py.
A consistency check compares the re-detected findings against
config.FINDINGS_BLUEPRINT and fails loudly on any drift.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

import config
from rules import violation_mask

_ID_COLUMN = {
    "identities": "identity_id",
    "cloud_resources": "resource_id",
    "applications": "app_id",
    "data_assets": "data_asset_id",
    "vendors": "vendor_id",
}


@dataclass
class Finding:
    finding_id: str
    control_id: str
    control_name: str
    domain: str
    dataset: str
    business_unit: str
    segment: str
    affected_assets: int
    affected_ids: str
    test_summary: str
    business_impact: str
    recommendation: str
    owner: str
    remediation_effort: str
    initiative: str
    roadmap_phase: str
    nist_csf: str
    nist_ai_rmf: str
    osfi_b13: str
    iso_27001: str
    # populated by risk_engine
    likelihood: int = 0
    impact: int = 0
    risk_score: int = 0
    severity: str = ""
    risk_rationale: str = ""
    estimated_risk_reduction: int = 0
    target_remediation_days: int = 0

    def as_row(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class ControlResult:
    control_id: str
    control_name: str
    domain: str
    dataset: str
    in_scope: int
    violations: int
    findings: list = field(default_factory=list)

    @property
    def status(self) -> str:
        """Effective / Partially Effective / Not Effective (worst finding wins)."""
        if not self.findings:
            return "Effective"
        sev = {f.severity for f in self.findings}
        if sev & {"Critical", "High"}:
            return "Not Effective"
        return "Partially Effective"

    @property
    def passed(self) -> bool:
        return not self.findings


def evaluate_control(control: dict, df: pd.DataFrame,
                     blueprint_index: dict) -> ControlResult:
    """Run one control and return its result (findings not yet scored)."""
    from rules import scope_mask

    scope = scope_mask(df, control["scope"])
    violations = violation_mask(df, control)
    viol_df = df[violations]

    result = ControlResult(
        control_id=control["id"], control_name=control["name"],
        domain=control["domain"], dataset=control["dataset"],
        in_scope=int(scope.sum()), violations=int(violations.sum()))

    id_col = _ID_COLUMN[control["dataset"]]
    for bu, group in viol_df.groupby("business_unit", sort=True):
        key = (control["id"], bu)
        bp = blueprint_index.get(key)
        if bp is None:
            raise RuntimeError(
                f"{control['id']}: detected an unplanned violation group for "
                f"business unit '{bu}' ({len(group)} rows) - not in blueprint")
        affected_ids = ";".join(sorted(group[id_col].astype(str)))
        result.findings.append(Finding(
            finding_id=bp["finding_id"],
            control_id=control["id"],
            control_name=control["name"],
            domain=control["domain"],
            dataset=control["dataset"],
            business_unit=str(bu),
            segment=bp["segment"],
            affected_assets=len(group),
            affected_ids=affected_ids,
            test_summary=control["test_summary"],
            business_impact=control["business_impact"],
            recommendation=control["recommendation"],
            owner=control["owner"],
            remediation_effort=control["remediation_effort"],
            initiative=control["initiative"],
            roadmap_phase=control["roadmap_phase"],
            nist_csf=control["nist_csf"],
            nist_ai_rmf=control["nist_ai_rmf"],
            osfi_b13=control["osfi_b13"],
            iso_27001=control["iso_27001"],
        ))
    return result


def run_all_controls(dfs: dict[str, pd.DataFrame]) -> list[ControlResult]:
    blueprint_index = {(f["control_id"], f["business_unit"]): f
                       for f in config.FINDINGS_BLUEPRINT}
    results = [evaluate_control(c, dfs[c["dataset"]], blueprint_index)
               for c in config.CONTROLS]
    _consistency_check(results, blueprint_index)
    return results


def all_findings(results: list[ControlResult]) -> list[Finding]:
    out: list[Finding] = []
    for r in results:
        out.extend(r.findings)
    return out


def _consistency_check(results: list[ControlResult], blueprint_index: dict) -> None:
    findings = all_findings(results)
    detected = {f.finding_id for f in findings}
    expected = {f["finding_id"] for f in config.FINDINGS_BLUEPRINT}

    if detected != expected:
        missing = sorted(expected - detected)
        extra = sorted(detected - expected)
        raise RuntimeError(
            f"finding set drift - missing={missing[:8]} extra={extra[:8]}")

    for f in findings:
        bp = blueprint_index[(f.control_id, f.business_unit)]
        if f.affected_assets != bp["affected_assets"]:
            raise RuntimeError(
                f"{f.finding_id}: detected {f.affected_assets} affected assets, "
                f"blueprint expects {bp['affected_assets']}")

    assert len(findings) == config.TOTAL_FINDINGS_TARGET, (
        f"expected {config.TOTAL_FINDINGS_TARGET} findings, got {len(findings)}")


if __name__ == "__main__":
    import generate_data
    dfs = generate_data.generate()
    results = run_all_controls(dfs)
    findings = all_findings(results)
    passed = [r.control_id for r in results if r.passed]
    print(f"controls evaluated : {len(results)}")
    print(f"controls passed    : {len(passed)} {passed}")
    print(f"findings detected  : {len(findings)}")
