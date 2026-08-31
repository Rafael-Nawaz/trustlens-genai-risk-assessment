"""
generate_data.py - build the synthetic NorthStar Bank environment.

Produces six CSVs in data/:
    identities.csv        (1,500 workforce / privileged / service identities)
    cloud_resources.csv   (250 Azure resources)
    applications.csv      (100 applications and service accounts)
    data_assets.csv       (100 sensitive data assets)
    vendors.csv           (50 third-party vendors)
    control_catalog.csv   (the 48-control catalogue)

Design
------
1. A *fully compliant* baseline is generated for every dataset - every attribute
   that a control tests is set to its passing value for every row.
2. Violations are then injected strictly according to config.FINDINGS_BLUEPRINT
   (`apply_blueprint_violations`).  Because the baseline is otherwise clean, the
   control-testing engine re-detects exactly the 137 planted findings.
3. Everything is driven by a fixed seed (config.RANDOM_SEED) so outputs are
   reproducible.

All data is synthetic.  NorthStar Bank is fictional.
"""

from __future__ import annotations

import os

import numpy as np
import pandas as pd

import config
from rules import scope_mask, scope_coercion_values

SEED = config.RANDOM_SEED
BU = config.BUSINESS_UNITS
DATA_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "data")

# Datasets where planted rows must not be shared between findings.  None are
# currently needed: no control's "plant" column is another control's "scope"
# column, so row reuse cannot create or erase an unplanned finding.
DISJOINT_DATASETS: set[str] = set()

OWNER_POOL = [
    "a.tremblay", "s.okafor", "m.leblanc", "j.nguyen", "r.patel", "c.dubois",
    "k.anderson", "l.moreau", "d.singh", "h.romano", "t.gagnon", "b.oconnell",
]


def _even_business_units(n: int, rng: np.random.Generator) -> np.ndarray:
    """Assign business units as evenly as possible, then shuffle."""
    base = np.tile(np.arange(len(BU)), n // len(BU) + 1)[:n]
    rng.shuffle(base)
    return np.array(BU)[base]


def _owners(n: int, rng: np.random.Generator) -> np.ndarray:
    return rng.choice(OWNER_POOL, size=n)


# ---------------------------------------------------------------------------
# Baseline builders (all rows compliant on every tested attribute)
# ---------------------------------------------------------------------------

def build_identities(rng: np.random.Generator) -> pd.DataFrame:
    n = config.DATASET_SIZES["identities"]
    emp_type = rng.choice(
        ["Employee", "Contractor", "ServiceAccount"], size=n, p=[0.80, 0.13, 0.07])
    status = np.where(
        emp_type == "ServiceAccount", "Active",
        rng.choice(["Active", "Disabled", "Terminated"], size=n, p=[0.88, 0.06, 0.06]))
    privileged = (emp_type != "ServiceAccount") & (rng.random(n) < 0.14)
    service_account = emp_type == "ServiceAccount"
    account_enabled = status == "Active"          # compliant: disabled/term -> not enabled

    role_count = np.where(privileged, rng.integers(2, 12, n),
                          np.where(service_account, rng.integers(1, 8, n),
                                   rng.integers(1, 7, n)))

    df = pd.DataFrame({
        "identity_id": [f"ID-{i:05d}" for i in range(1, n + 1)],
        "display_name": [f"user{i:05d}" for i in range(1, n + 1)],
        "employee_type": emp_type,
        "department": rng.choice(config.DEPARTMENTS, size=n),
        "business_unit": _even_business_units(n, rng),
        "status": status,
        "privileged": privileged,
        "service_account": service_account,
        "account_enabled": account_enabled,
        "mfa_enabled": True,                        # compliant baseline
        "last_login_days": rng.integers(0, 76, n),  # compliant: not dormant
        "role_count": role_count,
        "account_owner": _owners(n, rng),
        "access_review_completed": True,            # compliant
        "admin_used_daily": False,                  # compliant
    })
    df["risk_level"] = np.where(df["privileged"], "High",
                        np.where(df["service_account"], "Medium", "Low"))
    return df


def build_cloud_resources(rng: np.random.Generator) -> pd.DataFrame:
    n = config.DATASET_SIZES["cloud_resources"]
    rtype = rng.choice(
        ["StorageAccount", "VirtualMachine", "SQLDatabase", "KeyVault",
         "AppService", "FunctionApp", "AKSCluster"],
        size=n, p=[0.22, 0.20, 0.16, 0.10, 0.14, 0.10, 0.08])
    env = rng.choice(["Prod", "NonProd"], size=n, p=[0.55, 0.45])
    internet_facing = rng.random(n) < 0.25

    df = pd.DataFrame({
        "resource_id": [f"RES-{i:04d}" for i in range(1, n + 1)],
        "resource_type": rtype,
        "environment": env,
        "business_unit": _even_business_units(n, rng),
        "internet_facing": internet_facing,
        "public_access": False,           # compliant
        "encryption_enabled": True,       # compliant
        "logging_enabled": True,          # compliant
        "approved_config": True,          # compliant
        "excess_admin_assignments": False,  # compliant
        "backup_enabled": True,           # compliant
        "network_restricted": True,       # compliant
        "unsupported_runtime": False,     # compliant
        "owner": _owners(n, rng),
    })
    df["risk_tier"] = np.select(
        [(df.environment == "Prod") & df.internet_facing,
         df.environment == "Prod"],
        ["Critical", "High"], default="Medium")
    return df


def build_applications(rng: np.random.Generator) -> pd.DataFrame:
    n = config.DATASET_SIZES["applications"]
    ai_integrated = rng.random(n) < 0.65
    third_party_model = ai_integrated & (rng.random(n) < 0.55)
    risk_tier = rng.choice(["Critical", "High", "Medium", "Low"],
                           size=n, p=[0.18, 0.30, 0.34, 0.18])
    open_critical_vulns = rng.random(n) < 0.15

    df = pd.DataFrame({
        "app_id": [f"APP-{i:04d}" for i in range(1, n + 1)],
        "app_name": [f"app-{i:04d}" for i in range(1, n + 1)],
        "app_type": rng.choice(
            ["WebApp", "API", "BatchJob", "Integration", "ServiceAccount"],
            size=n, p=[0.30, 0.28, 0.14, 0.16, 0.12]),
        "business_unit": _even_business_units(n, rng),
        "environment": rng.choice(["Prod", "NonProd"], size=n, p=[0.6, 0.4]),
        "service_account": rng.random(n) < 0.25,
        "secret_rotation_days": rng.integers(30, 91, n),
        "data_sensitivity": rng.choice(
            ["Low", "Medium", "High", "Restricted"], size=n, p=[0.2, 0.35, 0.3, 0.15]),
        "risk_tier": risk_tier,
        "ai_integrated": ai_integrated,
        "third_party_model": third_party_model,
        "open_critical_vulns": open_critical_vulns,
        "owner": _owners(n, rng),
        # --- AI governance attributes (compliant baseline) ---
        "human_oversight": True,
        "ai_logging_enabled": True,
        "use_case_approved": True,
        "input_filtering": True,
        "ai_risk_classified": True,
        "output_monitoring": True,
        "model_data_handling_documented": True,
        # --- security operations attributes (compliant baseline) ---
        "siem_onboarded": True,
        "alert_owner_assigned": True,
        "monitored": True,
        "ir_runbook_exists": True,
        "ai_incident_playbook": True,
        "event_severity_defined": True,
        "vuln_sla_days": np.where(open_critical_vulns, rng.integers(5, 31, n), 0),
        "log_retention_days": rng.integers(365, 1096, n),
    })
    return df


def build_data_assets(rng: np.random.Generator) -> pd.DataFrame:
    """Constructed (not purely random) so every business unit has enough
    PII / AI-accessible rows to receive planted violations without coercion."""
    n = config.DATASET_SIZES["data_assets"]
    bus = _even_business_units(n, rng)

    data_type, contains_pii, classification, ai_accessible = [], [], [], []
    for i in range(n):
        # ~60% PII within each unit, ~45% AI-accessible
        is_pii = (i % 5) < 3
        if is_pii:
            dt = rng.choice(["Customer PII", "KYC Documents", "Credit Bureau Data",
                             "Transaction Records", "Employee Records"])
            cls = rng.choice(["Confidential", "Restricted"], p=[0.6, 0.4])
        else:
            dt = rng.choice(["Marketing Analytics", "Internal Documentation",
                             "Aggregated Reporting", "Reference Data"])
            cls = rng.choice(["Internal", "Public"], p=[0.7, 0.3])
        data_type.append(dt)
        contains_pii.append(bool(is_pii))
        classification.append(str(cls))
        ai_accessible.append((i % 20) < 9)

    df = pd.DataFrame({
        "data_asset_id": [f"DA-{i:04d}" for i in range(1, n + 1)],
        "data_name": [f"dataset-{i:04d}" for i in range(1, n + 1)],
        "data_type": data_type,
        "business_unit": bus,
        "contains_pii": contains_pii,
        "classification": classification,
        "pii_classified": True,                   # compliant
        "ai_accessible": ai_accessible,
        "region": "Canada",
        "region_outside_canada": False,           # compliant
        "encrypted": True,                         # compliant
        "approved_ai_access": True,                # compliant
        "retention_defined": True,                 # compliant
        "retention_days": rng.integers(365, 2556, n),   # compliant (<= 7y)
        "minimisation_reviewed": True,             # compliant
        "transfer_approved": True,                 # compliant
        "owner": _owners(n, rng),
    })
    df["risk_tier"] = np.select(
        [df.classification == "Restricted", df.classification == "Confidential"],
        ["Critical", "High"], default="Medium")
    return df


def build_vendors(rng: np.random.Generator) -> pd.DataFrame:
    n = config.DATASET_SIZES["vendors"]
    service_type = rng.choice(
        ["Cloud Infrastructure", "Managed AI Services", "Payment Processing",
         "Data Analytics", "Core Banking Platform", "Marketing SaaS",
         "HR SaaS", "Security Services"], size=n)
    ai_vendor = (service_type == "Managed AI Services") | (rng.random(n) < 0.18)
    criticality = rng.choice(["Critical", "High", "Medium", "Low"],
                             size=n, p=[0.24, 0.30, 0.30, 0.16])
    risk_rating = rng.choice(["Critical", "High", "Medium", "Low"],
                             size=n, p=[0.10, 0.30, 0.42, 0.18])

    df = pd.DataFrame({
        "vendor_id": [f"VEN-{i:03d}" for i in range(1, n + 1)],
        "vendor_name": [f"Vendor {i:03d}" for i in range(1, n + 1)],
        "service_type": service_type,
        "business_unit": _even_business_units(n, rng),
        "ai_vendor": ai_vendor,
        "criticality": criticality,
        "risk_rating": risk_rating,
        "data_access": rng.choice(["None", "Internal", "PII"], size=n, p=[0.3, 0.4, 0.3]),
        "security_assessment": True,        # compliant
        "ai_risk_review": True,             # compliant
        "contract_review": True,            # compliant
        "control_evidence_on_file": True,   # compliant
        "exception_approved": True,         # compliant
        "remediation_date_set": True,       # compliant
        "oversight_documented": True,       # compliant
        "data_retention_defined": rng.random(n) < 0.8,
        "owner": _owners(n, rng),
    })
    return df


# ---------------------------------------------------------------------------
# Violation injection
# ---------------------------------------------------------------------------

def _resolve(spec, rng: np.random.Generator):
    if isinstance(spec, list) and spec and spec[0] == "randint":
        return int(rng.integers(spec[1], spec[2] + 1))
    return spec


def apply_blueprint_violations(dfs: dict[str, pd.DataFrame],
                               rng: np.random.Generator) -> None:
    controls_by_id = {c["id"]: c for c in config.CONTROLS}
    used_by_dataset: dict[str, set] = {k: set() for k in dfs}
    used_by_control: dict[str, set] = {}

    for f in config.FINDINGS_BLUEPRINT:
        control = controls_by_id[f["control_id"]]
        dataset = f["dataset"]
        df = dfs[dataset]
        bu = f["business_unit"]
        n = f["affected_assets"]
        disjoint = dataset in DISJOINT_DATASETS
        used_ctrl = used_by_control.setdefault(f["control_id"], set())

        in_bu = df["business_unit"] == bu
        in_scope = scope_mask(df, control["scope"])
        blocked = used_by_dataset[dataset] if disjoint else used_ctrl

        candidates = df.index[in_bu & in_scope & ~df.index.isin(blocked)].tolist()
        chosen = candidates[:n]

        if len(chosen) < n and not disjoint:
            # coerce extra rows in the same business unit into scope
            need = n - len(chosen)
            filler = df.index[in_bu & ~df.index.isin(blocked)
                              & ~df.index.isin(chosen)].tolist()[:need]
            for col, val in scope_coercion_values(control["scope"]).items():
                df.loc[filler, col] = val
            chosen += filler

        if len(chosen) < n:
            raise RuntimeError(
                f"{f['finding_id']} ({f['control_id']}, {bu}): need {n} rows, "
                f"only {len(chosen)} available in dataset '{dataset}'")

        for col, spec in control["plant"].items():
            for idx in chosen:
                df.at[idx, col] = _resolve(spec, rng)

        used_by_dataset[dataset].update(chosen)
        used_ctrl.update(chosen)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def generate() -> dict[str, pd.DataFrame]:
    rng = np.random.default_rng(SEED)
    dfs = {
        "identities": build_identities(rng),
        "cloud_resources": build_cloud_resources(rng),
        "applications": build_applications(rng),
        "data_assets": build_data_assets(rng),
        "vendors": build_vendors(rng),
    }
    apply_blueprint_violations(dfs, rng)
    return dfs


def main() -> dict[str, pd.DataFrame]:
    os.makedirs(DATA_DIR, exist_ok=True)
    config.self_check()
    dfs = generate()

    total = 0
    for name, df in dfs.items():
        expected = config.DATASET_SIZES[name]
        assert len(df) == expected, f"{name}: {len(df)} rows, expected {expected}"
        path = os.path.join(DATA_DIR, f"{name}.csv")
        df.to_csv(path, index=False)
        total += len(df)
        print(f"  {name:<16} {len(df):>5} rows  -> {os.path.relpath(path)}")

    catalogue = pd.DataFrame(config.CONTROL_CATALOG)
    catalogue.to_csv(os.path.join(DATA_DIR, "control_catalog.csv"), index=False)
    print(f"  {'control_catalog':<16} {len(catalogue):>5} rows  -> "
          f"{os.path.relpath(os.path.join(DATA_DIR, 'control_catalog.csv'))}")

    assert total == config.TOTAL_ASSETS_TARGET, (
        f"total assets {total} != {config.TOTAL_ASSETS_TARGET}")
    assert len(catalogue) == 48
    print(f"\nOK  total assets / identities = {total}  |  controls = {len(catalogue)}")
    return dfs


if __name__ == "__main__":
    main()
