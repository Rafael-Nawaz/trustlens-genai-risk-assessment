"""
TrustLens - central configuration (the "spine" of the assessment).

This module is the single source of truth for:
  * the 48-control catalogue (6 domains x 8 controls)
  * the 137-finding blueprint (per-control "finding slices")
  * dataset sizing, the random seed and scoring parameters

Both the synthetic-data generator (generate_data.py) and the control-testing
engine (control_tests.py) read from here, so the headline metrics
(2,000 assets / 48 controls / 137 findings) are produced by code and stay
internally consistent.  Nothing here is hand-typed into a report.

Run `python src/config.py` to execute the self-check.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Global parameters
# ---------------------------------------------------------------------------

RANDOM_SEED = 42

CLIENT_NAME = "NorthStar Bank"

DATASET_SIZES = {
    "identities": 1500,
    "cloud_resources": 250,
    "applications": 100,
    "data_assets": 100,
    "vendors": 50,
}
TOTAL_ASSETS_TARGET = 2000

# Business units are attached to every record and are the dimension the
# assessment slices findings by (keeps the model simple and bank-realistic).
BUSINESS_UNITS = [
    "Retail Banking",
    "Commercial Banking",
    "Wealth Management",
    "Payments",
    "Digital & AI",
    "Shared Technology",
]

DEPARTMENTS = [
    "Finance", "Technology", "Operations", "Retail Banking",
    "Risk & Compliance", "Customer Support", "Human Resources", "Legal",
]

DOMAINS = [
    "Identity & Access Management",
    "Cloud Security",
    "Privacy & Data Protection",
    "AI Governance",
    "Security Operations",
    "Governance & Third-Party Risk",
]

# Target severity distribution for the 137 findings.
TARGET_SEVERITY_MIX = {"Critical": 9, "High": 23, "Medium": 61, "Low": 44}
TOTAL_FINDINGS_TARGET = 137

# Readiness score tuning (see docs/methodology.md).  Penalty points removed
# from 100 per finding, then normalised.  Tuned so the organisation lands in
# the "meaningful capability, not yet launch-ready" band (65-75).
READINESS_SEVERITY_PENALTY = {"Critical": 10.0, "High": 6.0, "Medium": 2.4, "Low": 0.9}
READINESS_PENALTY_DIVISOR = 12.9          # normalisation constant (overall score)
READINESS_DOMAIN_DIVISOR = 2.35           # normalisation constant (per-domain score)
READINESS_TARGET_BAND = (65, 75)

# Risk matrix -> severity bands (Risk Score = Likelihood x Impact, 1-25)
SEVERITY_BANDS = [
    (20, 25, "Critical"),
    (15, 19, "High"),
    (8, 14, "Medium"),
    (1, 7, "Low"),
]

EFFORT_RANK = {"Low": 1, "Medium": 2, "High": 3}


def severity_from_score(score: int) -> str:
    for lo, hi, label in SEVERITY_BANDS:
        if lo <= score <= hi:
            return label
    raise ValueError(f"risk score {score} outside 1-25")


# Canonical (likelihood, impact) pairs per severity.  A control's slices
# rotate through the variants for a little natural spread.
_LI_VARIANTS = {
    "Critical": [(5, 5), (5, 4), (4, 5)],
    "High":     [(4, 4), (5, 3), (3, 5)],
    "Medium":   [(3, 4), (4, 3), (3, 3), (2, 5)],
    "Low":      [(2, 3), (3, 2), (2, 2), (1, 5)],
}


def likelihood_impact(severity: str, variant_index: int) -> tuple[int, int]:
    variants = _LI_VARIANTS[severity]
    return variants[variant_index % len(variants)]


# ---------------------------------------------------------------------------
# 48 controls.  Each control carries:
#   id, name, domain, dataset, description, test_summary,
#   business_impact, recommendation, remediation_effort, initiative, owner,
#   framework crosswalk (nist_csf, nist_ai_rmf, osfi_b13, iso_27001),
#   scope   -> which rows are in-scope for the test  ({} = all rows)
#   detect  -> how a violating row is recognised
#   plant   -> how the generator injects a violation
#   roadmap_phase -> Stabilize / Govern / Scale
# ---------------------------------------------------------------------------

# detect DSL:
#   {"type": "eq",  "cols": {col: value, ...}}          row matches all
#   {"type": "gt",  "col": c, "value": v}               row[c] > v
#   {"type": "lt",  "col": c, "value": v}               row[c] < v
#   {"type": "isin","col": c, "values": [...]}          row[c] in values
# plant DSL: {col: literal}  or  {col: ["randint", lo, hi]}

CONTROLS: list[dict] = [
    # ================= 1. Identity & Access Management ====================
    dict(
        id="IAM-01", name="Privileged accounts must enforce phishing-resistant MFA",
        domain=DOMAINS[0], dataset="identities",
        description="All privileged / administrative identities must have multi-factor "
                    "authentication enforced.",
        test_summary="Privileged identities where mfa_enabled = False.",
        business_impact="Privileged accounts without MFA are the single most common entry "
                        "point for ransomware and wire-fraud in financial institutions; a "
                        "compromised admin could reach customer data through the new GenAI "
                        "platform.",
        recommendation="Enforce Conditional Access requiring phishing-resistant MFA for all "
                       "privileged roles; block legacy authentication.",
        remediation_effort="Low", initiative="Privileged MFA Enforcement",
        owner="IAM Engineering Lead",
        nist_csf="PR.AA-03", nist_ai_rmf="GOVERN 1.2", osfi_b13="B-13 Domain 3 - Identity & Access",
        iso_27001="A.8.2 / A.5.17", roadmap_phase="Stabilize",
        scope={"privileged": True}, detect={"type": "eq", "cols": {"mfa_enabled": False}},
        plant={"mfa_enabled": False},
    ),
    dict(
        id="IAM-02", name="Terminated and disabled staff must not retain active access",
        domain=DOMAINS[0], dataset="identities",
        description="Accounts for terminated or disabled workers must be de-provisioned.",
        test_summary="Identities with status in (Terminated, Disabled) where account_enabled = True.",
        business_impact="Orphaned active accounts are unmonitored and frequently abused by "
                        "departing insiders or attackers who bought the credentials.",
        recommendation="Automate joiner-mover-leaver de-provisioning from the HR system; run a "
                       "weekly reconciliation of disabled workers vs. active accounts.",
        remediation_effort="Medium", initiative="Joiner-Mover-Leaver Automation",
        owner="IAM Engineering Lead",
        nist_csf="PR.AA-01", nist_ai_rmf="-", osfi_b13="B-13 Domain 3 - Identity & Access",
        iso_27001="A.5.16 / A.5.18", roadmap_phase="Stabilize",
        scope={"status": ["Terminated", "Disabled"]},
        detect={"type": "eq", "cols": {"account_enabled": True}},
        plant={"account_enabled": True},
    ),
    dict(
        id="IAM-03", name="Dormant accounts must be reviewed and disabled",
        domain=DOMAINS[0], dataset="identities",
        description="Accounts with no sign-in for 90+ days must be reviewed and disabled.",
        test_summary="Enabled identities with last_login_days > 90.",
        business_impact="Dormant accounts expand the attack surface with no business benefit "
                        "and dilute the accuracy of access reviews.",
        recommendation="Introduce an automated dormancy policy that disables accounts after "
                       "90 days of inactivity, with owner notification.",
        remediation_effort="Low", initiative="Automated Access Reviews",
        owner="IAM Operations Manager",
        nist_csf="PR.AA-01", nist_ai_rmf="-", osfi_b13="B-13 Domain 3 - Identity & Access",
        iso_27001="A.5.18", roadmap_phase="Scale",
        scope={"account_enabled": True},
        detect={"type": "gt", "col": "last_login_days", "value": 90},
        plant={"last_login_days": ["randint", 95, 400]},
    ),
    dict(
        id="IAM-04", name="Excessive privileged role assignments must be limited",
        domain=DOMAINS[0], dataset="identities",
        description="Privileged identities should hold only the roles required for their function.",
        test_summary="Privileged identities holding more than 12 assigned roles.",
        business_impact="Role sprawl makes least-privilege unenforceable and increases the "
                        "blast radius of any single account compromise.",
        recommendation="Run an entitlement review for over-permissioned admins; adopt "
                       "just-in-time role activation for high-privilege roles.",
        remediation_effort="Medium", initiative="Privileged Access Modernisation",
        owner="IAM Engineering Lead",
        nist_csf="PR.AA-05", nist_ai_rmf="-", osfi_b13="B-13 Domain 3 - Identity & Access",
        iso_27001="A.8.2", roadmap_phase="Govern",
        scope={"privileged": True},
        detect={"type": "gt", "col": "role_count", "value": 12},
        plant={"role_count": ["randint", 13, 26]},
    ),
    dict(
        id="IAM-05", name="Service accounts must follow least privilege",
        domain=DOMAINS[0], dataset="identities",
        description="Non-human / service identities must be scoped to a single workload.",
        test_summary="Service accounts holding more than 8 roles.",
        business_impact="Broad service accounts are hard to rotate and are a favoured "
                        "persistence mechanism once an environment is breached.",
        recommendation="Re-scope over-permissioned service accounts to workload-specific "
                       "managed identities; enforce credential rotation.",
        remediation_effort="Medium", initiative="Privileged Access Modernisation",
        owner="Platform Engineering Lead",
        nist_csf="PR.AA-05", nist_ai_rmf="-", osfi_b13="B-13 Domain 3 - Identity & Access",
        iso_27001="A.8.2", roadmap_phase="Govern",
        scope={"service_account": True},
        detect={"type": "gt", "col": "role_count", "value": 8},
        plant={"role_count": ["randint", 9, 20]},
    ),
    dict(
        id="IAM-06", name="Privileged accounts must have a documented owner",
        domain=DOMAINS[0], dataset="identities",
        description="Every privileged identity must map to a named, accountable owner.",
        test_summary="Privileged identities where account_owner = UNASSIGNED.",
        business_impact="Unowned privileged accounts cannot be reviewed, attested or revoked "
                        "with confidence during an incident.",
        recommendation="Assign and record an accountable owner for every privileged account; "
                       "block creation without an owner attribute.",
        remediation_effort="Low", initiative="IAM Governance Uplift",
        owner="IAM Operations Manager",
        nist_csf="GV.RR-02", nist_ai_rmf="-", osfi_b13="B-13 Domain 1 - Governance",
        iso_27001="A.5.2 / A.8.2", roadmap_phase="Govern",
        scope={"privileged": True},
        detect={"type": "eq", "cols": {"account_owner": "UNASSIGNED"}},
        plant={"account_owner": "UNASSIGNED"},
    ),
    dict(
        id="IAM-07", name="Periodic access certifications must be completed",
        domain=DOMAINS[0], dataset="identities",
        description="Access for privileged and sensitive roles must be recertified each cycle.",
        test_summary="Privileged identities where access_review_completed = False.",
        business_impact="Missed certifications mean access accumulates unchecked, undermining "
                        "segregation-of-duties controls that regulators expect.",
        recommendation="Stand up a quarterly access-certification campaign with automated "
                       "reviewer routing and manager attestation.",
        remediation_effort="Medium", initiative="Automated Access Reviews",
        owner="IAM Operations Manager",
        nist_csf="PR.AA-05", nist_ai_rmf="-", osfi_b13="B-13 Domain 3 - Identity & Access",
        iso_27001="A.5.18", roadmap_phase="Scale",
        scope={"privileged": True},
        detect={"type": "eq", "cols": {"access_review_completed": False}},
        plant={"access_review_completed": False},
    ),
    dict(
        id="IAM-08", name="Administrative accounts must not be used for daily activity",
        domain=DOMAINS[0], dataset="identities",
        description="Privileged accounts must be separate from day-to-day user accounts.",
        test_summary="Privileged identities flagged admin_used_daily = True (email/browsing on admin account).",
        business_impact="Using admin accounts for routine work exposes high-privilege "
                        "credentials to phishing and drive-by compromise.",
        recommendation="Issue separate standard accounts to administrators; enforce Privileged "
                       "Access Workstations for tier-0 roles.",
        remediation_effort="Medium", initiative="Privileged Access Modernisation",
        owner="IAM Engineering Lead",
        nist_csf="PR.AA-05", nist_ai_rmf="-", osfi_b13="B-13 Domain 3 - Identity & Access",
        iso_27001="A.8.2", roadmap_phase="Govern",
        scope={"privileged": True},
        detect={"type": "eq", "cols": {"admin_used_daily": True}},
        plant={"admin_used_daily": True},
    ),

    # ========================= 2. Cloud Security =========================
    dict(
        id="CLD-01", name="Storage resources must not be publicly accessible",
        domain=DOMAINS[1], dataset="cloud_resources",
        description="Object / blob storage must not allow anonymous or public network access.",
        test_summary="Storage resources where public_access = True.",
        business_impact="Publicly exposed storage is the leading cause of large-scale financial "
                        "data breaches and would be catastrophic for customer trust and OSFI standing.",
        recommendation="Disable public network access on all storage accounts; enforce via Azure "
                       "Policy with deny effect and remediate exceptions.",
        remediation_effort="Low", initiative="Cloud Exposure Remediation",
        owner="Cloud Security Lead",
        nist_csf="PR.DS-01", nist_ai_rmf="-", osfi_b13="B-13 Domain 2 - Technology Operations",
        iso_27001="A.5.23 / A.8.20", roadmap_phase="Stabilize",
        scope={"resource_type": "StorageAccount"},
        detect={"type": "eq", "cols": {"public_access": True}},
        plant={"public_access": True},
    ),
    dict(
        id="CLD-02", name="Sensitive cloud resources must have encryption enabled",
        domain=DOMAINS[1], dataset="cloud_resources",
        description="Data-bearing resources must use encryption at rest with managed keys.",
        test_summary="Cloud resources where encryption_enabled = False.",
        business_impact="Unencrypted data stores fail baseline regulatory expectations and "
                        "materially increase breach impact.",
        recommendation="Enable encryption at rest across all data services; migrate to "
                       "customer-managed keys for Restricted workloads.",
        remediation_effort="Medium", initiative="Cloud Exposure Remediation",
        owner="Cloud Security Lead",
        nist_csf="PR.DS-01", nist_ai_rmf="-", osfi_b13="B-13 Domain 3 - Data Security",
        iso_27001="A.8.24", roadmap_phase="Govern",
        scope={},
        detect={"type": "eq", "cols": {"encryption_enabled": False}},
        plant={"encryption_enabled": False},
    ),
    dict(
        id="CLD-03", name="Security and diagnostic logging must be enabled",
        domain=DOMAINS[1], dataset="cloud_resources",
        description="Cloud resources must emit control-plane and data-plane logs to the SIEM.",
        test_summary="Cloud resources where logging_enabled = False.",
        business_impact="Without resource logging, the SOC is blind to misuse of the GenAI "
                        "platform and cannot investigate incidents or meet breach-reporting timelines.",
        recommendation="Enforce diagnostic settings via Azure Policy to route all resource logs "
                       "to the central Log Analytics workspace.",
        remediation_effort="Medium", initiative="Continuous Cloud Control Monitoring",
        owner="Cloud Security Lead",
        nist_csf="DE.CM-01", nist_ai_rmf="MEASURE 2.6", osfi_b13="B-13 Domain 2 - Technology Operations",
        iso_27001="A.8.15", roadmap_phase="Stabilize",
        scope={},
        detect={"type": "eq", "cols": {"logging_enabled": False}},
        plant={"logging_enabled": False},
    ),
    dict(
        id="CLD-04", name="Internet-facing services must use approved configurations",
        domain=DOMAINS[1], dataset="cloud_resources",
        description="Externally reachable resources must pass the hardened configuration baseline.",
        test_summary="Internet-facing resources where approved_config = False.",
        business_impact="Misconfigured external services are routinely exploited within hours of "
                        "exposure and provide a foothold into the cloud tenant.",
        recommendation="Remediate to the CIS/vendor baseline; require security review sign-off "
                       "before any resource is made internet-facing.",
        remediation_effort="Medium", initiative="Cloud Exposure Remediation",
        owner="Cloud Security Lead",
        nist_csf="PR.PS-01", nist_ai_rmf="-", osfi_b13="B-13 Domain 2 - Technology Operations",
        iso_27001="A.8.9 / A.8.20", roadmap_phase="Stabilize",
        scope={"internet_facing": True},
        detect={"type": "eq", "cols": {"approved_config": False}},
        plant={"approved_config": False},
    ),
    dict(
        id="CLD-05", name="Cloud administrator permissions must follow least privilege",
        domain=DOMAINS[1], dataset="cloud_resources",
        description="Resource-level privileged role assignments must be minimised and time-bound.",
        test_summary="Resources flagged excess_admin_assignments = True.",
        business_impact="Standing broad cloud admin rights let a single compromised identity "
                        "pivot across the entire environment, including AI data stores.",
        recommendation="Adopt Privileged Identity Management with just-in-time elevation and "
                       "approval for all owner/contributor assignments.",
        remediation_effort="High", initiative="Privileged Access Modernisation",
        owner="Cloud Security Lead",
        nist_csf="PR.AA-05", nist_ai_rmf="-", osfi_b13="B-13 Domain 3 - Identity & Access",
        iso_27001="A.8.2", roadmap_phase="Govern",
        scope={},
        detect={"type": "eq", "cols": {"excess_admin_assignments": True}},
        plant={"excess_admin_assignments": True},
    ),
    dict(
        id="CLD-06", name="Production resources must have backup configured",
        domain=DOMAINS[1], dataset="cloud_resources",
        description="Production data services must have backup / point-in-time restore enabled.",
        test_summary="Production resources where backup_enabled = False.",
        business_impact="Missing backups turn a ransomware or accidental-deletion event into a "
                        "prolonged customer-facing outage.",
        recommendation="Enable backup with tested restore for all production data services; "
                       "align retention to the resilience standard.",
        remediation_effort="Medium", initiative="Cloud Resilience Uplift",
        owner="Cloud Operations Lead",
        nist_csf="PR.DS-11", nist_ai_rmf="-", osfi_b13="B-13 Domain 2 - Disaster Recovery",
        iso_27001="A.8.13", roadmap_phase="Govern",
        scope={"environment": "Prod"},
        detect={"type": "eq", "cols": {"backup_enabled": False}},
        plant={"backup_enabled": False},
    ),
    dict(
        id="CLD-07", name="Network access to cloud resources must be restricted",
        domain=DOMAINS[1], dataset="cloud_resources",
        description="Resources must use private endpoints or IP allow-lists rather than open access.",
        test_summary="Cloud resources where network_restricted = False.",
        business_impact="Flat, open network access removes a key containment layer and lets "
                        "lateral movement reach sensitive AI and customer data.",
        recommendation="Deploy private endpoints and default-deny network rules; phase out "
                       "public service endpoints.",
        remediation_effort="High", initiative="Cloud Network Segmentation",
        owner="Cloud Security Lead",
        nist_csf="PR.IR-01", nist_ai_rmf="-", osfi_b13="B-13 Domain 2 - Technology Operations",
        iso_27001="A.8.20 / A.8.22", roadmap_phase="Scale",
        scope={},
        detect={"type": "eq", "cols": {"network_restricted": False}},
        plant={"network_restricted": False},
    ),
    dict(
        id="CLD-08", name="Unsupported or non-compliant resources must be identified",
        domain=DOMAINS[1], dataset="cloud_resources",
        description="Resources running unsupported runtimes / images must be tracked and remediated.",
        test_summary="Resources flagged unsupported_runtime = True.",
        business_impact="End-of-life components no longer receive security patches and are a "
                        "predictable route to compromise.",
        recommendation="Establish a lifecycle inventory; set upgrade deadlines for unsupported "
                       "runtimes and block new deployments on them.",
        remediation_effort="Medium", initiative="Continuous Cloud Control Monitoring",
        owner="Cloud Operations Lead",
        nist_csf="ID.AM-08", nist_ai_rmf="-", osfi_b13="B-13 Domain 2 - Technology Operations",
        iso_27001="A.8.8", roadmap_phase="Scale",
        scope={},
        detect={"type": "eq", "cols": {"unsupported_runtime": True}},
        plant={"unsupported_runtime": True},
    ),

    # =================== 3. Privacy & Data Protection ====================
    dict(
        id="PRV-01", name="Personal information must be classified and registered",
        domain=DOMAINS[2], dataset="data_assets",
        description="Data assets containing PII must be classified and registered in the data catalogue.",
        test_summary="Data assets where contains_pii = True but pii_classified = False (not registered / validated).",
        business_impact="Under-classified PII does not inherit encryption, access and retention "
                        "controls, creating silent privacy exposure.",
        recommendation="Re-classify all PII-bearing assets; enforce automated classification at "
                       "data-store creation.",
        remediation_effort="Medium", initiative="Sensitive-Data Classification",
        owner="Data Protection Officer",
        nist_csf="ID.AM-07", nist_ai_rmf="MAP 4.1", osfi_b13="B-13 Domain 3 - Data Security",
        iso_27001="A.5.12 / A.5.34", roadmap_phase="Govern",
        scope={"contains_pii": True},
        detect={"type": "eq", "cols": {"pii_classified": False}},
        plant={"pii_classified": False},
    ),
    dict(
        id="PRV-02", name="Confidential and Restricted data must be encrypted",
        domain=DOMAINS[2], dataset="data_assets",
        description="High-sensitivity datasets must be encrypted at rest and in transit.",
        test_summary="Data assets classified Confidential/Restricted where encrypted = False.",
        business_impact="Unencrypted sensitive customer data is a reportable breach if exposed "
                        "and a direct finding against privacy obligations.",
        recommendation="Apply encryption to all Confidential/Restricted assets; use "
                       "customer-managed keys and enforce TLS everywhere.",
        remediation_effort="Medium", initiative="Sensitive-Data Protection",
        owner="Data Protection Officer",
        nist_csf="PR.DS-01 / PR.DS-02", nist_ai_rmf="-", osfi_b13="B-13 Domain 3 - Data Security",
        iso_27001="A.8.24", roadmap_phase="Stabilize",
        scope={"classification": ["Confidential", "Restricted"]},
        detect={"type": "eq", "cols": {"encrypted": False}},
        plant={"encrypted": False},
    ),
    dict(
        id="PRV-03", name="AI systems must only access approved customer data",
        domain=DOMAINS[2], dataset="data_assets",
        description="Datasets reachable by the GenAI platform must be explicitly approved for AI use.",
        test_summary="Data assets where ai_accessible = True but approved_ai_access = False.",
        business_impact="Unapproved data in the AI context risks the model surfacing customer "
                        "PII or confidential records in responses - the defining risk of this launch.",
        recommendation="Implement an AI data-access allow-list enforced at the retrieval layer; "
                       "default-deny for any unreviewed dataset.",
        remediation_effort="Medium", initiative="AI Data-Loss Prevention",
        owner="AI Governance Lead",
        nist_csf="PR.DS-01", nist_ai_rmf="MAP 3.4 / MANAGE 2.2",
        osfi_b13="B-13 Domain 3 - Data Security", iso_27001="A.5.34 / A.8.3",
        roadmap_phase="Stabilize",
        scope={"ai_accessible": True},
        detect={"type": "eq", "cols": {"approved_ai_access": False}},
        plant={"approved_ai_access": False},
    ),
    dict(
        id="PRV-04", name="Data retention requirements must be defined",
        domain=DOMAINS[2], dataset="data_assets",
        description="Every data asset must have an approved retention period recorded.",
        test_summary="Data assets where retention_defined = False.",
        business_impact="Undefined retention leads to indefinite accumulation of personal data, "
                        "increasing breach exposure and privacy non-compliance.",
        recommendation="Assign retention schedules to all datasets from the records-management "
                       "standard; automate enforcement where possible.",
        remediation_effort="Medium", initiative="Data Retention Governance",
        owner="Data Protection Officer",
        nist_csf="GV.PO-01", nist_ai_rmf="MAP 4.1", osfi_b13="B-13 Domain 1 - Governance",
        iso_27001="A.5.33 / A.8.10", roadmap_phase="Govern",
        scope={},
        detect={"type": "eq", "cols": {"retention_defined": False}},
        plant={"retention_defined": False},
    ),
    dict(
        id="PRV-05", name="Customer data must not be retained indefinitely",
        domain=DOMAINS[2], dataset="data_assets",
        description="Personal data retention must not exceed the 7-year (2,555-day) ceiling without approval.",
        test_summary="PII-bearing data assets with retention_days > 2,555 or set to indefinite.",
        business_impact="Indefinite retention of customer records - including AI prompt / "
                        "conversation logs - is a growing regulatory focus and enlarges every breach.",
        recommendation="Cap retention at policy limits; implement automated purge for AI "
                       "conversation and prompt data.",
        remediation_effort="Medium", initiative="Data Retention Governance",
        owner="Data Protection Officer",
        nist_csf="GV.PO-01", nist_ai_rmf="MANAGE 2.2", osfi_b13="B-13 Domain 1 - Governance",
        iso_27001="A.5.33", roadmap_phase="Govern",
        scope={"contains_pii": True},
        detect={"type": "gt", "col": "retention_days", "value": 2555},
        plant={"retention_days": ["randint", 2600, 9999]},
    ),
    dict(
        id="PRV-06", name="Sensitive datasets must have an accountable owner",
        domain=DOMAINS[2], dataset="data_assets",
        description="Confidential and Restricted datasets must map to a named data owner.",
        test_summary="Confidential/Restricted data assets where owner = UNASSIGNED.",
        business_impact="Unowned sensitive data cannot be governed, reviewed for AI use, or "
                        "defended during an incident.",
        recommendation="Assign data owners for all sensitive assets; block onboarding to the "
                       "data platform without an owner.",
        remediation_effort="Low", initiative="Sensitive-Data Classification",
        owner="Data Protection Officer",
        nist_csf="GV.RR-02", nist_ai_rmf="MAP 1.1", osfi_b13="B-13 Domain 1 - Governance",
        iso_27001="A.5.9", roadmap_phase="Govern",
        scope={"classification": ["Confidential", "Restricted"]},
        detect={"type": "eq", "cols": {"owner": "UNASSIGNED"}},
        plant={"owner": "UNASSIGNED"},
    ),
    dict(
        id="PRV-07", name="Data minimisation must be enforced for AI use",
        domain=DOMAINS[2], dataset="data_assets",
        description="Datasets exposed to AI must have completed a data-minimisation review.",
        test_summary="AI-accessible data assets where minimisation_reviewed = False.",
        business_impact="Feeding the model more personal data than the use case needs breaches "
                        "the minimisation principle and increases exposure with no upside.",
        recommendation="Require a minimisation review (field-level necessity, masking, "
                       "tokenisation) before any dataset is connected to the GenAI platform.",
        remediation_effort="Medium", initiative="AI Data-Loss Prevention",
        owner="AI Governance Lead",
        nist_csf="PR.DS-01", nist_ai_rmf="MAP 3.4", osfi_b13="B-13 Domain 3 - Data Security",
        iso_27001="A.8.3", roadmap_phase="Govern",
        scope={"ai_accessible": True},
        detect={"type": "eq", "cols": {"minimisation_reviewed": False}},
        plant={"minimisation_reviewed": False},
    ),
    dict(
        id="PRV-08", name="Cross-border transfers of personal data must be approved",
        domain=DOMAINS[2], dataset="data_assets",
        description="PII stored or processed outside Canada must have an approved transfer basis.",
        test_summary="PII-bearing data assets with region != Canada and transfer_approved = False.",
        business_impact="Unapproved cross-border data flows create regulatory and contractual "
                        "exposure, particularly where a foreign AI provider is involved.",
        recommendation="Document transfer bases and safeguards for all non-Canadian data "
                       "locations; restrict AI processing to approved regions.",
        remediation_effort="Medium", initiative="Third-Party AI Risk Review",
        owner="Data Protection Officer",
        nist_csf="GV.SC-07", nist_ai_rmf="MAP 4.1", osfi_b13="B-13 Domain 1 - Third-Party Risk",
        iso_27001="A.5.34", roadmap_phase="Govern",
        scope={"contains_pii": True},
        detect={"type": "eq", "cols": {"transfer_approved": False, "region_outside_canada": True}},
        plant={"transfer_approved": False, "region_outside_canada": True},
    ),

    # ======================== 4. AI Governance ===========================
    dict(
        id="AIG-01", name="AI systems must have a documented accountable owner",
        domain=DOMAINS[3], dataset="applications",
        description="Every AI-integrated application must have a named business and technical owner.",
        test_summary="AI-integrated applications where owner = UNASSIGNED.",
        business_impact="Without clear ownership, no one is accountable for model behaviour, "
                        "incidents or regulatory questions about the GenAI platform.",
        recommendation="Record accountable owners for all AI systems in the AI inventory; make "
                       "it a gate for production release.",
        remediation_effort="Low", initiative="AI Governance Operating Model",
        owner="AI Governance Lead",
        nist_csf="GV.RR-02", nist_ai_rmf="GOVERN 2.1", osfi_b13="B-13 Domain 1 - Governance",
        iso_27001="A.5.2", roadmap_phase="Govern",
        scope={"ai_integrated": True},
        detect={"type": "eq", "cols": {"owner": "UNASSIGNED"}},
        plant={"owner": "UNASSIGNED"},
    ),
    dict(
        id="AIG-02", name="High-risk AI actions must have human oversight",
        domain=DOMAINS[3], dataset="applications",
        description="AI actions that affect customers (payments, account changes, advice) must "
                    "have a human-in-the-loop checkpoint.",
        test_summary="AI-integrated applications where human_oversight = False.",
        business_impact="Autonomous AI actions on customer accounts without review can cause "
                        "financial harm at machine speed and scale.",
        recommendation="Define which AI actions require human approval; implement confirmation "
                       "steps and hard limits for customer-impacting operations.",
        remediation_effort="Medium", initiative="AI Governance Operating Model",
        owner="AI Governance Lead",
        nist_csf="GV.OV-01", nist_ai_rmf="MANAGE 4.1", osfi_b13="B-13 Domain 1 - Governance",
        iso_27001="A.5.36", roadmap_phase="Govern",
        scope={"ai_integrated": True},
        detect={"type": "eq", "cols": {"human_oversight": False}},
        plant={"human_oversight": False},
    ),
    dict(
        id="AIG-03", name="AI activity must be logged",
        domain=DOMAINS[3], dataset="applications",
        description="Prompts, responses, tool calls and data access by AI systems must be logged.",
        test_summary="AI-integrated applications where ai_logging_enabled = False.",
        business_impact="Without AI activity logs the bank cannot investigate misuse, prove "
                        "what data the model saw, or meet breach-notification duties.",
        recommendation="Enable structured logging of AI prompts, responses and retrieval calls "
                       "to the SIEM with privacy-safe redaction.",
        remediation_effort="Medium", initiative="AI Audit Logging",
        owner="AI Governance Lead",
        nist_csf="DE.CM-01", nist_ai_rmf="MEASURE 2.6 / MANAGE 4.1",
        osfi_b13="B-13 Domain 2 - Technology Operations", iso_27001="A.8.15",
        roadmap_phase="Stabilize",
        scope={"ai_integrated": True},
        detect={"type": "eq", "cols": {"ai_logging_enabled": False}},
        plant={"ai_logging_enabled": False},
    ),
    dict(
        id="AIG-04", name="AI systems must have documented, approved use cases",
        domain=DOMAINS[3], dataset="applications",
        description="Each AI system must have a recorded, approved use case and scope.",
        test_summary="AI-integrated applications where use_case_approved = False.",
        business_impact="Undocumented AI use cases drift into unapproved, higher-risk territory "
                        "without governance visibility.",
        recommendation="Require an approved use-case record (purpose, data, users, limits) "
                       "before enabling AI features.",
        remediation_effort="Low", initiative="AI Governance Operating Model",
        owner="AI Governance Lead",
        nist_csf="GV.PO-01", nist_ai_rmf="MAP 1.1 / GOVERN 1.3",
        osfi_b13="B-13 Domain 1 - Governance", iso_27001="A.5.1",
        roadmap_phase="Govern",
        scope={"ai_integrated": True},
        detect={"type": "eq", "cols": {"use_case_approved": False}},
        plant={"use_case_approved": False},
    ),
    dict(
        id="AIG-05", name="Sensitive inputs to AI must be controlled",
        domain=DOMAINS[3], dataset="applications",
        description="AI systems must filter sensitive data (PII, secrets) from prompts and context.",
        test_summary="AI-integrated applications where input_filtering = False.",
        business_impact="Unfiltered prompts let customer PII and credentials flow into the "
                        "model and any downstream provider - the highest-profile GenAI failure mode.",
        recommendation="Deploy prompt-side DLP / redaction and context sanitisation on every "
                       "AI pathway before production launch.",
        remediation_effort="High", initiative="AI Data-Loss Prevention",
        owner="AI Governance Lead",
        nist_csf="PR.DS-01", nist_ai_rmf="MANAGE 2.2 / MEASURE 2.7",
        osfi_b13="B-13 Domain 3 - Data Security", iso_27001="A.8.3 / A.5.34",
        roadmap_phase="Stabilize",
        scope={"ai_integrated": True},
        detect={"type": "eq", "cols": {"input_filtering": False}},
        plant={"input_filtering": False},
    ),
    dict(
        id="AIG-06", name="AI systems must have a defined risk classification",
        domain=DOMAINS[3], dataset="applications",
        description="Each AI system must be risk-tiered (e.g. limited / high / unacceptable) to drive controls.",
        test_summary="AI-integrated applications where ai_risk_classified = False.",
        business_impact="Without risk tiering, controls are applied inconsistently and "
                        "high-risk AI may launch with limited-risk safeguards.",
        recommendation="Apply an AI risk-classification method at intake; tie control "
                       "requirements to the assigned tier.",
        remediation_effort="Low", initiative="AI Governance Operating Model",
        owner="AI Governance Lead",
        nist_csf="ID.RA-05", nist_ai_rmf="MAP 1.5 / GOVERN 1.3",
        osfi_b13="B-13 Domain 1 - Governance", iso_27001="A.5.1",
        roadmap_phase="Govern",
        scope={"ai_integrated": True},
        detect={"type": "eq", "cols": {"ai_risk_classified": False}},
        plant={"ai_risk_classified": False},
    ),
    dict(
        id="AIG-07", name="Model outputs must have monitoring procedures",
        domain=DOMAINS[3], dataset="applications",
        description="AI outputs must be monitored for accuracy, bias, toxicity and drift.",
        test_summary="AI-integrated applications where output_monitoring = False.",
        business_impact="Unmonitored model outputs can give customers wrong financial "
                        "information or biased treatment without anyone noticing.",
        recommendation="Stand up output-quality monitoring with sampling, feedback capture and "
                       "drift alerts feeding the AI governance forum.",
        remediation_effort="Medium", initiative="AI Output Monitoring",
        owner="AI Governance Lead",
        nist_csf="DE.CM-09", nist_ai_rmf="MEASURE 2.3 / MANAGE 4.1",
        osfi_b13="B-13 Domain 2 - Technology Operations", iso_27001="A.8.16",
        roadmap_phase="Scale",
        scope={"ai_integrated": True},
        detect={"type": "eq", "cols": {"output_monitoring": False}},
        plant={"output_monitoring": False},
    ),
    dict(
        id="AIG-08", name="Third-party AI models must disclose data-handling practices",
        domain=DOMAINS[3], dataset="applications",
        description="AI systems using external models must document the provider's data-handling terms.",
        test_summary="AI-integrated applications using third-party models where model_data_handling_documented = False.",
        business_impact="If a provider trains on or retains prompt data, customer information "
                        "could leave the bank's control without disclosure.",
        recommendation="Capture and review provider data-handling terms (training use, "
                       "retention, sub-processors) for every external model in use.",
        remediation_effort="Medium", initiative="Third-Party AI Risk Review",
        owner="AI Governance Lead",
        nist_csf="GV.SC-07", nist_ai_rmf="MAP 4.1 / GOVERN 6.1",
        osfi_b13="B-13 Domain 1 - Third-Party Risk", iso_27001="A.5.19 / A.5.21",
        roadmap_phase="Govern",
        scope={"ai_integrated": True, "third_party_model": True},
        detect={"type": "eq", "cols": {"model_data_handling_documented": False}},
        plant={"model_data_handling_documented": False},
    ),

    # ===================== 5. Security Operations ========================
    dict(
        id="SOC-01", name="Critical systems must forward security logs to the SIEM",
        domain=DOMAINS[4], dataset="applications",
        description="Systems tiered Critical must be onboarded to central security monitoring.",
        test_summary="Critical-tier applications where siem_onboarded = False.",
        business_impact="Critical systems outside the SIEM are undetectable during an attack, "
                        "extending dwell time and breach impact.",
        recommendation="Onboard all Critical systems to the SIEM with validated log sources; "
                       "make it a production gate.",
        remediation_effort="Medium", initiative="AI Audit Logging",
        owner="SOC Manager",
        nist_csf="DE.CM-01 / DE.CM-03", nist_ai_rmf="MEASURE 2.6",
        osfi_b13="B-13 Domain 2 - Cyber Security", iso_27001="A.8.15 / A.8.16",
        roadmap_phase="Stabilize",
        scope={"risk_tier": "Critical"},
        detect={"type": "eq", "cols": {"siem_onboarded": False}},
        plant={"siem_onboarded": False},
    ),
    dict(
        id="SOC-02", name="Security alerts must have assigned owners",
        domain=DOMAINS[4], dataset="applications",
        description="Every monitored system must have a named team accountable for its alerts.",
        test_summary="Monitored applications where alert_owner_assigned = False.",
        business_impact="Unowned alerts are missed or delayed, the root cause of many escalated "
                        "incidents.",
        recommendation="Map each alert source to an on-call owner in the SOC runbook; alert on "
                       "unrouted detections.",
        remediation_effort="Low", initiative="SOC Operating Model Uplift",
        owner="SOC Manager",
        nist_csf="RS.MA-01", nist_ai_rmf="-", osfi_b13="B-13 Domain 2 - Cyber Security",
        iso_27001="A.5.24 / A.5.26", roadmap_phase="Govern",
        scope={},
        detect={"type": "eq", "cols": {"alert_owner_assigned": False}},
        plant={"alert_owner_assigned": False},
    ),
    dict(
        id="SOC-03", name="High-risk systems must be actively monitored",
        domain=DOMAINS[4], dataset="applications",
        description="Critical and High tier systems must have active detection coverage.",
        test_summary="Critical/High-tier applications where monitored = False.",
        business_impact="Monitoring gaps on high-value systems are exactly where attackers "
                        "operate unnoticed.",
        recommendation="Close detection-coverage gaps for all High and Critical systems; track "
                       "coverage as a SOC KPI.",
        remediation_effort="Medium", initiative="Continuous Cloud Control Monitoring",
        owner="SOC Manager",
        nist_csf="DE.CM-01", nist_ai_rmf="MEASURE 2.6",
        osfi_b13="B-13 Domain 2 - Cyber Security", iso_27001="A.8.16",
        roadmap_phase="Scale",
        scope={"risk_tier": ["Critical", "High"]},
        detect={"type": "eq", "cols": {"monitored": False}},
        plant={"monitored": False},
    ),
    dict(
        id="SOC-04", name="Incident-response runbooks must exist for critical systems",
        domain=DOMAINS[4], dataset="applications",
        description="Critical systems must have a documented, tested incident-response runbook.",
        test_summary="Critical-tier applications where ir_runbook_exists = False.",
        business_impact="Without runbooks, response to an incident on a critical system is "
                        "slow, inconsistent and error-prone.",
        recommendation="Develop and exercise IR runbooks for all Critical systems, including "
                       "the GenAI platform.",
        remediation_effort="Medium", initiative="Incident Response Readiness",
        owner="Incident Response Lead",
        nist_csf="RS.MA-01 / RC.RP-01", nist_ai_rmf="MANAGE 4.1",
        osfi_b13="B-13 Domain 2 - Cyber Incident Management", iso_27001="A.5.26 / A.5.24",
        roadmap_phase="Govern",
        scope={"risk_tier": "Critical"},
        detect={"type": "eq", "cols": {"ir_runbook_exists": False}},
        plant={"ir_runbook_exists": False},
    ),
    dict(
        id="SOC-05", name="Critical vulnerabilities must have remediation targets",
        domain=DOMAINS[4], dataset="applications",
        description="Systems with critical vulnerabilities must have an SLA-bound remediation date.",
        test_summary="Applications where open_critical_vulns = True and vuln_sla_days > 30.",
        business_impact="Critical vulnerabilities left beyond SLA are the most predictable "
                        "cause of breach in regulated environments.",
        recommendation="Enforce a 30-day (or shorter) SLA for critical vulnerabilities with "
                       "executive reporting on breaches of SLA.",
        remediation_effort="Medium", initiative="Vulnerability Management Uplift",
        owner="Vulnerability Management Lead",
        nist_csf="ID.RA-01 / RS.MI-02", nist_ai_rmf="-",
        osfi_b13="B-13 Domain 2 - Cyber Security", iso_27001="A.8.8",
        roadmap_phase="Govern",
        scope={"open_critical_vulns": True},
        detect={"type": "gt", "col": "vuln_sla_days", "value": 30},
        plant={"vuln_sla_days": ["randint", 45, 180]},
    ),
    dict(
        id="SOC-06", name="AI-related incidents must be built into response procedures",
        domain=DOMAINS[4], dataset="applications",
        description="AI systems must be covered by an AI-specific incident playbook (jailbreak, data leak, harmful output).",
        test_summary="AI-integrated applications where ai_incident_playbook = False.",
        business_impact="Generic IR does not cover AI failure modes; the SOC would improvise "
                        "during a public AI incident.",
        recommendation="Extend the IR framework with AI scenarios and run a tabletop before "
                       "launch.",
        remediation_effort="Medium", initiative="Incident Response Readiness",
        owner="Incident Response Lead",
        nist_csf="RS.MA-01", nist_ai_rmf="MANAGE 4.1 / MANAGE 4.3",
        osfi_b13="B-13 Domain 2 - Cyber Incident Management", iso_27001="A.5.26",
        roadmap_phase="Govern",
        scope={"ai_integrated": True},
        detect={"type": "eq", "cols": {"ai_incident_playbook": False}},
        plant={"ai_incident_playbook": False},
    ),
    dict(
        id="SOC-07", name="Security events must have severity classifications",
        domain=DOMAINS[4], dataset="applications",
        description="Alert sources must map detections to a defined severity scheme.",
        test_summary="Monitored applications where event_severity_defined = False.",
        business_impact="Without severity classification, triage cannot prioritise and genuine "
                        "incidents queue behind noise.",
        recommendation="Apply a standard severity taxonomy to all detections; validate during "
                       "onboarding.",
        remediation_effort="Low", initiative="SOC Operating Model Uplift",
        owner="SOC Manager",
        nist_csf="RS.MA-03", nist_ai_rmf="-", osfi_b13="B-13 Domain 2 - Cyber Security",
        iso_27001="A.5.25", roadmap_phase="Scale",
        scope={},
        detect={"type": "eq", "cols": {"event_severity_defined": False}},
        plant={"event_severity_defined": False},
    ),
    dict(
        id="SOC-08", name="Log retention must meet the internal minimum",
        domain=DOMAINS[4], dataset="applications",
        description="Security-relevant logs must be retained for at least 365 days.",
        test_summary="Applications where log_retention_days < 365.",
        business_impact="Short retention prevents investigation of slow-burn intrusions and "
                        "fails common regulatory expectations.",
        recommendation="Set security log retention to at least 12 months (with longer archive "
                       "for critical systems).",
        remediation_effort="Low", initiative="SOC Operating Model Uplift",
        owner="SOC Manager",
        nist_csf="PR.PS-04", nist_ai_rmf="-", osfi_b13="B-13 Domain 2 - Cyber Security",
        iso_27001="A.8.15", roadmap_phase="Scale",
        scope={},
        detect={"type": "lt", "col": "log_retention_days", "value": 365},
        plant={"log_retention_days": ["randint", 30, 300]},
    ),

    # ================ 6. Governance & Third-Party Risk ===================
    dict(
        id="TPR-01", name="Critical vendors must have a current security assessment",
        domain=DOMAINS[5], dataset="vendors",
        description="Vendors rated Critical must have a security assessment completed within 12 months.",
        test_summary="Critical vendors where security_assessment = False.",
        business_impact="Unassessed critical vendors are an unmeasured route to the bank's data "
                        "and systems, including the AI supply chain.",
        recommendation="Complete security assessments for all Critical vendors; block renewals "
                       "without a current assessment.",
        remediation_effort="Medium", initiative="Third-Party AI Risk Review",
        owner="Third-Party Risk Manager",
        nist_csf="GV.SC-04 / GV.SC-07", nist_ai_rmf="GOVERN 6.1",
        osfi_b13="B-13 Domain 1 - Third-Party Risk", iso_27001="A.5.19 / A.5.22",
        roadmap_phase="Govern",
        scope={"criticality": "Critical"},
        detect={"type": "eq", "cols": {"security_assessment": False}},
        plant={"security_assessment": False},
    ),
    dict(
        id="TPR-02", name="AI vendors must have a completed AI risk review",
        domain=DOMAINS[5], dataset="vendors",
        description="Vendors providing AI capability must pass an AI-specific risk review.",
        test_summary="AI vendors where ai_risk_review = False.",
        business_impact="AI vendors introduce model, data-handling and concentration risks that "
                        "a standard security review does not cover.",
        recommendation="Add an AI risk-review module to third-party onboarding covering "
                       "training-data use, retention, evaluation and exit.",
        remediation_effort="Medium", initiative="Third-Party AI Risk Review",
        owner="Third-Party Risk Manager",
        nist_csf="GV.SC-07", nist_ai_rmf="MAP 4.1 / GOVERN 6.1",
        osfi_b13="B-13 Domain 1 - Third-Party Risk", iso_27001="A.5.19 / A.5.21",
        roadmap_phase="Govern",
        scope={"ai_vendor": True},
        detect={"type": "eq", "cols": {"ai_risk_review": False}},
        plant={"ai_risk_review": False},
    ),
    dict(
        id="TPR-03", name="Identified risks must have an assigned owner",
        domain=DOMAINS[5], dataset="vendors",
        description="Every vendor-related risk must map to an accountable owner.",
        test_summary="Vendors where owner = UNASSIGNED.",
        business_impact="Unowned risks are not tracked to closure and resurface during audits "
                        "and incidents.",
        recommendation="Assign risk owners for all vendor relationships in the risk register; "
                       "review ownership quarterly.",
        remediation_effort="Low", initiative="Technology Risk Governance",
        owner="Technology Risk Manager",
        nist_csf="GV.RR-02", nist_ai_rmf="GOVERN 2.1",
        osfi_b13="B-13 Domain 1 - Governance", iso_27001="A.5.9",
        roadmap_phase="Govern",
        scope={},
        detect={"type": "eq", "cols": {"owner": "UNASSIGNED"}},
        plant={"owner": "UNASSIGNED"},
    ),
    dict(
        id="TPR-04", name="Contracts and policies must have defined review dates",
        domain=DOMAINS[5], dataset="vendors",
        description="Vendor contracts and governing policies must carry a scheduled review date.",
        test_summary="Vendors where contract_review = False.",
        business_impact="Contracts without review dates drift out of alignment with current "
                        "risk, security and regulatory requirements.",
        recommendation="Attach review dates to all vendor contracts and policies; drive "
                       "reminders from the contract system.",
        remediation_effort="Low", initiative="Technology Risk Governance",
        owner="Technology Risk Manager",
        nist_csf="GV.PO-02", nist_ai_rmf="-", osfi_b13="B-13 Domain 1 - Governance",
        iso_27001="A.5.1 / A.5.20", roadmap_phase="Scale",
        scope={},
        detect={"type": "eq", "cols": {"contract_review": False}},
        plant={"contract_review": False},
    ),
    dict(
        id="TPR-05", name="Critical controls must have evidence on file",
        domain=DOMAINS[5], dataset="vendors",
        description="Controls relied on for Critical vendors must have supporting evidence retained.",
        test_summary="Critical vendors where control_evidence_on_file = False.",
        business_impact="Controls without evidence cannot be relied on during audit or incident "
                        "and may be failing silently.",
        recommendation="Collect and store control evidence (SOC 2, pen-test summaries, "
                       "attestations) for all Critical vendors.",
        remediation_effort="Medium", initiative="Technology Risk Governance",
        owner="Technology Risk Manager",
        nist_csf="GV.SC-09", nist_ai_rmf="-", osfi_b13="B-13 Domain 1 - Third-Party Risk",
        iso_27001="A.5.22", roadmap_phase="Scale",
        scope={"criticality": "Critical"},
        detect={"type": "eq", "cols": {"control_evidence_on_file": False}},
        plant={"control_evidence_on_file": False},
    ),
    dict(
        id="TPR-06", name="High-risk exceptions must be formally approved",
        domain=DOMAINS[5], dataset="vendors",
        description="Any exception for a high-risk vendor must be documented and approved by risk leadership.",
        test_summary="Vendors rated High risk where exception_approved = False.",
        business_impact="Unapproved exceptions bypass governance and accumulate unmanaged risk "
                        "on the balance sheet.",
        recommendation="Route all high-risk exceptions through a formal approval workflow with "
                       "expiry dates and executive visibility.",
        remediation_effort="Low", initiative="Technology Risk Governance",
        owner="Technology Risk Manager",
        nist_csf="GV.RM-02", nist_ai_rmf="GOVERN 1.3",
        osfi_b13="B-13 Domain 1 - Governance", iso_27001="A.5.4",
        roadmap_phase="Scale",
        scope={"risk_rating": "High"},
        detect={"type": "eq", "cols": {"exception_approved": False}},
        plant={"exception_approved": False},
    ),
    dict(
        id="TPR-07", name="Technology risks must have remediation dates",
        domain=DOMAINS[5], dataset="vendors",
        description="Open technology and vendor risks must have a committed remediation date.",
        test_summary="High/Critical-risk vendors where remediation_date_set = False.",
        business_impact="Risks without target dates are not actually being managed, only "
                        "recorded.",
        recommendation="Require remediation dates for all High and Critical risks; report "
                       "overdue items to the risk committee.",
        remediation_effort="Low", initiative="Technology Risk Governance",
        owner="Technology Risk Manager",
        nist_csf="ID.RA-06", nist_ai_rmf="MANAGE 1.3",
        osfi_b13="B-13 Domain 1 - Governance", iso_27001="A.5.8",
        roadmap_phase="Scale",
        scope={"risk_rating": ["High", "Critical"]},
        detect={"type": "eq", "cols": {"remediation_date_set": False}},
        plant={"remediation_date_set": False},
    ),
    dict(
        id="TPR-08", name="Critical suppliers must have documented oversight",
        domain=DOMAINS[5], dataset="vendors",
        description="Critical suppliers must have an ongoing oversight / relationship-management plan.",
        test_summary="Critical vendors where oversight_documented = False.",
        business_impact="Critical suppliers without oversight can degrade in security posture "
                        "or resilience without the bank noticing until failure.",
        recommendation="Establish documented oversight (KPIs, review cadence, escalation) for "
                       "every Critical supplier, especially AI providers.",
        remediation_effort="Medium", initiative="Third-Party AI Risk Review",
        owner="Third-Party Risk Manager",
        nist_csf="GV.SC-07 / GV.SC-08", nist_ai_rmf="GOVERN 6.1",
        osfi_b13="B-13 Domain 1 - Third-Party Risk", iso_27001="A.5.22",
        roadmap_phase="Govern",
        scope={"criticality": "Critical"},
        detect={"type": "eq", "cols": {"oversight_documented": False}},
        plant={"oversight_documented": False},
    ),
]

# ---------------------------------------------------------------------------
# Slice plan: severity code list per control.
#   C = Critical, H = High, M = Medium, L = Low
# Total slices = 137, distribution = 9C / 23H / 61M / 44L.
# Controls with an empty list "pass" the assessment (no findings).
# ---------------------------------------------------------------------------

SLICE_PLAN: dict[str, list[str]] = {
    # IAM  (24 slices; IAM-05 passes)
    "IAM-01": ["C", "H", "M", "L"],
    "IAM-02": ["C", "H", "M"],
    "IAM-03": ["H", "M", "M", "M", "L"],
    "IAM-04": ["H", "M", "L"],
    "IAM-05": [],
    "IAM-06": ["M", "L"],
    "IAM-07": ["M", "M", "L"],
    "IAM-08": ["H", "M", "L", "L"],
    # CLD  (25 slices; CLD-06 passes)
    "CLD-01": ["C", "H", "M", "L"],
    "CLD-02": ["H", "M", "M", "L"],
    "CLD-03": ["C", "M", "L"],
    "CLD-04": ["H", "M", "L"],
    "CLD-05": ["M", "M", "M", "L"],
    "CLD-06": [],
    "CLD-07": ["M", "M", "L"],
    "CLD-08": ["M", "M", "L", "L"],
    # PRV  (23 slices; PRV-07 passes)
    "PRV-01": ["H", "M", "L", "L"],
    "PRV-02": ["C", "H", "M", "L"],
    "PRV-03": ["C", "M", "L"],
    "PRV-04": ["M", "M", "M", "L"],
    "PRV-05": ["M", "M", "L"],
    "PRV-06": ["H", "M", "L"],
    "PRV-07": [],
    "PRV-08": ["H", "M"],
    # AIG  (23 slices)
    "AIG-01": ["H", "M", "L"],
    "AIG-02": ["H", "M", "M", "L"],
    "AIG-03": ["C", "H", "M"],
    "AIG-04": ["M", "M", "L"],
    "AIG-05": ["C", "H", "M", "L"],
    "AIG-06": ["M", "L"],
    "AIG-07": ["M", "L"],
    "AIG-08": ["M", "L"],
    # SOC  (21 slices; SOC-08 passes)
    "SOC-01": ["C", "H", "M"],
    "SOC-02": ["H", "M", "L", "L"],
    "SOC-03": ["H", "M", "L"],
    "SOC-04": ["M", "L"],
    "SOC-05": ["H", "M", "L"],
    "SOC-06": ["M", "M", "M", "L"],
    "SOC-07": ["M", "L"],
    "SOC-08": [],
    # TPR  (21 slices; TPR-05 and TPR-07 pass)
    "TPR-01": ["H", "M", "L"],
    "TPR-02": ["H", "M", "L"],
    "TPR-03": ["M", "L", "L"],
    "TPR-04": ["M", "M", "M", "L"],
    "TPR-05": [],
    "TPR-06": ["M", "M", "M", "L"],
    "TPR-07": [],
    "TPR-08": ["H", "M", "L", "L"],
}

_SEV_CODE = {"C": "Critical", "H": "High", "M": "Medium", "L": "Low"}

# Per-dataset baseline "affected assets" per slice by severity (deterministic
# jitter added in the builder).  Vendors are a small population so counts are low.
_AFFECTED_BASE = {
    "identities":      {"Critical": 13, "High": 9, "Medium": 5, "Low": 3},
    "cloud_resources": {"Critical": 10, "High": 7, "Medium": 4, "Low": 2},
    "data_assets":     {"Critical": 6,  "High": 4, "Medium": 2, "Low": 2},
    "applications":    {"Critical": 4,  "High": 3, "Medium": 2, "Low": 2},
    "vendors":         {"Critical": 3,  "High": 2, "Medium": 2, "Low": 1},
}

_RISK_REDUCTION = {"Critical": 62, "High": 45, "Medium": 28, "Low": 12}
_REMEDIATION_DAYS = {"Critical": 21, "High": 45, "Medium": 75, "Low": 110}


def _stable_jitter(key: str, mod: int) -> int:
    """Deterministic small integer from a string key (no RNG needed)."""
    return sum(ord(c) for c in key) % mod


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def build_control_catalog() -> list[dict]:
    """Flat catalogue rows for control_catalog.csv."""
    rows = []
    for c in CONTROLS:
        rows.append({
            "control_id": c["id"],
            "control_name": c["name"],
            "domain": c["domain"],
            "dataset": c["dataset"],
            "description": c["description"],
            "test_summary": c["test_summary"],
            "remediation_effort": c["remediation_effort"],
            "initiative": c["initiative"],
            "owner": c["owner"],
            "nist_csf": c["nist_csf"],
            "nist_ai_rmf": c["nist_ai_rmf"],
            "osfi_b13": c["osfi_b13"],
            "iso_27001": c["iso_27001"],
            "roadmap_phase": c["roadmap_phase"],
        })
    return rows


def build_findings_blueprint() -> list[dict]:
    """Expand SLICE_PLAN into the 137-row finding blueprint."""
    controls_by_id = {c["id"]: c for c in CONTROLS}
    control_offset = {c["id"]: i for i, c in enumerate(CONTROLS)}
    blueprint: list[dict] = []
    counter = 0
    for control_id, codes in SLICE_PLAN.items():
        control = controls_by_id[control_id]
        dataset = control["dataset"]
        # each slice of a control gets a distinct business unit (max 5 slices < 6 BUs)
        assert len(codes) <= len(BUSINESS_UNITS), f"{control_id}: too many slices"
        for slice_ix, code in enumerate(codes):
            counter += 1
            severity = _SEV_CODE[code]
            finding_id = f"F-{counter:03d}"
            likelihood, impact = likelihood_impact(severity, slice_ix)
            bu = BUSINESS_UNITS[(control_offset[control_id] + slice_ix) % len(BUSINESS_UNITS)]
            base = _AFFECTED_BASE[dataset][severity]
            affected = base + _stable_jitter(finding_id, 3)
            blueprint.append({
                "finding_id": finding_id,
                "control_id": control_id,
                "control_name": control["name"],
                "domain": control["domain"],
                "dataset": dataset,
                "business_unit": bu,
                "segment": f"{control['name']} - {bu}",
                "severity": severity,
                "likelihood": likelihood,
                "impact": impact,
                "risk_score": likelihood * impact,
                "affected_assets": affected,
                "owner": control["owner"],
                "remediation_effort": control["remediation_effort"],
                "estimated_risk_reduction": _RISK_REDUCTION[severity]
                + _stable_jitter(finding_id + "rr", 8),
                "target_remediation_days": _REMEDIATION_DAYS[severity],
                "initiative": control["initiative"],
                "roadmap_phase": control["roadmap_phase"],
            })
    return blueprint


CONTROL_CATALOG = build_control_catalog()
FINDINGS_BLUEPRINT = build_findings_blueprint()


# Aggregated planting requirement: dataset -> business_unit -> count of rows
# that must be available to receive planted violations.  Used by the generator
# to size / guarantee the baseline population.
def planting_requirements() -> dict[str, dict[str, int]]:
    req: dict[str, dict[str, int]] = {}
    for f in FINDINGS_BLUEPRINT:
        req.setdefault(f["dataset"], {}).setdefault(f["business_unit"], 0)
        req[f["dataset"]][f["business_unit"]] += f["affected_assets"]
    return req


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------

def self_check() -> None:
    # 48 controls, 6 domains x 8
    assert len(CONTROLS) == 48, f"expected 48 controls, got {len(CONTROLS)}"
    ids = [c["id"] for c in CONTROLS]
    assert len(set(ids)) == 48, "duplicate control ids"
    from collections import Counter
    dom_counts = Counter(c["domain"] for c in CONTROLS)
    assert set(dom_counts) == set(DOMAINS), "domain names mismatch"
    assert all(v == 8 for v in dom_counts.values()), f"domains not 8 each: {dom_counts}"

    # blueprint size + severity mix
    assert len(FINDINGS_BLUEPRINT) == TOTAL_FINDINGS_TARGET, (
        f"expected {TOTAL_FINDINGS_TARGET} findings, got {len(FINDINGS_BLUEPRINT)}")
    sev_counts = Counter(f["severity"] for f in FINDINGS_BLUEPRINT)
    assert dict(sev_counts) == TARGET_SEVERITY_MIX, (
        f"severity mix {dict(sev_counts)} != target {TARGET_SEVERITY_MIX}")

    # severity band consistency
    for f in FINDINGS_BLUEPRINT:
        assert severity_from_score(f["risk_score"]) == f["severity"], (
            f"{f['finding_id']}: score {f['risk_score']} not in band {f['severity']}")

    # every SLICE_PLAN key is a real control
    assert set(SLICE_PLAN) <= set(ids), "SLICE_PLAN references unknown control"

    # (control_id, business_unit) must be unique so that grouping violations by
    # business unit reproduces exactly one finding per blueprint row.
    pairs = [(f["control_id"], f["business_unit"]) for f in FINDINGS_BLUEPRINT]
    assert len(pairs) == len(set(pairs)), "duplicate (control, business_unit) in blueprint"

    # dataset sizing
    assert sum(DATASET_SIZES.values()) == TOTAL_ASSETS_TARGET

    # planting must fit inside each dataset population
    req = planting_requirements()
    for dataset, bu_map in req.items():
        assert sum(bu_map.values()) <= DATASET_SIZES[dataset] * 3, (
            f"{dataset}: planting demand {sum(bu_map.values())} unreasonable")

    print("config.self_check: OK")
    print(f"  controls           : {len(CONTROLS)} (6 domains x 8)")
    print(f"  blueprint findings : {len(FINDINGS_BLUEPRINT)}")
    print(f"  severity mix       : {dict(sev_counts)}")
    print(f"  passing controls   : "
          f"{sorted(set(ids) - set(k for k, v in SLICE_PLAN.items() if v))}")


if __name__ == "__main__":
    self_check()
