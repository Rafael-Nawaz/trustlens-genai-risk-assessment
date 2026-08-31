# TrustLens — Architecture

## Assessment flow

```
Synthetic Enterprise Environment
        |
        v
Python Control Testing
        |
        v
48 Cybersecurity Controls  (6 domains x 8)
        |
        v
Risk Scoring & Framework Mapping  (Likelihood x Impact)
        |
        v
137 Findings  (9 Critical / 23 High / 61 Medium / 44 Low)
        |
        v
Executive Risk Analytics  (readiness score, domain maturity, top risks)
        |
        v
Prioritized Recommendations  (quick wins / strategic / low priority)
        |
        v
90-Day Transformation Roadmap  (Stabilize -> Govern -> Scale)
```

## Module responsibilities

| Module | Responsibility | Key functions |
|---|---|---|
| `src/config.py` | **Single source of truth.** 48-control catalogue, 137-row finding blueprint, dataset sizing, scoring constants, self-check. | `CONTROLS`, `FINDINGS_BLUEPRINT`, `severity_from_score`, `self_check` |
| `src/rules.py` | Shared rule evaluation so "in scope" and "in violation" are defined once. | `scope_mask`, `detect_mask`, `violation_mask`, `scope_coercion_values` |
| `src/generate_data.py` | Builds the synthetic estate: a fully compliant baseline, then injects the blueprint's violations. Writes `data/*.csv`. | `build_identities`, `build_cloud_resources`, `build_applications`, `build_data_assets`, `build_vendors`, `apply_blueprint_violations` |
| `src/control_tests.py` | Runs all 48 controls, groups violations by business unit into findings, cross-checks against the blueprint. | `evaluate_control`, `run_all_controls`, `all_findings`, `_consistency_check` |
| `src/risk_engine.py` | Likelihood × Impact scoring, readiness score (overall + per domain), initiative prioritisation and quadrants. | `score_findings`, `compute_readiness`, `prioritize`, `top_initiatives`, `top_risks` |
| `src/generate_findings.py` | Orchestrator. Runs the pipeline, builds every deliverable, validates the headline metrics, prints the summary. | `run`, `build_risk_register`, `build_powerbi_tables`, `build_roadmap`, `_validate` |

## Why a "blueprint" design

The hard requirement is exactly **2,000 assets / 48 controls / 137 findings** with a
specific severity distribution, produced by code rather than asserted in prose.

`config.FINDINGS_BLUEPRINT` is a list of 137 "finding slices", each naming a control, a
business unit, an affected-asset count and a `(likelihood, impact)` pair. It drives:

- **the generator** — `apply_blueprint_violations` plants exactly the specified violations
  into an otherwise-compliant baseline;
- **the tests** — `evaluate_control` re-detects violations from the data and matches each
  finding group back to a blueprint row;
- **the scorer** — `score_findings` reads the `(likelihood, impact)` values and
  independently re-checks that the resulting severity band matches.

Because no control's `plant` column is another control's `scope` column, planted rows can be
shared between findings without creating or erasing an unplanned finding. `control_tests.py`
raises immediately if the detected finding set ever diverges from the blueprint.

## Data dictionary

### `identities.csv` (1,500)
`identity_id, display_name, employee_type {Employee|Contractor|ServiceAccount}, department,
business_unit, status {Active|Disabled|Terminated}, privileged, service_account,
account_enabled, mfa_enabled, last_login_days, role_count, account_owner,
access_review_completed, admin_used_daily, risk_level`

### `cloud_resources.csv` (250)
`resource_id, resource_type {StorageAccount|VirtualMachine|SQLDatabase|KeyVault|AppService|
FunctionApp|AKSCluster}, environment {Prod|NonProd}, business_unit, internet_facing,
public_access, encryption_enabled, logging_enabled, approved_config,
excess_admin_assignments, backup_enabled, network_restricted, unsupported_runtime, owner,
risk_tier`

### `applications.csv` (100)
`app_id, app_name, app_type, business_unit, environment, service_account,
secret_rotation_days, data_sensitivity, risk_tier {Critical|High|Medium|Low}, ai_integrated,
third_party_model, open_critical_vulns, owner, human_oversight, ai_logging_enabled,
use_case_approved, input_filtering, ai_risk_classified, output_monitoring,
model_data_handling_documented, siem_onboarded, alert_owner_assigned, monitored,
ir_runbook_exists, ai_incident_playbook, event_severity_defined, vuln_sla_days,
log_retention_days`

### `data_assets.csv` (100)
`data_asset_id, data_name, data_type, business_unit, contains_pii, classification
{Public|Internal|Confidential|Restricted}, pii_classified, ai_accessible, region,
region_outside_canada, encrypted, approved_ai_access, retention_defined, retention_days,
minimisation_reviewed, transfer_approved, owner, risk_tier`

### `vendors.csv` (50)
`vendor_id, vendor_name, service_type, business_unit, ai_vendor,
criticality {Critical|High|Medium|Low}, risk_rating, data_access {None|Internal|PII},
security_assessment, ai_risk_review, contract_review, control_evidence_on_file,
exception_approved, remediation_date_set, oversight_documented, data_retention_defined,
owner`

### `control_catalog.csv` (48)
`control_id, control_name, domain, dataset, description, test_summary, remediation_effort,
initiative, owner, nist_csf, nist_ai_rmf, osfi_b13, iso_27001, roadmap_phase`

## Outputs

| File | Rows | Purpose |
|---|--:|---|
| `outputs/assessment_results.csv` | 48 | Per-control result: status, in-scope, violations, finding counts by severity, framework crosswalk |
| `outputs/risk_register.xlsx` | 137 | The full risk register (severity-coloured) |
| `outputs/framework_crosswalk.xlsx` | 48 + coverage | Control-to-framework crosswalk + coverage summary |
| `outputs/remediation_roadmap.xlsx` | 4 sheets | All initiatives + one sheet per 30-day phase |
| `outputs/executive_summary.csv` | ~19 | KPI key/value table for the deck |
| `outputs/powerbi/*.csv` | 9 tables | Flat tables for the Power BI dashboard |

## Reproducibility

Fixed seed (`42`), relative paths, no network calls, no external services. `generate_findings.py`
regenerates everything and asserts the headline metrics before it exits.
