# TrustLens — Risk Methodology

This document explains how TrustLens turns synthetic control results into quantified,
prioritised business risk. It is deliberately transparent and tunable — every constant
lives in `src/config.py`.

---

## 1. Control model

Each of the 48 controls is defined in `src/config.py` with:

| Element | Meaning |
|---|---|
| `scope` | Which records the control applies to (e.g. `privileged = True`). `{}` = all records. |
| `detect` | The rule that makes a record non-compliant (equality, `>`, `<`, or set membership). |
| `plant` | How the data generator injects a controlled violation (used only for synthetic data). |
| framework fields | Illustrative mapping to NIST CSF 2.0, NIST AI RMF, OSFI B-13, ISO/IEC 27001. |

A control is evaluated by:

1. `scope_mask` → records in scope
2. `violation_mask` = `scope_mask AND detect_mask` → non-compliant records
3. Non-compliant records are **grouped by business unit**; each non-empty group becomes one
   **finding**.

This is why 48 controls produce 137 findings — a control that fails in four business units
produces four findings, each with its own affected-asset count.

## 2. Risk scoring

```
Risk Score = Likelihood x Impact           Likelihood in 1..5,  Impact in 1..5
Range: 1 .. 25
```

### Severity bands

| Risk Score | Severity |
|---|---|
| 20 – 25 | **Critical** |
| 15 – 19 | **High** |
| 8 – 14 | **Medium** |
| 1 – 7 | **Low** |

### Likelihood (1–5)

Driven by how directly the gap is exploitable and the number of affected assets:

| Score | Interpretation |
|---|---|
| 5 | Directly and trivially exploitable; large affected population |
| 4 | Directly exploitable under common conditions |
| 3 | Exploitable under common conditions |
| 2 | Exploitable only in limited conditions |
| 1 | Exploitable only in rare / contrived conditions |

### Impact (1–5)

Driven by the business consequence given the GenAI platform's reach:

| Score | Interpretation |
|---|---|
| 5 | Direct customer-data loss, regulatory breach, or systemic outage |
| 4 | Significant confidentiality / integrity impact on customer-facing systems |
| 3 | Contained impact on sensitive internal systems |
| 2 | Limited impact, largely internal |
| 1 | Negligible business impact |

### Worked examples

| Finding | L | I | Score | Severity | Reasoning |
|---|--:|--:|--:|---|---|
| Privileged accounts without MFA (Retail Banking) | 5 | 5 | 25 | Critical | Trivially exploitable, and these identities are how the AI platform reaches customer data |
| AI prompt input filtering disabled (Payments) | 5 | 4 | 20 | Critical | Customer PII flows to the model unfiltered; high likelihood at launch |
| Internet-facing service off baseline (Wealth Mgmt) | 4 | 4 | 16 | High | Externally reachable and misconfigured; contained to one service |
| Dataset retention undefined (Shared Technology) | 3 | 4 | 12 | Medium | Data accumulates; impact grows over time rather than immediately |
| Vendor contract missing a review date (Commercial) | 3 | 2 | 6 | Low | Governance hygiene; low immediate exposure |

The `(likelihood, impact)` values for each finding come from the finding blueprint in
`config.py` and are chosen so the 137 findings distribute as
**9 Critical / 23 High / 61 Medium / 44 Low** — a realistic pyramid for a pre-launch
assessment of an organisation with existing capability.

## 3. Control status

| Status | Rule |
|---|---|
| **Effective** | No findings |
| **Partially Effective** | Only Medium / Low findings |
| **Not Effective** | At least one High or Critical finding |

Current result: **6 Effective · 17 Partially Effective · 25 Not Effective**.

## 4. Organisational readiness score (0–100)

```
penalty(findings)  = sum over findings of  SEVERITY_PENALTY[severity]

SEVERITY_PENALTY = { Critical: 10.0, High: 6.0, Medium: 2.4, Low: 0.9 }

overall_readiness  = clamp(0, 100,  100  -  penalty(all findings) / 12.9)
domain_readiness   = clamp(0, 100,  100  -  penalty(domain findings) / 2.35)
```

### Worked calculation (current run)

| Severity | Count | Penalty each | Subtotal |
|---|--:|--:|--:|
| Critical | 9 | 10.0 | 90.0 |
| High | 23 | 6.0 | 138.0 |
| Medium | 61 | 2.4 | 146.4 |
| Low | 44 | 0.9 | 39.6 |
| **Total** | **137** | | **414.0** |

`overall_readiness = 100 − 414.0 / 12.9 = 100 − 32.1 = `**`67.9 → 68 / 100`**

### Readiness bands

| Score | Band |
|---|---|
| 85 – 100 | LOW RISK |
| 75 – 84 | MODERATE RISK |
| 60 – 74 | **HIGH RISK** |
| 0 – 59 | CRITICAL RISK |

The normalisation constants are calibrated so an organisation with real capability but
material GenAI-specific gaps lands in the **HIGH RISK** band (65–75). They are documented
here rather than hidden — a different firm could re-calibrate for its own risk appetite.

## 5. Prioritisation model

Findings are aggregated into **remediation initiatives** (e.g. "Privileged MFA
Enforcement"). For each initiative:

```
risk_points_removed = sum over findings of ( risk_score x estimated_risk_reduction% )
effort_rank         = mean control effort   ( Low = 1, Medium = 2, High = 3 )
priority_score      = ( risk_points_removed + 6 x (# Critical/High findings) ) / effort_rank
```

### Quadrants

|  | Low effort | Higher effort |
|---|---|---|
| **High value** (above-median risk points removed, or addresses a Critical/High finding) | **Quick Win** | **Strategic Initiative** |
| **Lower value** | Fill-In | **Low Priority** |

The top 10 initiatives by `priority_score` become the investment-priority table and the
input to the 90-day roadmap. This answers *"what should the CISO fund first?"*

## 6. Framework crosswalk

Each control carries an indicative mapping to:

- **NIST Cybersecurity Framework 2.0** (e.g. `PR.AA-03`, `DE.CM-01`, `GV.SC-04`)
- **NIST AI Risk Management Framework** (e.g. `GOVERN 2.1`, `MAP 4.1`, `MANAGE 4.1`)
- **OSFI Guideline B-13** (Technology and Cyber Risk Management — by domain)
- **ISO/IEC 27001:2022** (Annex A controls, e.g. `A.8.2`, `A.8.24`, `A.5.19`)

Not every control maps to every framework — infrastructure controls often have no AI RMF
mapping, and AI-governance controls map most strongly to the AI RMF. **These mappings are
illustrative for a portfolio project and are not a certified compliance crosswalk.**

## 7. Reproducibility

- Fixed seed: `config.RANDOM_SEED = 42`
- `python src/generate_findings.py` regenerates data, re-runs the assessment and re-writes
  every output. Two consecutive runs produce byte-identical CSVs.
- `generate_findings.py` asserts: 2,000 assets, 48 controls, 137 findings, the exact
  severity mix, the readiness band, and the existence of every output file. Any drift fails
  the run.
