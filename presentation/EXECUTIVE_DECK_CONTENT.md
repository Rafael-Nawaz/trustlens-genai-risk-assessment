# NorthStar Bank — GenAI Security & Digital Trust Assessment
## Executive presentation content (5 slides)

Audience: CISO / CIO and the technology risk committee.
Tone: consulting advisor to the executive — plain language, decision-focused.
Every number below is produced by the TrustLens pipeline (`outputs/`).

---

## SLIDE 1 — Executive Summary

### Should the bank launch the GenAI platform today?

> **Not today. Proceed with a controlled launch once the Critical and High findings are
> resolved — a focused 30-day effort, not a re-platform.**

**GenAI Readiness: 68 / 100 — HIGH RISK**
NorthStar has real security capability. It is not yet ready to expose customer data to a
generative AI platform.

**Three observations**

1. **The identities the AI will operate through are the weakest link.** Privileged accounts
   without MFA, active accounts for departed staff, and role sprawl — Identity & Access
   Management scores lowest of the six domains (66 / 100).
2. **The AI-specific control layer is largely not yet built.** AI activity logging, prompt
   input filtering, human oversight and AI incident response are inconsistent or absent.
3. **Customer data can reach the model without approval.** Unapproved AI data access,
   under-registered PII and no enforced data minimisation on AI pathways.

**Three priority recommendations**

1. **Stabilize identity and cloud exposure** — enforce privileged MFA, disable stale
   privileged accounts, close public storage and logging gaps (0–30 days).
2. **Put an AI governance operating model in place** — ownership, risk tiering, human
   oversight, approved use cases, and AI activity logging to the SOC (0–60 days).
3. **Control the data boundary to the model** — AI data-access allow-list, prompt-side DLP,
   and a data-minimisation gate before any dataset is connected (0–60 days).

**The bottom line:** 9 Critical and 23 High findings stand between NorthStar and a safe
launch. All 9 Critical findings sit inside the top 3 recommendations above.

---

## SLIDE 2 — Current-State Risk Assessment

### Readiness across the six control domains

| Domain | Readiness | Rating | Read |
|---|--:|---|---|
| Governance & Third-Party Risk | 79 | Moderate | Vendor programme exists; AI vendors not yet reviewed |
| Security Operations | 74 | Moderate | Solid SOC; AI incidents and some critical systems not covered |
| Cloud Security | 68 | High risk | Mostly controlled; residual public / unencrypted exposure |
| Privacy & Data Protection | 68 | High risk | Classification and AI-data-access gaps |
| AI Governance | 68 | High risk | Control layer still being built |
| Identity & Access Management | 66 | High risk | Privileged access is the top exposure |

**48 controls tested → 6 Effective · 17 Partially Effective · 25 Not Effective**
**137 findings → 9 Critical · 23 High · 61 Medium · 44 Low**

*Speaker note:* the shape is typical of an organisation with a mature traditional security
programme that has not yet extended it to AI. The gaps are concentrated and fixable, not
systemic.

---

## SLIDE 3 — Top Risks

### The five gaps that block a safe launch

| # | Risk | Domain | Why it matters to the business |
|---|---|---|---|
| 1 | **Privileged accounts without phishing-resistant MFA** (15 accounts, Retail Banking) | IAM | Most common route to ransomware and wire fraud; these accounts are how the AI platform reaches customer data |
| 2 | **Active accounts for terminated / disabled staff** (13 accounts) | IAM | Unmonitored standing access; a favoured insider and post-breach path |
| 3 | **Publicly accessible cloud storage** (12 resources, Wealth Management) | Cloud | Leading cause of large financial-data breaches; direct customer-trust and OSFI impact |
| 4 | **AI can access customer data that was never approved for AI use** (8 datasets) | Privacy | The model could surface customer PII or confidential records in a response |
| 5 | **No prompt input filtering / AI activity logging** (Digital & AI, Wealth Management) | AI Governance | Customer PII flows to the model unfiltered, and the SOC cannot see or investigate misuse |

Each of these is a **risk score of 20–25 (Critical)** — high likelihood, high business
impact. Collectively they represent the difference between "AI as a contained pilot" and
"AI as an unbounded data-exposure surface".

---

## SLIDE 4 — Investment Priorities

### What the CISO should fund first

Ranked by risk reduction per unit of effort; quadrant = quick win vs strategic.

| Rank | Initiative | Type | Effort | Expected risk reduction |
|---|---|---|---|---|
| 1 | **AI Governance Operating Model** — ownership, risk tiering, oversight, use cases | Quick Win | Low | ~29% across AI findings |
| 2 | **Cloud Exposure Remediation** — public storage, encryption, hardened external services | Strategic | Medium | ~34% |
| 3 | **AI Audit Logging** — prompts, responses, retrieval to the SIEM | Strategic | Medium | ~49% |
| 4 | **Third-Party AI Risk Review** — AI vendor reviews, data-handling disclosure, oversight | Strategic | Medium | ~30% |
| 5 | **Privileged MFA Enforcement** — phishing-resistant MFA on all admin accounts | Quick Win | Low | ~38% |
| 6 | **Automated Access Reviews** — quarterly certification + 90-day dormancy policy | Quick Win | Low | ~28% |
| 7 | **Technology Risk Governance** — risk owners, remediation dates, exception approvals | Quick Win | Low | ~26% |

**Quick wins (fund immediately):** AI governance operating model, privileged MFA, access
reviews, technology risk governance — all low effort, all high value.
**Strategic (fund with a plan and a budget line):** cloud exposure remediation, AI audit
logging, AI data-loss prevention, third-party AI risk, privileged access modernisation.

*One-line answer:* **~$ of effort on four low-cost governance and identity fixes removes
most of the Critical exposure; the strategic items make it durable.**

---

## SLIDE 5 — 90-Day Transformation Roadmap

### Stabilize → Govern → Scale

**Days 0–30 — STABILIZE** *(remove the launch-blockers)*
- Enforce phishing-resistant MFA on every privileged account
- Disable active accounts for terminated / disabled staff
- Close publicly accessible cloud storage; enable diagnostic logging
- Stand up AI prompt input filtering (DLP) on all AI pathways
- Turn on AI activity logging to the SOC

**Days 31–60 — GOVERN** *(build the operating model)*
- Establish AI ownership, risk classification and human-oversight rules
- Approve (or deny) every dataset the AI can access; enforce data minimisation
- Define AI and customer-data retention; auto-purge prompt / conversation data
- Run formal AI vendor risk reviews and document supplier oversight
- Complete sensitive-data classification and owner assignment

**Days 61–90 — SCALE** *(make it continuous)*
- Automate access certification and dormancy management
- Introduce continuous cloud control monitoring (policy guardrails + drift)
- Start executive AI-risk reporting to the technology risk committee
- Integrate security checks into the deployment pipeline
- Schedule recurring AI risk assessments (this assessment, repeatable)

**Checkpoint at day 30:** re-run the assessment. Target: 0 Critical, < 10 High, readiness
≥ 78 → **approve the controlled production launch.**

---

## Appendix — 60-second interview answer

> "TrustLens is a consulting-style cybersecurity readiness assessment I built for a
> fictional Canadian bank that wanted to launch a generative-AI customer-service platform on
> Azure. I generated a synthetic enterprise of 2,000 identities, cloud resources,
> applications, data assets and vendors, then wrote a Python engine that tests 48 controls
> across six domains — identity, cloud, privacy, AI governance, security operations and
> third-party risk. It produced 137 findings, each scored with a likelihood-times-impact
> model and mapped to NIST CSF 2.0, the NIST AI RMF, OSFI B-13 and ISO 27001. I rolled that
> up into a 0–100 readiness score — the bank came out at 68, 'high risk' — and a Power BI
> executive dashboard with a risk-versus-effort view so the CISO can see the quick wins. The
> recommendation wasn't 'don't launch' — it was 'controlled launch after a 90-day
> Stabilize–Govern–Scale roadmap that clears the nine critical findings.' The whole thing is
> reproducible from one command."
