# TrustLens — Power BI Executive Dashboard (build guide)

This guide builds **one strong executive page**: *"NorthStar Bank — GenAI Readiness"*.

> No `.pbix` is committed (it is a binary that cannot be generated headless and reliably).
> Everything the dashboard needs is in `outputs/powerbi/*.csv`; this guide is the recipe.

---

## 1. Load the data

**Home → Get data → Text/CSV**, and load each file from `outputs/powerbi/`:

| Table | Grain | Used for |
|---|---|---|
| `findings` | 1 row per finding (137) | severity, domain, top-risk visuals, slicers |
| `domain_summary` | 1 row per domain (6) | risk-by-domain, domain readiness |
| `severity_summary` | 1 row per severity (4) | findings-by-severity donut |
| `top10_risks` | 10 rows | top-10 risk bar |
| `control_status` | 1 row per control (48) | control pass/fail rate |
| `framework_coverage` | 4 rows | framework coverage |
| `risk_effort_matrix` | 1 row per initiative (~22) | risk-vs-effort scatter |
| `investment_priorities` | top 10 initiatives | investment-priority table |
| `kpis` | metric / value | KPI cards |

In **Power Query**, set data types (Whole Number for counts/scores, Decimal for
percentages, Text for names) and **Close & Apply**.

## 2. Data model (relationships)

Create single-direction, one-to-many relationships from the dimension to `findings`:

- `domain_summary[domain]` → `findings[domain]`
- `control_status[domain]` → `findings[domain]`  *(keep inactive if it causes ambiguity)*
- `severity_summary[severity]` → `findings[severity]`

`risk_effort_matrix` / `investment_priorities` relate on `initiative` if you want the
slicer to cross-filter; otherwise leave them standalone. `kpis` and `framework_coverage`
stay standalone (they are pre-aggregated).

## 3. Measures (DAX)

Create a `_Measures` table (**Home → Enter data**, one blank column) and add:

```DAX
Total Findings = COUNTROWS ( findings )

Critical Findings = CALCULATE ( [Total Findings], findings[severity] = "Critical" )
High Findings     = CALCULATE ( [Total Findings], findings[severity] = "High" )

Controls Tested = DISTINCTCOUNT ( control_status[control_id] )

Controls Not Effective =
CALCULATE ( DISTINCTCOUNT ( control_status[control_id] ),
            control_status[status] = "Not Effective" )

Control Effectiveness Rate =
DIVIDE (
    CALCULATE ( DISTINCTCOUNT ( control_status[control_id] ),
                control_status[status] = "Effective" ),
    [Controls Tested]
)

Assets Assessed = 2000   -- or: VALUE ( LOOKUPVALUE ( kpis[value], kpis[metric], "assets_assessed" ) )

Readiness Score =
VAR s = LOOKUPVALUE ( kpis[value], kpis[metric], "genai_readiness_score" )
RETURN VALUE ( s )

Readiness Band =
VAR r = [Readiness Score]
RETURN SWITCH ( TRUE(),
    r >= 85, "LOW RISK",
    r >= 75, "MODERATE RISK",
    r >= 60, "HIGH RISK",
    "CRITICAL RISK" )

Readiness Card Label = FORMAT ( [Readiness Score], "0" ) & " / 100  —  " & [Readiness Band]
```

## 4. Page layout (single 16:9 page)

```
┌────────────────────────────────────────────────────────────────────────────┐
│  NorthStar Bank — GenAI Security & Digital Trust Readiness      [BU slicer] │
├───────────┬───────────┬───────────┬───────────┬───────────┬────────────────┤
│ Readiness │ Controls  │ Total     │ Critical  │ High      │ Assets         │  ← KPI cards
│ 68 / 100  │ Tested 48 │ Findings  │ Findings  │ Findings  │ Assessed       │
│ HIGH RISK │           │ 137       │ 9         │ 23        │ 2,000          │
├───────────┴───────────┴───────────┼───────────┴───────────┴────────────────┤
│ (1) Risk by control domain        │ (2) Findings by severity (donut)       │
│     stacked bar                   │                                        │
├───────────────────────────────────┼────────────────────────────────────────┤
│ (3) Top 10 risks (bar)            │ (6) Risk vs remediation effort         │
│                                   │     scatter — the quick-win finder     │
├───────────────────────────────────┼────────────────────────────────────────┤
│ (4) Control effectiveness         │ (5) Framework coverage (matrix)        │
│     100% stacked bar              │ (7) Top investment priorities (table)  │
└───────────────────────────────────┴────────────────────────────────────────┘
```

## 5. Visual-by-visual

### KPI cards (top band, 6 × **Card**)
| Card | Field / measure |
|---|---|
| GenAI Readiness | `[Readiness Card Label]` (Card) — set callout to the measure; add `[Readiness Band]` as a small multi-row card beneath, conditionally coloured |
| Controls Tested | `[Controls Tested]` |
| Total Findings | `[Total Findings]` |
| Critical Findings | `[Critical Findings]` — red |
| High Findings | `[High Findings]` — orange |
| Assets Assessed | `[Assets Assessed]` |

Conditional formatting for the readiness card: **Format → Callout value → fx** →
Field value = `[Readiness Band]` mapped to colours (LOW=green, MODERATE=amber,
HIGH=orange-red, CRITICAL=red).

### (1) Risk by control domain — **Stacked bar chart**
- Y axis: `findings[domain]`
- X axis: `Total Findings`
- Legend: `findings[severity]`
- Sort descending by count. Colour severity consistently everywhere:
  Critical `#C0392B`, High `#E67E22`, Medium `#F1C40F`, Low `#7FB3D5`.
- *Alt version:* Y axis `domain_summary[domain]`, X axis `domain_summary[readiness_score]`
  to show the six-domain readiness bars.

### (2) Findings by severity — **Donut chart**
- Legend: `severity_summary[severity]`
- Values: `severity_summary[findings]`
- Detail/tooltip: `severity_summary[pct_of_findings]`

### (3) Top 10 risks — **Clustered bar chart**
- Y axis: `top10_risks[title]` (or `finding_id` + `title`)
- X axis: `top10_risks[risk_score]`
- Legend/colour: `top10_risks[severity]`
- Tooltip: `business_impact`, `business_unit`, `affected_assets`
- Sort by `rank` ascending.

### (4) Control effectiveness rate — **100% stacked bar** (or stacked column)
- Axis: `control_status[domain]` (or a single "All controls" bar)
- Values: count of `control_status[control_id]`
- Legend: `control_status[status]` (Effective / Partially Effective / Not Effective)
- Colours: Effective `#27AE60`, Partially `#F1C40F`, Not Effective `#C0392B`
- Add a Card with `[Control Effectiveness Rate]` (format %) as the headline number.

### (5) Framework coverage — **Matrix** (or clustered bar)
- Rows: `framework_coverage[framework]`
- Values: `controls_mapped`, `coverage_pct`, `findings_mapped`
- Data bars on `coverage_pct`.

### (6) Risk vs remediation effort — **Scatter chart** (the executive quick-win finder)
- X axis: `risk_effort_matrix[effort_rank]` (1 = Low, 2 = Medium, 3 = High) — rename axis
  ticks via a small mapping table or just label the axis "Implementation effort →"
- Y axis: `risk_effort_matrix[expected_risk_reduction_pct]`
- Size: `risk_effort_matrix[risk_points_removed]` (or `total_risk_score`)
- Legend: `risk_effort_matrix[quadrant]`
- Details: `risk_effort_matrix[initiative]`
- Add **constant lines**: X analytics line at `1.5`, Y analytics line at the median
  reduction (~30). Label the bottom-left quadrant **"QUICK WINS"** and the top-right
  **"STRATEGIC"** with text boxes.
- This lets an executive see immediately: *bottom-right of the reduction axis + left of the
  effort axis = do it now.*

### (7) Top investment priorities — **Table**
- Columns: `rank`, `initiative`, `quadrant`, `implementation_effort`,
  `expected_risk_reduction_pct`, `risk_points_removed`, `priority_score`
- Sort by `rank`. Conditional-format `quadrant` (Quick Win = green, Strategic = blue,
  Low Priority = grey).

## 6. Slicer

Add one **slicer** on `findings[business_unit]` (Retail Banking, Commercial Banking, Wealth
Management, Payments, Digital & AI, Shared Technology) at the top right. It cross-filters
visuals 1, 2, 3 and (if related) 6/7. Set **Format → Slicer settings → Single select off**.

## 7. Theme

**View → Themes → Customize current theme**, set the data colours to the severity palette
above so every visual is consistent. Use a white background, one accent colour (`#1F3A5F`
navy) for titles, and keep the page uncluttered — this is a CISO/CIO page, not an analyst page.

## 8. Export

**File → Export → Export to PDF** for the deck, or take a screenshot of the full page for
the GitHub README (`dashboard/screenshot-executive.png`).
