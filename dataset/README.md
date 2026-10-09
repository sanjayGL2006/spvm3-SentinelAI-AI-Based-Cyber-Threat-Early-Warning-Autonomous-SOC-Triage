# CRQ Optimize: synthetic dataset

All data is **synthetic** (generated with a fixed seed). It exists to test and demo the platform and cannot validate real-world accuracy. Currency: INR.

| File | Rows | Use |
|---|---|---|
| assets.csv | 31 | Import with the Import tab (kind = assets) |
| findings.csv | 152 | Import after assets (kind = findings) |
| services.csv | 5 | Business services (Phase 3 import) |
| asset_service_map.csv | 11 | Assets to services mapping (Phase 3) |
| scenarios.csv | 6 | Enter in Scenarios (frequency per year, loss per event in INR) |
| mitigations.csv | 10 | Enter in Mitigations (includes a prerequisite, an exclusion and a mandatory action) |

## Built-in data-quality cases
- assets.csv: one duplicate asset name (Payment Gateway), three assets with no owner.
- findings.csv: 2 findings with no matching asset, 1 with no asset, 1 missing title, 2 invalid severities (urgent, 15) and 2 duplicate references.
Expected importer result for findings: rejected 3, duplicates 2, unmatched 3 (verified with the importer).

## Suggested demo
1. Import assets, then findings; show the error table and the Needs-review list.
2. Add the 6 scenarios; run the analysis.
3. Add mitigations; run the optimizer with budgets of INR 1,500,000, 3,000,000 and 6,000,000 and compare plans.
