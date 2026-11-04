# Supplied Report Consistency Audit

This audit compares the `security-report.csv` files provided in `Test Application.zip` with their corresponding ground-truth CSV files. It does **not** independently reproduce the validator execution.

## CSV report comparison

| Application | Endpoints | Misconfigured | Correct | CSV findings | Missing findings | Extra findings | Type/severity mismatches |
|---|---:|---:|---:|---:|---:|---:|---:|
| College | 77 | 33 | 44 | 33 | 0 | 0 | 0 |
| E-commerce | 115 | 42 | 73 | 42 | 0 | 0 | 0 |
| ERP | 136 | 46 | 90 | 46 | 0 | 0 | 0 |
| Hospital | 51 | 25 | 26 | 25 | 0 | 0 | 0 |
| Hotel | 88 | 27 | 61 | 27 | 0 | 0 | 0 |
| **Total** | **467** | **173** | **294** | **173** | **0** | **0** | **0** |

The supplied CSV reports match the supplied ground-truth labels exactly. Under the supplied evaluator's endpoint-level binary rule, the counts are TP=173, FP=0, FN=0, TN=294. This reflects internal consistency of the submitted report and label files. It is not an independently verified performance result because the archive does not provide a reproducible, clean run trace proving how the CSV reports were generated.

## Hospital DOCX comparison

The supplied `security-report.docx` was separately parsed against the Hospital ground truth:

- Findings parsed: 25
- Violation-type accuracy: 100%
- Severity accuracy: 44% (11 of 25)
- Severity mismatches: 14

This differs from the Hospital CSV report, which matches all 25 expected violation types and severities. Investigate whether the DOCX report is an older report, a manually edited report, or a parser/input issue before treating DOCX and CSV as equivalent supported formats.

## Runtime compatibility finding

The submitted Hospital `run.log` shows that the application started its web server but failed when the security-policy validation runner executed. The relevant call is:

```text
RequestAuthorizationEvaluator.isGranted
  -> AuthorizationManager.authorize(Supplier, Object)
```

The loaded `spring-security-core` class is version 6.3.4, which does not provide the method referenced by the validator class. Align the validator's compiled Spring Security API with the version resolved by the Spring Boot 3.3.5 benchmark application, then rerun the application and regenerate the report.

## Publication recommendation

Do not insert the perfect CSV-derived values into the paper as final detection performance yet. First regenerate all five reports from a clean checkout of the validator and benchmark projects, capture command logs and commit SHAs, resolve the Hospital DOCX/CSV discrepancy, and document the exact toolchain.
