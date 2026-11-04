# Supplied Report Consistency Audit

This audit compares the reports supplied in `Test Application.zip` with the corresponding ground-truth CSV files. It does **not** independently reproduce validator execution.

## CSV report comparison

| Application | Endpoints | Misconfigured | Correct | CSV findings | Missing findings | Extra findings | Type/severity mismatches |
|---|---:|---:|---:|---:|---:|---:|---:|
| College | 77 | 33 | 44 | 33 | 0 | 0 | 0 |
| E-commerce | 115 | 42 | 73 | 42 | 0 | 0 | 0 |
| ERP | 136 | 46 | 90 | 46 | 0 | 0 | 0 |
| Hospital | 51 | 25 | 26 | 25 | 0 | 0 | 0 |
| Hotel | 88 | 27 | 61 | 27 | 0 | 0 | 0 |
| **Total** | **467** | **173** | **294** | **173** | **0** | **0** | **0** |

The supplied CSV reports match the supplied ground-truth labels exactly. Under the supplied endpoint-level binary rule, the aggregate counts are TP=173, FP=0, FN=0, TN=294. This is a report-to-label consistency check only, not independently verified detector performance. The archive does not provide a reproducible clean-run trace proving how every report was generated.

## Hospital DOCX parser finding — corrected

The earlier 44% Hospital DOCX severity accuracy was caused by a parser field-order bug, not by a demonstrated disagreement in the DOCX content.

The DOCX uses this order for each record:

1. `Severity: ...`
2. `Endpoint: METHOD:/path`
3. `Type: ...`
4. `Message: ...`

The former parser assumed endpoint-first ordering. It therefore assigned each new record's severity to the preceding record. The corrected parser starts a new finding at each new `Severity:` field and keeps the severity with the following endpoint/type.

Re-running the supplied Hospital ground truth and reports with the corrected parser gives:

| Hospital report | Findings parsed | TP | FP | FN | TN | Violation-type accuracy | Severity accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|
| DOCX, corrected parser | 25 | 25 | 0 | 0 | 26 | 100% | 100% |
| CSV | 25 | 25 | 0 | 0 | 26 | 100% | 100% |

These values show agreement between the supplied files and the supplied ground truth; they must not be presented as independently reproduced detection performance until the validator is rerun successfully and fresh reports are preserved.

## Hospital runtime compatibility finding

The submitted Hospital `run.log` shows that the application starts its web server but fails when the validator runner performs request-level authorization analysis.

The failing call was:

```text
RequestAuthorizationEvaluator.isGranted
  -> AuthorizationManager.authorize(Supplier, Object)
```

The Hospital application loads `spring-security-core` 6.3.4. The validator bytecode references the newer `authorize` method, which is not available in this runtime. A compatibility patch on the branch `fix/spring-security-63-and-docx-parser` changes the evaluator to use `AuthorizationManager.check(Supplier, Object)`, returning an `AuthorizationDecision`.

The patch still requires a clean Maven build/install of the validator and a fresh Hospital application startup on the target Windows/JDK/Maven environment. This environment did not contain Maven, so the Java runtime fix has not yet been end-to-end verified here.

## Publication recommendation

After the compatibility patch is installed, rerun all five applications, retain fresh raw reports and startup logs, record exact commit SHAs and dependency trees, and regenerate metrics using the corrected evaluator. Do not report the supplied-file consistency values as final empirical detection performance.
