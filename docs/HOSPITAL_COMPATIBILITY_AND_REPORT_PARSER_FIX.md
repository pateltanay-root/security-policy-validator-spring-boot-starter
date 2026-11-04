# Compatibility and DOCX Evaluator Fixes

## 1. Spring Security 6.3 runtime compatibility

The Hospital app uses Spring Boot 3.3.5 and resolves Spring Security 6.3.4. The previous validator bytecode invoked `AuthorizationManager.authorize(Supplier, Object)`, which was introduced in Spring Security 6.4. The runtime therefore failed with `NoSuchMethodError`.

The validator's `RequestAuthorizationEvaluator` now uses `AuthorizationManager.check(Supplier, Object)` and reads the returned `AuthorizationDecision`. The `check` method exists in Spring Security 6.3.x; it is deprecated in later 6.x versions but remains available in the 6.5 API. This keeps the starter callable by Spring Boot 3.3.x applications without forcing the benchmark projects to upgrade their Spring Boot parent.

Reference: Spring Security 6.3 API documentation lists `AuthorizationManager.check`; Spring Security 6.4 API documentation marks `authorize` as introduced in 6.4:
- https://docs.spring.io/spring-security/site/docs/6.3.3/api/org/springframework/security/authorization/AuthorizationManager.html
- https://docs.spring.io/spring-security/site/docs/6.4.10/api/org/springframework/security/authorization/AuthorizationManager.html

**Verification still required:** build/install the modified starter and rerun the Hospital app using the same Windows/JDK/Maven setup. The current execution environment does not contain Maven or the full dependency cache, so an end-to-end Java rebuild was not performed here.

## 2. DOCX severity parsing

The earlier report parser assumed that an endpoint begins a record and then searched subsequent lines for type and severity. The supplied Hospital DOCX uses the order `Severity`, `Endpoint`, `Type`, `Message`. Because the previous parser did not close the preceding record before reading the next severity, it shifted severity values onto the wrong endpoint.

The updated evaluator starts a new record when it encounters a new `Severity:` field, and reads CSV reports by named columns instead of parsing them as arbitrary text.

## 3. Recheck against the supplied Hospital files

After the parser correction:
- DOCX: 25 findings parsed; TP=25, FP=0, FN=0, TN=26; violation-type accuracy=100%; severity accuracy=100%.
- CSV: 25 findings parsed; TP=25, FP=0, FN=0, TN=26; violation-type accuracy=100%; severity accuracy=100%.

These are consistency comparisons against the supplied ground-truth file. They are **not** independently reproduced validator detection results. Regenerate reports after the Java compatibility fix before presenting them as measured performance.

Run:
```bash
python evaluate.py --truth ground_truth.csv --report security-report.docx
python evaluate.py --truth ground_truth.csv --report security-report.csv
python -m unittest -v
```
