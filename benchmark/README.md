# Five-Application Benchmark — Intake Review

A user-submitted archive named `Test Application.zip` was inspected for this research artifact. It contains five Spring Boot application projects and their associated policy, ground-truth, and evaluation materials.

## Inventory observed in the uploaded archive

| Application | Ground-truth endpoints | Marked misconfigured | Marked correct | Supplied CSV findings |
|---|---:|---:|---:|---:|
| College | 77 | 33 | 44 | 33 |
| E-commerce | 115 | 42 | 73 | 42 |
| ERP | 136 | 46 | 90 | 46 |
| Hospital | 51 | 25 | 26 | 25 |
| Hotel | 88 | 27 | 61 | 27 |
| **Total** | **467** | **173** | **294** | **173** |

All five nested application POM files declare Java 17 and Spring Boot 3.3.5. This is distinct from the root validator project, whose current POM declares Spring Boot 3.5.11.

## Materials found

For each application, the archive contains a source-project ZIP, a YAML policy file, a ground-truth CSV, a misconfiguration description, an evaluator script, and a supplied CSV security report. The five top-level evaluator scripts are byte-identical; one common copy is sufficient. The Hospital project also contains an alternate evaluator, a DOCX security report, a duplicate extracted source tree, build output, and a run log.

## Validation findings requiring attention

- The supplied CSV reports match all 173 ground-truth rows labelled `MISCONFIGURED`: no missing or extra endpoints and no violation-type or severity mismatches. Therefore the supplied report/label pairs produce perfect agreement under the supplied evaluator. Their independent generation provenance is not documented in the archive, so this is only a file-consistency check and must not be presented as independently reproduced detector performance.
- The supplied Hospital DOCX report is inconsistent with its CSV report. Against the same ground truth, the evaluator reads 25 findings, with 100% violation-type accuracy but only 44% severity accuracy (11/25). Resolve this mismatch before claiming consistent DOCX parsing.
- The Hospital run log records a startup failure during request-level validation. `RequestAuthorizationEvaluator.isGranted` calls `AuthorizationManager.authorize(Supplier,Object)`, but the loaded `spring-security-core` is 6.3.4 and does not provide that method. This is a Spring Security binary-compatibility issue to fix before benchmarking the Spring Boot 3.3.5 applications with the current validator.
- No benchmark-generator/fault-injection source directory was found. The misconfiguration lists describe the injected scenarios but are not a generator.
- The sample applications include hard-coded demo users/passwords intended for local testing. Do not deploy them as-is.

## Repository status

This file records the intake review. The normalized benchmark data bundle must still be uploaded into this repository (or attached to a versioned release) before the paper describes it as publicly available here. The uploaded archive and the normalized copy are available in the working conversation; generated `target/` output, Eclipse metadata, duplicate Hospital files, and screenshot-only output were excluded from the normalized bundle.

See [the supplied-report audit](evaluation/SUPPLIED_REPORT_AUDIT.md) and [the artifact manifest](../docs/ARTIFACT_MANIFEST.md).
