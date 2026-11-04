# Spring Boot API Authorization Policy Validator

Research implementation for **automated validation of declared API authorization policies against effective Spring Security enforcement in Spring Boot applications**.

The validator compares endpoint policies declared in YAML with authorization information extracted from Spring MVC handlers/source code and, where supported, request-level decisions made by Spring Security.

## Research scope

The current project focuses on authorization-configuration conformance. It is not, by itself, a runtime traffic-anomaly detector or a machine-learning system.

The policy model uses three access classes:

- `PUBLIC`: endpoint is intended to be accessible without authentication.
- `AUTHENTICATED`: endpoint requires an authenticated identity.
- `ROLE_BASED`: endpoint requires one or more declared roles.

## Current validator build

The root Maven project declares Java 17 and Spring Boot parent 3.5.11. The exact resolved Spring Security dependency should be captured with `mvn dependency:tree` for each evaluation commit.

## Benchmark applications

A five-application benchmark archive has been received and inspected. Its intake details and validation caveats are documented in [benchmark/README.md](benchmark/README.md). The source ZIPs, YAML policies, ground-truth files, and supplied reports were reviewed.

The corrected report parser and Hospital Spring Security compatibility change are available on the pull request branch `fix/spring-security-63-and-docx-parser`. See [the fix notes](docs/HOSPITAL_COMPATIBILITY_AND_REPORT_PARSER_FIX.md) and [the updated report consistency audit](benchmark/evaluation/SUPPLIED_REPORT_AUDIT.md).

**Important:** the supplied reports match the supplied ground-truth files after the DOCX parser correction, but this is a consistency check, not independent detector-performance validation. Fresh reports must be generated after the Hospital runtime compatibility change is rebuilt and tested.

## Build and test

From the repository root:

```bash
mvn clean test
```

Record the command output and exact commit identifier for the final evaluation run.

## Reproducibility

Before reporting results, record the repository commit SHA; validator and benchmark application versions; exact JDK, Maven, Spring Boot, and Spring Security versions; OS and hardware; benchmark application and policy identifiers; ground-truth labels; raw reports and checksums; and exact commands/evaluation script version.

See [environment/ENVIRONMENT.md](environment/ENVIRONMENT.md) and [docs/ARTIFACT_MANIFEST.md](docs/ARTIFACT_MANIFEST.md).

## Security and licensing

Do not commit credentials, API keys, private tokens, personal data, or local environment files. Check the license and redistribution permissions for every third-party benchmark application before including its source code.

## Citation

When the benchmark and evaluation artifact are finalized, cite a stable GitHub release/tag or an archived DOI. Until then, use this repository as the project development location, not as evidence that every planned artifact has been independently reproduced.
