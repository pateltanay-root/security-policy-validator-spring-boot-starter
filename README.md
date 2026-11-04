# Spring Boot API Authorization Policy Validator

Research implementation for **automated validation of declared API authorization policies against effective Spring Security enforcement in Spring Boot applications**.

The validator compares endpoint policies declared in YAML with authorization information extracted from Spring MVC handlers/source code and, where supported, request-level decisions made by Spring Security.

## Research scope

The current project focuses on authorization-configuration conformance. It is not, by itself, a runtime traffic-anomaly detector or a machine-learning system.

The policy model uses three access classes:

- `PUBLIC`: endpoint is intended to be accessible without authentication.
- `AUTHENTICATED`: endpoint requires an authenticated identity.
- `ROLE_BASED`: endpoint requires one or more declared roles.

The validator reports typed policy deviations and severity information. See [the reproducibility and artifact plan](docs/REPRODUCIBILITY_AND_ARTIFACT_PLAN.md) for the planned benchmark and evaluation package.

## Current validator build

The root Maven project currently declares:

| Component | Version/configuration |
|---|---|
| Java | 17 |
| Spring Boot parent | 3.5.11 |
| JavaParser | 3.26.4 |
| Build | Maven |

These values are taken from the current root `pom.xml`. The exact Spring Security dependency version should be recorded from the resolved Maven dependency tree for each reproducible experiment.

## Repository layout

```text
.
├── pom.xml
├── src/
│   ├── main/
│   └── test/
├── docs/
│   ├── ARTIFACT_MANIFEST.md
│   └── REPRODUCIBILITY_AND_ARTIFACT_PLAN.md
└── environment/
    └── ENVIRONMENT.md
```

The benchmark application folders, generator, policy files, ground-truth labels, evaluation program, raw reports, and generated results should be added as they are implemented and verified. The intended layout is documented in the artifact plan; empty or planned items must not be treated as completed evidence.

## Build and test

From the repository root, use:

```bash
mvn clean test
```

Record the command output and exact commit identifier for the final evaluation run. A historical test log is not a substitute for a clean run against the committed revision.

## Planned research artifact

The planned publication artifact includes five benchmark Spring Boot applications (Java 17; target Spring Boot 3.3.5), a generator/fault-injection component, YAML policies, ground-truth labels, an evaluation script, raw reports, metric-generation scripts, and environment details. This benchmark package is separate from the root validator project, whose current Maven parent is Spring Boot 3.5.11.

The evaluation script is intended to accept JSON, CSV, and Word/DOCX reports. List a format as supported only after its parser and tests have been committed.

## Reproducibility

Before reporting results, record:

- repository commit SHA;
- validator and benchmark application versions;
- exact JDK, Maven, Spring Boot, and Spring Security versions;
- OS and hardware;
- benchmark application and policy identifiers;
- ground-truth labels;
- raw report files and checksums;
- exact commands and evaluation script version.

See [environment/ENVIRONMENT.md](environment/ENVIRONMENT.md) and [docs/ARTIFACT_MANIFEST.md](docs/ARTIFACT_MANIFEST.md) for the recording templates.

## Security and licensing

Do not commit credentials, API keys, private tokens, personal data, or local environment files. Check the license and redistribution permissions for every third-party benchmark application before including its source code. Add a repository license only after confirming that you have the right to license all material it covers.

## Citation

When the benchmark and evaluation artifact are finalized, cite a stable GitHub release/tag or an archived DOI in the paper. Until then, use the repository URL as a project-development link, not as evidence that every planned artifact is already available.
