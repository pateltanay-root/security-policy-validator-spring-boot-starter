# Reproducibility and Artifact Plan

## Purpose

This document describes the artifact package intended to accompany the research paper, **A Dual-View Framework for Automated API Authorization Policy Conformance in Spring Boot Applications**.

The package is designed to allow another researcher to inspect the validator, reproduce the benchmark conditions, compare tool output with ground-truth labels, and regenerate every reported metric.

## Planned artifact bundle

The intended artifact bundle consists of:

1. **Source code** for the validator, identified by a Git commit SHA.
2. **Five benchmark applications**, targeted to Java 17 and Spring Boot 3.3.5, together with the application/generator code used to construct the benchmark.
3. **YAML policy files** defining the expected authorization policy for each benchmark application.
4. **Ground-truth label files** identifying the expected configuration state and seeded violation type for each endpoint.
5. **An evaluation script** intended to accept the validator's JSON, CSV, or Microsoft Word (DOCX) reports and calculate the evaluation measures.
6. **Raw tool reports** preserved as produced by each experiment.
7. **Metric-generation scripts** that calculate every value reported in the paper and, where applicable, generate tables and figures.

The exact repository commit, artifact release, or archival URL should be recorded here after the complete package is committed. Until then, the repository URL is a development location; the planned contents must not be described as already released.

## Important version distinction

The current root validator Maven project declares Java 17 and Spring Boot parent **3.5.11** in `pom.xml`. The five benchmark applications described in the manuscript are targeted at Java 17 and Spring Boot **3.3.5**.

These are separate project environments. Preserve and document the actual versions used by each project. Do not change the validator version label to 3.3.5 unless its own build file is actually changed and tested.

## Suggested repository layout

```text
.
├── README.md
├── pom.xml
├── src/
│   ├── main/
│   └── test/
├── benchmark/
│   ├── apps/
│   │   ├── app-01/
│   │   ├── app-02/
│   │   ├── app-03/
│   │   ├── app-04/
│   │   └── app-05/
│   └── generator/
├── policies/
├── ground-truth/
├── evaluation/
├── reports/
│   └── raw/
├── results/
├── scripts/
├── environment/
└── docs/
    ├── ARTIFACT_MANIFEST.md
    └── REPRODUCIBILITY_AND_ARTIFACT_PLAN.md
```

## Evaluation script contract

The evaluation implementation should document and test:

- supported input formats (JSON, CSV, DOCX only when implemented);
- required report fields and example schemas;
- how a reported finding is matched to a ground-truth endpoint and violation label;
- the unit of analysis used for TP, TN, FP, and FN (for example, endpoint-policy pair or injected fault);
- handling of duplicate findings and findings with incorrect violation types;
- precision, recall, F1-score, and false-positive-rate calculations;
- validation-time measurement and its units;
- output file format and command-line invocation.

Do not claim a report format is supported based only on the intended design. Commit parser tests for every claimed format.

## Reproduction procedure

For each experiment:

1. Check out the exact validator commit recorded in the paper.
2. Install the toolchain documented in `environment/ENVIRONMENT.md`.
3. Build and test the validator.
4. Build the five benchmark applications at their documented commits.
5. Run the benchmark generator/fault-injection process and preserve the seed/configuration where applicable.
6. Apply the corresponding YAML policy files.
7. Execute the validator using the recorded command and configuration.
8. Preserve the unmodified output reports in `reports/raw/`.
9. Run the evaluation script against those reports and the ground-truth labels.
10. Store generated metrics and plots in `results/`.
11. Record the Git commit SHA, execution command, timestamp, and checksums for the input/output artifacts.

## Environment information to publish

Record at minimum:

- operating system and version;
- CPU model and available memory;
- JDK vendor and exact version;
- Maven version;
- validator Spring Boot and Spring Security versions;
- each benchmark application's Spring Boot and Spring Security versions;
- generator and evaluation-script versions;
- command-line options and relevant configuration.

A fill-in template is provided in `environment/ENVIRONMENT.md`.

## Data integrity and licensing

Raw reports should not be manually edited after collection. If a report must be redacted, preserve the original securely and document the redaction procedure and the published derivative.

Before committing third-party benchmark applications, check their licenses and permissions. Do not upload credentials, tokens, private keys, personal data, or confidential test data.

## Repository / archival location

Repository: https://github.com/pateltanay-root/security-policy-validator-spring-boot-starter

Release/tag: To be assigned after the benchmark and evaluation package is complete.

Archival DOI: To be added if the repository is archived in a DOI-minting service.
