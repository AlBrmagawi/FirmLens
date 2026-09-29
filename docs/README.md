# FirmwareLens documentation

FirmwareLens is a local workbench for authorized Linux IoT firmware research. Start with the [repository quickstart](../README.md#quickstart), then run the [source-built demo](../README.md#run-the-source-built-demo) to explore evidence, triage, release comparison and exports.

## Use the workbench

| Guide | What you will find |
| --- | --- |
| [Operations](OPERATIONS.md) | Setup, offline operation, advisory updates, optional AI, backup, migration and troubleshooting |
| [Support matrix](SUPPORT_MATRIX.md) | Supported inputs, ZIP codecs, architectures and actual test coverage |
| [API and CLI](API_CLI.md) | Authentication, commands, endpoints, automation and exit codes |
| [Analysis rules](RULES.md) | Detection behavior, evidence, severity and uncertainty |
| [Case study](CASE_STUDY.md) | A worked example using the synthetic firmware releases |
| [Limitations](LIMITATIONS.md) | Coverage gaps, interpretation limits and future work |
| [Get help](../SUPPORT.md) | Troubleshooting and reporting a reproducible problem |

## Understand and contribute

| Guide | What you will find |
| --- | --- |
| [Architecture](ARCHITECTURE.md) | Data flow, modules, jobs, persistence and trust boundaries |
| [Threat model](THREAT_MODEL.md) | Isolation controls, privileged components and residual risks |
| [Security policy](../SECURITY.md) | Private vulnerability reporting and sensitive-data handling |
| [Contributing](../CONTRIBUTING.md) | Development setup, checks and pull request guidance |
| [Quality policy](QUALITY.md) | Required checks and release evidence |
| [Third-party notices](../THIRD_PARTY_NOTICES.md) | Dependencies, analyzers, schemas and licensing |

## Assess the release

The current [release qualification](RELEASE_READINESS.md) identifies the tested implementation, successful hosted workflow and remaining limits. Its evidence is available as [QA results](validation/release-qa.json) and [runtime image results](validation/release-images-qa.json).

[Status](../STATUS.md) and the [changelog](../CHANGELOG.md) describe the delivered implementation. The [original validation](VALIDATION.md) and [initial release audit](RELEASE_AUDIT_INITIAL.md) are historical records; use the current qualification to assess readiness.
