# Changelog

## Release audit fixes

- Bound graceful-shutdown retries and persist cancellation timestamps correctly.
- Preserve uploads on Escape, restore dialog focus, and accept long default filenames in UI/CLI flows.
- Update Python/Debian and PostgreSQL runtime images; verify an isolated restore and preserve database metadata through the upgrade.
- Expand unit, cross-browser, concurrency, sandbox-failure, restore and container-audit checks. Retain the unresolved upstream container security gate in [the release audit](docs/RELEASE_READINESS.md).

## 0.1.0 — initial implementation

- Signature-led Linux firmware extraction in disposable, offline, non-root containers.
- Typed file/evidence/finding/component contracts, Syft SBOMs, local Grype matching and reproducibility manifests.
- Configuration/credential/permission rules and conservative ELF hardening analysis.
- PostgreSQL leased jobs, cancellation/recovery, authenticated FastAPI and shared Typer CLI.
- React research workbench, immutable evidence, project-scoped triage/audit/suppression, release comparison and report exports.
- Opt-in OpenAI Responses and local Ollama adapters with bounded scoped retrieval and citation validation.
- Source-built lab/revised firmware fixtures, automated tests, deployment and threat-model documentation.

See STATUS.md and docs/VALIDATION.md for exact checks performed and unverified integrations; this changelog is not a claim of universal coverage.
