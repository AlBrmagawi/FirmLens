# Changelog

## Release audit fixes

- Reject non-ASCII authentication tokens, CSRF values and upload digests without server errors.
- Enforce the documented ZIP codec boundary before opening members; unsupported BZIP2/LZMA/Zstandard members cannot reach decompression.
- Move shipped runtimes to Alpine/Python 3.14, rebuild analyzers with Go 1.26.8, and apply the tested upstream zlib fix.
- Block unresolved high, critical and unknown container advisories; retain raw matches and verify narrowly scoped remediation evidence.
- Migrate Debian PostgreSQL data by logical restore into a separate Alpine volume, with row verification and the original volume retained.
- Use the supported Starlette test client dependency and compare database restore contents with locale-independent ordering.
- Write image-audit JSON through the host process, avoiding Linux report-directory ownership failures and removing the scanner's writable host mount.
- Bound graceful-shutdown retries and persist cancellation timestamps correctly.
- Preserve uploads on Escape, restore dialog focus, and accept long default filenames in UI/CLI flows.
- Expand unit, cross-browser, concurrency, sandbox-failure, restore and container-audit checks. Record current outcomes in [the release audit](docs/RELEASE_READINESS.md).

## 0.1.0 — initial implementation

- Signature-led Linux firmware extraction in disposable, offline, non-root containers.
- Typed file/evidence/finding/component contracts, Syft SBOMs, local Grype matching and reproducibility manifests.
- Configuration/credential/permission rules and conservative ELF hardening analysis.
- PostgreSQL leased jobs, cancellation/recovery, authenticated FastAPI and shared Typer CLI.
- React research workbench, immutable evidence, project-scoped triage/audit/suppression, release comparison and report exports.
- Opt-in OpenAI Responses and local Ollama adapters with bounded scoped retrieval and citation validation.
- Source-built lab/revised firmware fixtures, automated tests, deployment and threat-model documentation.

See STATUS.md and docs/VALIDATION.md for exact checks performed and unverified integrations; this changelog is not a claim of universal coverage.
