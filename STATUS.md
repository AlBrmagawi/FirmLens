# FirmwareLens implementation status

## Milestones
1. Architecture, typed contracts, reproducible fixtures, isolated sandbox.
2. Shared extraction/analysis pipeline and CLI.
3. Syft/Grype, evidence, coverage-aware comparison.
4. PostgreSQL jobs, authenticated API, React workbench.
5. Evidence-grounded AI and report exports.
6. Adversarial tests, real demo, browser inspection, operational documentation.

## Current milestone
All six implementation milestones are delivered. The local firmware workflow, final container builds, browser workflow, export schemas, byte reproducibility and operational recovery checks are validated. Live provider verification remains an environment-dependent outstanding check: no key/model is configured, and adapter evaluations do not claim live-model behavior.

## Decisions
- Modular Python monolith; database-backed queue and separate trusted supervisor.
- Analysis only inside restricted Linux containers. No host-execution fallback.
- PostgreSQL in deployment; SQLite only in isolated persistence tests.
- Original inputs immutable, normalized redacted results separate from analyst triage.
- Cloud AI disabled until explicitly configured; no model downloads.

## Environment
- Empty Windows workspace; Node 24.18.0 and Docker CLI 29.6.2 present.
- Python runs in a development container. Docker Desktop is running.
- User moved Docker Desktop WSL storage to D:\Docker after a computer crash; engine and project files survived. Development container restarted.
- Specification preserved verbatim in PROJECT_SPEC.md.

## Completed and validated
- Authenticated API, durable jobs, sandbox, typed plugins, CLI, React views, triage, comparisons, reports and real provider adapters are implemented.
- 40 Python tests passed both in development and the network-disabled check image; Ruff, mypy, ESLint, Prettier and production frontend build passed. Three browser workflow/mobile/offline-documentation tests passed; nine-view Axe inspection reported zero violations.
- All seven synthetic formats passed actual extraction/inventory; missing intelligence correctly yielded partial coverage.
- Actual Grype update and matching: source-built lab 19 findings, revised 3; comparison 16 no longer detected, 3 persistent. Measured pipeline times 15.252 and 10.052 seconds.
- Pinned OpenWrt image analyzed with explicit partial coverage: 1,398 entries, 368 components, 161 ELF files. Nonfatal SquashFS handling was fixed and regression-tested.
- Actual CycloneDX/SARIF exports validated against official schemas. Dependency audits and Gitleaks found no known dependency vulnerabilities/leaks at the recorded time.
- Architecture, threat model, rules, support matrix, operations, API/CLI, case study, measured validation and screenshots are documented. GitHub workflow exists but has not run remotely.
- All 14 generated artifacts were byte-identical across two fresh builder runs and matched the prepared demo fixtures.
- Final deployed demo reproduced 19/3 findings in 11.743/10.609 seconds. Reports were written to the private named volume and copied to the host successfully.
- Actual restart preserved immutable results; SIGKILL interruption recovered on attempt 2; active cancellation removed its container; CLI severity threshold returned exit 3. The operational test helper was corrected to explicitly restart and verify the stopped supervisor.

## Remaining environment-dependent checks and next steps
- Configure either an existing Ollama model or explicit OpenAI cloud opt-in/key/model in `.env`, recreate the API, then evaluate real answers/citations with the questions in PROJECT_SPEC.md. See docs/OPERATIONS.md; neither provider has been exercised live here.
- Push the source to a chosen GitHub repository to run the provided hosted workflow. No remote repository has been created or publication performed.
- ARM64 host validation and destructive backup restoration remain unverified; see docs/VALIDATION.md. No provider or large model is installed automatically.
- A Docker API timeout occurred during concurrent image builds; the failed scan remains visible and the sequential rerun passed. Finish image preparation before analysis on a busy engine.
- The application is left running at http://localhost:8080. Retrieve the local sign-in credential with `docker compose exec api firmwarelens access-token`.
