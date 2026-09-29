# Release audit — 2026-09-29

**The functional checks pass, but the strict container security gate is blocked. This is not a 100% clean release verdict.** Live AI and hosted GitHub Actions also remain unverified. The source can be reviewed and published with these limitations disclosed; it should not be described as production-certified or vulnerability-free.

The audit started from local commit `813cddc`. Tests ran on the Windows/WSL2 x86-64 environment described in [the original validation record](VALIDATION.md). The updated runtime uses Python 3.12.14, PostgreSQL 17.11, Debian Trixie, squashfs-tools 4.6.1, Syft 1.52.0 and Grype 0.119.0. Runtime base images are pinned by digest.

## Checks and evidence

| Check | Result |
| --- | --- |
| Python unit, API, CLI and provider-contract tests | 56 passed on Python 3.12.14 |
| Unit coverage, including branches | 67% overall; API 89%. Separate Docker integration runs are not included in this percentage |
| Python lint, formatting and typing | Ruff passed; mypy passed for all 17 source modules |
| Frontend quality checks | Clean npm installation, ESLint, Prettier, TypeScript and production build passed |
| Browser workflows | 12 Playwright scenarios across Chromium, Firefox and WebKit; real uploads/analyses, reload-persistent triage, reports, disabled AI, keyboard dialogs and error recovery |
| Responsive layouts | Login at 320 px and overview at 320, 390 and 768 px; desktop workflows at 1440 px |
| Accessibility and visual review | Nine application views with zero Axe violations and zero page errors; no page-level overflow at 390 px. Refreshed overview, findings, comparison, dashboard and mobile screenshots were visually reviewed |
| Synthetic firmware | Lab: 19 findings; revised: 3; comparison: 16 no longer detected, 3 persistent |
| Format matrix | All seven formats passed; each retained the expected 12 static findings and one component |
| OpenWrt 23.05.5 sample | Partial coverage reported correctly: 1,398 entries, 368 components and 143 findings; all stages after extraction succeeded |
| Actual export formats | Both releases' CycloneDX 1.7 and SARIF 2.1.0 outputs passed official schema validation offline |
| Concurrent requests | Eight simultaneous uploads and eight idempotent submissions produced one scan with one attempt; 50 parallel reads passed; original download hash matched |
| Sandbox failure paths | Missing intelligence, entry budget, immediate cancellation and wall-time limit passed; all test containers removed |
| Fixture reproducibility | All 14 artifacts matched across two builds using the updated builder image |
| Restart, worker crash, cancellation and CLI | Immutable scan survived restart; forced crash recovered on attempt 2; active cancellation removed its container; real high-severity CLI run returned exit 3 |
| Backup and database upgrade | Final restore matched all 11 public tables and 20 artifacts, including bytes and ownership. Upgrade to PostgreSQL 17.11 preserved metadata; collation indexes were rebuilt before refreshing the recorded version |
| Dependency and secret audits | npm and pip audits reported no known application dependency vulnerabilities; Gitleaks found no secrets in source/history |
| Container security | **Failed critical gate:** database image retains one critical advisory match; other high-severity matches remain disclosed below |

These checks are a test matrix, not exhaustive proof of correctness, accessibility, security or firmware detection accuracy. The automated accessibility checks cover WCAG 2 A/AA and 2.1 AA rules supported by Axe. A Starlette test-client deprecation warning remains; it did not fail the locked test suite.

The checked-in [machine-readable audit](validation/release-audit.json) records the final test counts, coverage, runtime isolation probe, firmware results, recovery and restore checks. The [image audit](validation/release-image-audit.json) retains every high and critical package/advisory match and its source. Full local reports, traces and private backups remain under ignored `exports/` and `frontend/test-results/` paths. Unit coverage is 71% of statements and 53% of branches (67% combined); it is not 100% coverage. Integration timings recorded while other audits ran are observations, not controlled performance benchmarks.

## Fixes made during the audit

- Graceful worker shutdown now respects the retry budget. Analyst cancellation during shutdown records a terminal timestamp and the correct event status.
- Escape no longer hides an upload in progress. Closing a dialog restores keyboard focus to its opener.
- Default labels derived from long filenames are bounded in both the UI and CLI.
- The Python/Debian runtime and PostgreSQL image were updated after the image audit exposed outdated system packages. The application image's critical match count fell from 16 to zero, and its high match count from 124 to 50.
- Regression coverage now includes suppression expiry, triage isolation and redaction, immutable results, AI error/budget handling, revoked sessions, CLI exit contracts, and tar hard-link/symbolic-link chains.
- The restore harness waits for the final PostgreSQL TCP listener and an actual query; `pg_isready` alone could succeed during initial temporary-server startup.

## Remaining container advisories

These are package/advisory matches, not proven reachable vulnerabilities in FirmwareLens. Counts include multiple packages matching the same advisory. No findings were suppressed to obtain a passing result.

| Runtime image | Critical matches | High matches |
| --- | ---: | ---: |
| Application / supervisor | 0 | 50 |
| Analysis sandbox | 0 | 65 |
| PostgreSQL | 1 | 73 |

The critical database match is **CVE-2026-6653** in `libxml2` `2.12.7+dfsg+really2.9.14-2.1+deb13u3`. Debian marks that Trixie version affected and describes the issue as minor, with no stable security update currently scheduled. The issue concerns XML entity parsing; FirmwareLens uses parameterized SQL and does not expose arbitrary SQL or XML database operations. Those application boundaries are relevant, but do not constitute a complete reachability assessment. See the [Debian advisory record](https://security-tracker.debian.org/tracker/CVE-2026-6653).

Other matches include unpatched distribution packages and Go standard-library advisories in the current official Syft/Grype binaries. The official release APIs were checked: [Syft 1.52.0](https://github.com/anchore/syft/releases/tag/v1.52.0) and [Grype 0.119.0](https://github.com/anchore/grype/releases/tag/v0.119.0) were still the latest releases at audit time. Retain the findings for review and update/retest when patched upstream artifacts become available; switching off the scanner or its critical gate is not remediation.

Python's [CVE-2026-82049 advisory](https://mail.python.org/archives/list/security-announce%40python.org/message/EFJWGAZJA56AKSBR2WHMHQZO7RRLZPRH/) concerns tar extraction filters following hard-link/symbolic-link chains. FirmwareLens copies regular-file contents manually and records links without materializing them. A dedicated regression verifies that the external file's bytes, mode and timestamp remain unchanged and that `TarFile.extract`/`extractall` are never called. The package match remains visible in the image report.

`node scripts/verify_images.mjs` scans application, sandbox and database images against the prepared local database, retains all matches, and fails on any critical match. The GitHub workflow runs this gate after functional checks so the remaining security failure does not prevent collection of their results. **A green hosted release gate is not currently expected until the critical match is resolved or a separately reviewed, evidence-backed disposition is established.**

## Repeating the release checks

Follow [CONTRIBUTING.md](../CONTRIBUTING.md) for unit, lint, type and browser checks. Generate the demo and prepare Grype intelligence using [OPERATIONS.md](OPERATIONS.md), then run:

```sh
docker compose exec -T api python scripts/demo_workflow.py
docker compose exec -T api python scripts/verify_variants.py
docker compose cp api:/exports/. ./exports
node scripts/verify_reproducibility.mjs
node scripts/verify_concurrency.mjs
node scripts/verify_sandbox_boundaries.mjs
node scripts/verify_operations.mjs
node scripts/verify_restore.mjs
node scripts/verify_images.mjs
```

Run operational scripts sequentially: they restart services, interrupt a test worker and create ordinary test projects. The restore check uses separate labelled containers/volumes, checks ownership before cleanup, and never replaces live data. `FL_RESTORE_IMAGE` optionally selects a target PostgreSQL image for a restore compatibility exercise. Run `node scripts/verify_openwrt.mjs` after preparing the pinned sample with `scripts/openwrt_integration.py` and a local advisory database.

Still unverified: live OpenAI/Ollama inference and real-model prompt-injection resistance, hosted GitHub Actions, ARM64 host execution, production-scale load, exhaustive accessibility and independent penetration testing. No provider key or large model was installed, and nothing was published to GitHub.
