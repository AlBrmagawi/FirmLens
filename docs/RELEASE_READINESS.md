# Release qualification — 2026-09-29

**All documented local and hosted release gates pass for the supported local research workflow.** Live AI remains unverified until a real provider is configured. This is not a claim of zero bugs, universal firmware support or production certification.

Tested implementation: `c07fa9afc3887a92365e32159074cddd6c2a24af`. The [GitHub run](https://github.com/AlBrmagawi/FirmLens/actions/runs/36596449346), [machine-readable QA record](validation/release-qa.json) and [runtime image evidence](validation/release-images-qa.json) identify the actual checks and artifacts. Documentation updates report those measurements. The [initial failed audit](RELEASE_AUDIT_INITIAL.md) remains available as history.

## Verified checks

| Area | Result |
| --- | --- |
| Python unit, API, CLI and provider contracts | 62 passed; zero failures, errors or skips; Python 3.14.7 |
| Image-policy regression tests | 3 passed, including missing/tampered evidence, changed packages, unexpected artifact locations and affected server packages |
| Source quality | Ruff lint/format, mypy for 17 modules, generated API types, ESLint, Prettier, TypeScript and production UI build passed |
| Browsers and UX | 12 scenarios passed across Chromium, Firefox and WebKit, with zero retries/flaky results; upload, analysis, evidence, persistent triage, comparison, exports, keyboard dialogs and upload-error recovery |
| Accessibility and responsive layout | Nine views with zero Axe violations and page errors; tested widths 320, 390, 768 and 1440 px; screenshots visually reviewed; wide tables scroll within their containers |
| Firmware matrix | All seven input formats passed real extraction/inventory; 12 static findings and one component per lab input |
| ZIP boundaries | Real Store/Deflate tar bundles analyzed successfully; real BZIP2, LZMA and Zstandard members returned an actionable unsupported result |
| Prepared advisory matching | Actual Syft/Grype scans: lab 19 findings, revised 3; comparison 16 no longer detected and 3 persistent |
| Real OpenWrt sample | Explicit partial coverage: 1,398 entries, 368 components, 143 findings; all stages after extraction succeeded |
| Export schemas | Both releases' CycloneDX 1.7 and SARIF 2.1.0 exports passed official schema validation offline |
| Reproducibility | All 14 artifacts matched across two fresh builder runs and matched the prepared demo files |
| Concurrency | Eight uploads and eight idempotent submissions produced one scan/one attempt; 50 parallel reads passed; original-download hash matched |
| Sandbox failures | Missing intelligence, file budget, cancellation and wall-time limits produced the expected outcomes; all test containers removed |
| Recovery | Immutable results survived restart; forced worker crash recovered on attempt 2; active cancellation removed its container; severity-threshold CLI exit was 3 |
| Backup and migration | Isolated restore matched all 11 public tables and 36 stored artifacts, including bytes/ownership/permissions; Debian-to-Alpine logical migration preserved every table and retained the original volume |
| Dependency and secret audits | npm/pip audits found no known application dependency vulnerabilities; Gitleaks found no source/history secrets; private outputs and dependencies are absent from tracked files |
| Runtime image policy | Passed for application, sandbox and database: zero critical matches and zero unresolved high/unknown matches |
| Hosted GitHub Actions | Both source-quality and full container-integration jobs passed on Ubuntu 24.04 for the tested implementation revision |

Unit coverage is **66.65% combined line/branch coverage** (70.41% statements, 53.95% branches). Separate container integration processes are not instrumented in this percentage. Accessibility automation covers the Axe rules exercised, not exhaustive accessibility. Recorded timings are observations from local runs, not controlled performance benchmarks.

## Fixes and runtime provenance

The release uses pinned Alpine runtime bases, Python 3.14.7 and PostgreSQL 17.11. Syft 1.52.0 and Grype 0.119.0 are rebuilt from checksummed upstream archives with Go 1.26.8. SquashFS tools are 4.7.4. The local host used Docker Engine 29.6.2 on Windows/WSL2 x86-64.

- Non-ASCII login tokens, bearer/CSRF headers and upload digests now return authentication/validation errors instead of server errors. Regression tests failed before the fix and pass afterward.
- ZIP members outside Store/Deflate are rejected before opening a decompressor. Unit regressions and actual encoded-archive integrations verify the boundary.
- The upstream zlib fix is compiled into each runtime. Build checks include a failing unpatched negative control, upstream tests and passing patched tests. The image gate reruns the installed shared-library regression and verifies the recorded source/file hashes.
- Database migration restores into a new volume, verifies rows before cutover, checks readiness and retains the original volume. Restore digests use explicit byte ordering across glibc/musl; startup checks wait for a real query on the final TCP listener.
- Image audits return JSON on stdout for the host process to write. This fixes the Linux report-directory ownership failure found by GitHub CI and removes the scanner's writable host mount.
- Earlier worker shutdown/retry, cancellation timestamp, dialog focus/Escape and long-filename fixes remain covered.

## Retained advisory matches

These are raw package/advisory counts. The gate does not delete scanner findings.

| Runtime | Critical | High | Medium | Low | Unresolved high/critical/unknown |
| --- | ---: | ---: | ---: | ---: | ---: |
| Application / supervisor | 0 | 1 | 8 | 1 | 0 |
| Analysis sandbox | 0 | 2 | 11 | 3 | 0 |
| PostgreSQL | 0 | 1 | 3 | 0 | 0 |

CVE-2026-85091 is recorded as `fixed_by_backport` only after verifying the specific [upstream patch and regression evidence](../security/zlib/README.md). GO-2026-4887 concerns [Docker daemon authorization middleware](https://github.com/moby/moby/security/advisories/GHSA-x744-4wpc-v9h2); Grype's recorded production package graph excludes the affected server/authorization packages. Its disposition is scoped to that binary, module version and compiler. Operators must patch their host Docker Engine separately.

Medium/low matches remain disclosed in the image evidence and full scanner reports. FirmwareLens copies tar regular-file contents itself, rejects unsafe paths, omits links and now explicitly restricts ZIP codecs. The firmware workflow does not use POP3, urllib password managers or BusyBox wget with firmware-controlled URLs. These boundaries reduce exposure; they do not certify every possible use of the runtime libraries. Review all matches when changing dependencies or intelligence.

## Scope and reproduction

Follow [CONTRIBUTING.md](../CONTRIBUTING.md), prepare fixtures and intelligence using [OPERATIONS.md](OPERATIONS.md), and run the workflow in `.github/workflows/ci.yml`. [QUALITY.md](QUALITY.md) defines the gates. Run operational scripts sequentially because they restart services and interrupt test jobs. `node scripts/verify_openwrt.mjs` adds the pinned real-firmware exercise after preparing its sample.

Live OpenAI/Ollama inference and real-model prompt-injection resistance remain unverified: no provider/model is configured, cloud AI is disabled, and no model was downloaded automatically. Adapter tests use test doubles. ARM64 hardware, production-scale load and independent penetration testing remain outside the measured support claims.

Full local reports and private backups remain under ignored `exports/`; browser artifacts remain under ignored frontend report directories. No credentials, firmware, advisory database, database dump or installed dependency tree is committed.
