# Validation record

This is the original implementation validation, preserved as history. See the subsequent [release audit](RELEASE_READINESS.md) for the current runtime, expanded tests and release gate results.

Validation date: 2026-09-29. This record describes local runs, not a hosted CI result. Machine-readable measured results are retained in [measured-results.json](validation/measured-results.json). Full generated reports and raw firmware remain excluded from Git.

## Environment

- Windows host, Intel Core i5-9400F at 2.90 GHz, 6 cores/6 logical processors.
- Docker Desktop 4.83.0, Linux engine 29.6.2, WSL2 kernel `6.18.33.2-microsoft-standard-WSL2`, x86-64. Engine exposes 6 CPUs and 8,290,160,640 bytes RAM (7.72 GiB).
- Docker Desktop data was moved by the operator to `D:\Docker`; application volumes and metadata survived the interruption. Project source is on an NTFS workspace.
- Python 3.12.12, pyelftools 0.33, Syft 1.52.0, Grype 0.119.0, squashfs-tools 4.5.1, Node 24.18.0. Python and frontend lockfiles record all resolved dependencies.
- Per analysis container: one CPU, 1,536 MiB memory with no additional swap, 64 processes, 768 MiB work tmpfs, 16 MiB temporary tmpfs, no network, non-root UID 65532, read-only root, dropped capabilities and no-new-privileges. Default job wall limit 600 s; tool/stage deadline 90 s.

## Actual checks

| Check | Local outcome |
| --- | --- |
| Python unit/API/provider tests | 40 tests passed; covers hostile archives, metadata, ELF architectures, redaction, output validation, scope/authentication, idempotency, cancellation, leases, reports, provider boundaries, tool crashes/timeouts and context limits |
| Ruff lint and formatting | Passed |
| mypy | Passed for 17 source modules |
| ESLint, Prettier, TypeScript/Vite production build | Passed |
| Playwright main workflow, mobile layout and offline API documentation | 3 passed in 49.2 s; real uploads/jobs, evidence, triage, comparison, report download, mobile sign-out and local Swagger assets |
| Axe WCAG 2 A/AA and 2.1 AA automation | Zero reported violations across nine inspected views; 390 px document fits 390 px viewport |
| Browser visual inspection | Actual overview, finding/evidence and mobile screenshots inspected; contrast and mobile overflow defects corrected |
| Syft/Grype and isolation doctor | Real restricted self-test passed; missing-tool and isolation failures do not fall back to host parsing |
| Input variants | All seven synthetic formats passed the real API/queue/sandbox workflow |
| Missing intelligence | Observed partial scans with explicit vulnerability-stage failure; static findings retained |
| Prepared intelligence | Real database update and Grype scans passed |
| Export schemas | Both actual CycloneDX 1.7 and SARIF 2.1.0 reports for both releases validated against official schemas |
| Dependencies | `pip-audit` found no known dependency vulnerabilities; local project is not a PyPI advisory target. `npm audit` found zero vulnerabilities at validation time |
| Secret scan | Gitleaks 8.30.1 scanned source with redacted output: no leaks found. Generated local artifacts and dependencies are excluded |
| Fixture reproducibility | Two fresh builds using the same recorded builder image produced identical SHA-256 values for all 14 artifacts, also matching the prepared demo fixtures; see [reproducibility.json](validation/reproducibility.json) |
| Restart, interruption, cancellation and CLI | Passed: persisted result unchanged after restart; forcibly interrupted job completed on attempt 2 after lease recovery; active cancellation removed its container; actual high-severity CLI threshold returned exit 3. See [operations.json](validation/operations.json) |
| Hosted GitHub Actions | Workflow provided; not run on GitHub |

Automated accessibility checks do not establish exhaustive accessibility. Provider tests use test doubles; no canned answer is used by the production assistant. Starlette emitted a deprecation warning for its httpx-based test client; tests passed with the locked supported dependency set.

Fixture reproducibility is established for the recorded builder image and architecture. Debian build-time packages are not pinned to a dated package-mirror snapshot; retain the builder image when reproducing the exact recorded bytes after future toolchain updates.

## Measured synthetic firmware

These are individual observed runs, not an average, throughput benchmark or accuracy evaluation. Duration covers the analysis process, excluding upload, queueing and container startup. RSS is `getrusage`: the Python process peak and the largest child-process peak, **not** aggregate container peak memory.

| Measurement | Lab | Revised |
| --- | ---: | ---: |
| Outcome with prepared database | complete | complete |
| Filesystem entries | 18 | 17 |
| Syft components | 1 | 1 |
| Static configuration/permission/ELF findings | 12 | 0 |
| Advisory matches | 7 | 3 |
| Total findings | 19 | 3 |
| Pipeline time | 15,252 ms | 10,052 ms |
| Python peak RSS | 39,172 KiB | 39,204 KiB |
| Largest child peak RSS | 175,992 KiB | 187,528 KiB |

Comparison: 0 new, 3 persistent, 16 no longer detected, 0 unknown due to coverage. Synthetic package metadata changes BusyBox's Alpine version; these advisory matches do not imply that the fixture contains an exploitable BusyBox binary.

A final deployment rerun reproduced the same complete outcomes and finding counts, with pipeline times of 11,743 ms and 10,609 ms; see [final-demo-run.json](validation/final-demo-run.json). Reports were successfully written to the private named volume, copied to the host and validated again in a network-disabled check container. A scan submitted during concurrent container builds had earlier failed with a Docker `ReadTimeout`; it was retained as a failed attempt, and the sequential rerun passed. Complete image preparation before running analyses on a busy local engine.

Database: Grype v6.1.9, built `2026-09-29T06:32:31Z`, database-file SHA-256 `89d80b3df8f320b4e828fa708ce729f297ee95b601521e33753794d8e4255497`. Source and complete status are recorded in the scan manifest. Expected advisory counts can change when intelligence changes; deterministic static expectations live in `demo/expected.json`.

Variant checks disabled advisory matching to isolate extraction/inventory. Each identified one component and the same 12 static findings: tar 1,264 ms; gzip tar 1,254 ms; SquashFS gzip 1,375 ms, xz 1,337 ms, zstd 1,381 ms; embedded SquashFS at offset 4096: 1,346 ms; ZIP payload: 1,383 ms. These scans correctly reported partial overall coverage because the vulnerability stage was explicitly skipped.

## OpenWrt integration: tested with partial extraction

The integration helper downloads the official OpenWrt 23.05.5 x86/64 generic SquashFS root filesystem, validates compressed SHA-256 `478601ab0f5176372e6e0079614240dd25049c74167572ca9bc1b91e9261fe17`, and performs bounded decompression. The 109,051,904-byte raw image has SHA-256 `c27bb3ab1f955b46940b9752a546bede813c9324b73be004202027091065a806`.

Official [release directory and checksums](https://downloads.openwrt.org/releases/23.05.5/targets/x86/64/) provide provenance. The helper pins an older research sample; it is not a recommendation to install that release on a device.

```sh
uv run python scripts/openwrt_integration.py
docker compose exec api firmwarelens project create "OpenWrt integration" --json
docker compose exec api firmwarelens scan /demo/openwrt-23.05.5-rootfs.squashfs --project PROJECT_ID --allow-partial --json
```

Observed: **partial**, 1,398 filesystem entries, 368 components, 161 ELF files inspected, 143 findings (1 critical, 10 high, 36 medium, 96 low). Inventory, configuration, ELF, components and vulnerability stages succeeded. Extraction remained partial because unsquashfs reported nonfatal errors and links/special-file contents were intentionally omitted. This sample exposed an exit-code handling defect; the fix retains safe files on documented nonfatal exit 2 and keeps fatal exit 1 as an error, with regression tests.

Pipeline duration: 13,715 ms; Python peak RSS: 150,188 KiB; largest child peak RSS: 195,444 KiB. Finding counts are analyzer observations requiring review, not confirmed OpenWrt vulnerabilities. Raw image and reports are local only.

## Reproducing checks

See [CONTRIBUTING.md](../CONTRIBUTING.md) for unit/lint/type/browser commands. With the app and fixtures prepared:

```sh
docker compose exec api python scripts/demo_workflow.py
docker compose exec api python scripts/verify_variants.py
docker compose cp api:/exports/. ./exports
uv run python scripts/validate_exports.py
node scripts/verify_operations.mjs
node scripts/verify_reproducibility.mjs
```

The operations script verifies persistence across restart, forcibly interrupts an active supervisor job, waits for its expired lease and bounded retry, cancels a running job, checks container cleanup, and verifies CLI threshold exit 3. It creates additional ordinary scan records. `frontend/scripts/inspect.mjs` regenerates screenshots and an accessibility audit from the demo results.

## Unverified behavior

Live OpenAI and Ollama inference, provider-specific model quality, real-model prompt-injection resistance, ARM64 host/container execution, full ARM/MIPS/AArch64 vendor firmware, alternative SquashFS compressors, destructive backup restoration, and production-scale concurrency have not been validated here. No credentials or large local model were installed to simulate those checks. The implementation fails clearly when no provider is configured. Hosted CI and a GitHub publication remain unrun.
