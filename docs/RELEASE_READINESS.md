# Release qualification — 2026-09-29

The updated release candidate is undergoing final integration and hosted CI checks. The earlier failed image audit is preserved in [RELEASE_AUDIT_INITIAL.md](RELEASE_AUDIT_INITIAL.md); it describes the previous Debian images.

The candidate uses Python 3.14.7, PostgreSQL 17.11, Alpine runtime images, squashfs-tools 4.7.4, Syft 1.52.0 and Grype 0.119.0 rebuilt with Go 1.26.8. Base images and analyzer source archives are pinned. All three runtime images build and test the upstream zlib security backport.

## Completed candidate checks

- 59 Python unit/API/CLI/provider-contract tests passed without warnings.
- Three image-policy tests passed, including rejection of missing evidence, changed packages, unexpected artifact locations and affected Docker server packages.
- Ruff lint/formatting, mypy across 17 modules, generated API types, ESLint, Prettier, TypeScript and the production frontend build passed.
- npm and pip audits found no known application dependency vulnerabilities; source and Git history passed Gitleaks.
- An isolated restore into the patched Alpine database matched all 11 public tables and 21 stored artifacts, including bytes, ownership and permissions.
- Live database migration passed with every public table unchanged, the original volume retained and application readiness verified.
- All three runtime image gates passed: zero critical matches and zero unresolved high/unknown matches. Raw high matches were app 1, sandbox 2, database 1; each received a verified backport or unaffected-code disposition. Raw medium/low counts were 8/1, 11/3 and 3/0 respectively.

The firmware, browser and recovery matrix is being repeated against the candidate. Hosted GitHub Actions must pass on the intended source revision before its distribution gate is recorded as passed. Previous runtime results remain historical evidence.

## Remediation and quality controls

Non-ASCII tokens and security headers now produce authentication/validation errors instead of server errors. Regression tests reproduced the original failure before the fix. The test client uses Starlette's supported dependency. Restore comparisons use explicit byte ordering so glibc/musl collation differences do not masquerade as changed rows.

The database migration uses a logical dump and a separate volume. It verifies table contents, retains the original volume, and checks application readiness before declaring success. See [operations](OPERATIONS.md).

The [image policy](QUALITY.md) blocks unresolved critical, high and unknown-severity findings. Every raw scanner match is retained. The zlib disposition requires the reviewed upstream patch, installed file hashes and an actual shared-library regression. The Docker advisory disposition requires evidence that affected daemon authorization code is absent from Grype's production package graph.

Medium and low package matches remain visible for review. FirmwareLens copies tar regular-file contents itself, rejects unsafe paths, omits links and accepts only Store/Deflate ZIP compression. Its firmware workflow does not use POP3, urllib password managers or BusyBox wget with firmware-controlled URLs. These boundaries reduce exposure; they do not certify every use of the runtime libraries.

## Repeating the checks

Follow [CONTRIBUTING.md](../CONTRIBUTING.md), prepare the demo and advisory database using [OPERATIONS.md](OPERATIONS.md), and run the workflow in `.github/workflows/ci.yml`. Run operational scripts sequentially because they restart services and interrupt test jobs. `node scripts/verify_openwrt.mjs` adds the pinned real-firmware exercise after preparing its sample.

Live OpenAI/Ollama inference remains unverified until a real provider is configured. No model is downloaded automatically. ARM64 hardware, production-scale load, exhaustive accessibility and independent penetration testing remain outside the measured support claims. Passing the documented gates does not establish absence of all bugs or vulnerabilities.
