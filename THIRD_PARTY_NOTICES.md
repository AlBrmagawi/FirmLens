# Third-party notices

FirmwareLens original source is licensed under Apache-2.0. This does not relicense dependencies or firmware analyzed with it. Lockfiles identify exact resolved Python/npm dependencies. Runtime package provenance is available from Alpine package metadata and its source repositories; analyzer licenses and build manifests are retained under `/usr/local/share/firmwarelens/analyzers`.

| Component | Source and license |
| --- | --- |
| Syft | [Anchore Syft](https://github.com/anchore/syft), Apache-2.0; checksummed release source rebuilt with pinned Go 1.26.8 |
| Grype | [Anchore Grype](https://github.com/anchore/grype), Apache-2.0; checksummed release source rebuilt with pinned Go 1.26.8; advisory feeds retain source-specific terms |
| squashfs-tools | [Upstream](https://github.com/plougher/squashfs-tools), GPL-2.0; [Alpine packaging and corresponding source](https://gitlab.alpinelinux.org/alpine/aports/-/tree/3.23-stable/main/squashfs-tools) apply when redistributing containers |
| zlib | [Upstream](https://zlib.net/), zlib license; the [documented security backport](security/zlib/README.md) retains the upstream license and patch provenance |
| pyelftools | [Upstream](https://github.com/eliben/pyelftools), public domain / Unlicense |
| FastAPI, Pydantic, SQLAlchemy, Alembic, Typer, OpenAI Python SDK | Respective upstream packages, MIT |
| React, Vite, Tailwind CSS | Respective upstream packages, MIT |
| Lucide icons | [Lucide](https://lucide.dev/license), ISC; source includes icon artwork |
| Swagger UI | [Swagger UI](https://github.com/swagger-api/swagger-ui), Apache-2.0; LICENSE and NOTICE copied alongside locally bundled documentation assets |
| PostgreSQL | [PostgreSQL license](https://www.postgresql.org/about/licence/) |
| Python, Node.js, uv, Alpine and build tools | Respective upstream and per-package licenses; not covered by this project's license |

## Vendored validation schemas

`tests/schemas/provenance.json` records source URLs and SHA-256 values. Schema content is unmodified; it is used only for export validation.

- CycloneDX 1.7 and its referenced schemas come from the [CycloneDX specification](https://github.com/CycloneDX/specification). Its [Apache-2.0 license](tests/schemas/licenses/CycloneDX.txt) and embedded notices are retained. Referenced JSON Signature Format definitions retain their embedded WebPKI copyright and license notices.
- SARIF 2.1.0 comes from the [OASIS SARIF specification](https://github.com/oasis-tcs/sarif-spec). The repository's [license terms](tests/schemas/licenses/SARIF.md) are retained; OASIS policies and applicable specification terms govern it.

## Optional firmware and synthetic fixtures

OpenWrt firmware is downloaded only by the explicit integration recipe, verified by SHA-256, and excluded from Git. It contains multiple independently licensed components; consult [OpenWrt licensing](https://openwrt.org/license) and the release's corresponding sources before redistribution. This repository does not ship its firmware image.

The synthetic fixture's package metadata deliberately names BusyBox to exercise package inventory and real advisory matching. It does not distribute a BusyBox binary or assert that a corresponding vulnerable implementation is present. The separately compiled `lens-probe` program and nonfunctional credential material are project source fixtures.
