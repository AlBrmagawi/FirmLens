# Contributing

Use authorized, redistributable, or synthetic inputs. Do not upload production secrets, proprietary firmware or live-device targets to issues. Read [architecture](docs/ARCHITECTURE.md), [rules](docs/RULES.md), and [threat model](docs/THREAT_MODEL.md) before changing analysis boundaries.

## Choose a contribution

Documentation improvements, accessibility fixes, parser coverage and minimal synthetic regression fixtures are welcome. Check [existing issues](https://github.com/AlBrmagawi/FirmLens/issues) before opening a [bug report or feature proposal](https://github.com/AlBrmagawi/FirmLens/issues/new/choose). For a large change, describe the research problem and proposed behavior in an issue before implementing it. Small, focused fixes can go directly to a pull request.

Follow the [code of conduct](CODE_OF_CONDUCT.md). Report vulnerabilities through the private channel in [SECURITY.md](SECURITY.md); use [SUPPORT.md](SUPPORT.md) for setup and usage questions.

## Set up and validate

Fork the repository, clone your fork and create a branch from `main`. Follow the [quickstart](README.md#quickstart) and build the [demo fixtures](README.md#run-the-source-built-demo) when working on the application or analysis pipeline.

Python 3.14, uv and Node 24 are used for release validation. The source declares Python 3.12+ compatibility; the shipped containers and hosted checks use 3.14. Linux/WSL2 is recommended:

```sh
uv sync --frozen
uv run pytest -q
uv run ruff check src tests scripts demo
uv run ruff format --check src tests scripts demo
uv run mypy src
uv run python scripts/generate_types.py
node --test tests/test_image_policy.mjs
cd frontend
npm ci
npx playwright install chromium firefox webkit
npm run lint
npx prettier --check .
npm run build
npm run test:e2e
```

Browser tests require the running Compose application and generated demo images. They retrieve the local token through `docker compose exec` without logging it, create genuine scans, and check UI evidence, triage, comparison, exports, disabled AI, mobile layout and accessibility. On Windows use `npm.cmd` / `npx.cmd` if PowerShell script execution is restricted.

The alternative container check runner is `docker build -f Dockerfile.sandbox --target checks -t firmwarelens-checks .` followed by `docker run --rm firmwarelens-checks pytest -q`. Analysis of untrusted inputs always belongs in the real sandbox; unit tests only use locally generated trusted fixtures.

Changes to rules need stable IDs/versioning, evidence, limitations and meaningful tests. Changing the schema requires regenerated frontend types and a migration when persistence changes. Never duplicate analysis logic in the UI or CLI. Use lockfiles, keep fake providers/advisories under tests only, and distinguish a test passing from an unrun hosted workflow. PRs should explain the trigger, behavior, security boundary and validation.

## Submit a pull request

Keep changes focused and explain the user-visible result. Link the relevant issue, describe the checks you ran and disclose anything you could not validate. Include a synthetic reproducer for behavior fixes and before/after screenshots for visible UI changes. Documentation-only changes need accurate examples and working links; they do not need new implementation tests.

Review the diff before pushing: generated research outputs, credentials, firmware and databases belong outside Git. Open a pull request against `main` and use the provided template. The hosted workflow runs source checks and full container integration; maintainers review the evidence before merging. See [quality policy](docs/QUALITY.md) for the release gates.
