# Contributing

Use authorized, redistributable, or synthetic inputs. Do not upload production secrets, proprietary firmware or live-device targets to issues. Read [architecture](docs/ARCHITECTURE.md), [rules](docs/RULES.md), and [threat model](docs/THREAT_MODEL.md) before changing analysis boundaries.

Python 3.12+, uv and Node 24 are used for development. Linux/WSL2 is recommended:

```sh
uv sync --frozen
uv run pytest -q
uv run ruff check src tests scripts demo
uv run ruff format --check src tests scripts demo
uv run mypy src
uv run python scripts/generate_types.py
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
