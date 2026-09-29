# API and CLI

Interactive OpenAPI documentation: `http://localhost:8080/api/docs`. Schema: `/api/openapi.json`. Application endpoints are under `/api/v1`. Health and readiness are `/health` and `/ready`. Errors have an `error` object with a code and understandable message; validation errors omit rejected input values. Every response has a request identifier.

Authenticate a script using `Authorization: Bearer <local access token>`. The browser exchanges that credential for a 12-hour HttpOnly, SameSite=Strict session and receives a CSRF value. Cookie-authenticated mutations require both `X-CSRF-Token` and exact `Origin`. CORS is not enabled. Credentials never belong in URLs.

| Workflow | Routes |
|---|---|
| Projects | GET/POST `/projects`, DELETE `/projects/{project}` |
| Firmware | POST/GET `/projects/{project}/artifacts`, GET `.../artifacts/{sha256}/download` |
| Jobs | POST/GET `.../scans`, GET/DELETE `.../scans/{scan}`, POST `.../scans/{scan}/cancel`, GET `.../events?after=0` |
| Findings | GET `.../findings?q=&severity=&status=&sort=priority&offset=0&limit=50`, GET/PATCH `.../findings/{id}` |
| Components/evidence | GET `.../components`, GET `.../evidence/{id}` |
| Files | GET `.../files?q=etc/&offset=0&limit=50`, GET `.../file?path=etc/ssh/sshd_config` |
| Comparison | GET `/projects/{project}/compare?before={scan}&after={scan}`, GET `.../compare/export?...&format=html` |
| Reports | GET `.../scans/{scan}/report?format=html` (also json, markdown, sbom, sarif) |
| Assistant | POST `.../scans/{scan}/assistant`, GET `.../conversations` |
| Diagnostics | GET `/settings` |

Uploads use a raw streaming request body, `Content-Type: application/octet-stream`, and optional `X-Filename` and `X-Content-SHA256`. They are capped while streaming, including chunked bodies. The hash identifies bytes; signatures are inspected inside the sandbox. POST a scan with `{ "artifact_id": "sha256", "label": "release name", "options": { "components": true, "vulnerabilities": true } }`. An optional `Idempotency-Key` header makes scan creation safe to retry without losing the ability to deliberately create a separate scan.

Finding triage PATCH accepts `status`, `note`, `suppress`, `reason`, `expires_at` (timezone required). States: open, acknowledged, false-positive, accepted-risk, resolved. Suppression scope is project + fingerprint. Severity and confidence are immutable analyzer observations; triage remains separate.

## CLI examples

Use `docker compose exec api firmwarelens ...` for an already configured client. For a local Python environment run `uv sync --frozen`, then `uv run firmwarelens ...` with `FL_API_URL`, `FL_TOKEN` or `FL_TOKEN_FILE` configured. All ordinary CLI analysis goes through the same API/supervisor; there is no host parser fallback.

```sh
firmwarelens doctor --json
firmwarelens project create "Router study" --description "Authorized release comparison" --json
firmwarelens project list
firmwarelens scan release.squashfs --project PROJECT_ID --label "1.0" --allow-partial --json
firmwarelens scans list PROJECT_ID --json
firmwarelens findings PROJECT_ID SCAN_ID --severity high --json
firmwarelens scans cancel PROJECT_ID SCAN_ID
firmwarelens compare PROJECT_ID OLD_SCAN_ID NEW_SCAN_ID
firmwarelens compare PROJECT_ID OLD_SCAN_ID NEW_SCAN_ID --output comparison.html --format html
firmwarelens report PROJECT_ID SCAN_ID report.html --format html
firmwarelens report PROJECT_ID SCAN_ID sbom.json --format sbom
```

Machine-readable output is JSON (the `--json` option documents this explicitly). Exit codes: **0** successful operation, **2** failed/unsupported/cancelled scan or API error, **3** findings exceed `--fail-on` severity, **4** partial coverage unless explicitly accepted with `--allow-partial`, **5** unavailable dependencies/configuration. Usage errors also use Typer's conventional code 2. `--no-wait` submits a job without waiting. `--idempotency-key` can be reused after a connection interruption. A severity-threshold failure is distinct from a pipeline failure; partial coverage remains visible in JSON even if allowed.

Intelligence commands (`update`, `import`, `status`) run inside the dedicated maintenance container; see [operations](OPERATIONS.md). `retention gc` is a local administrative command with dry-run behavior by default.
