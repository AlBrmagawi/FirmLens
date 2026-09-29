# Local operations

Use Linux with Docker Engine 26+ (volume subpaths), cgroup v2 and Docker Compose. On Windows use WSL2 plus Docker Desktop's Linux engine. The repository can also reside on Windows, as validated here; bind-mounted development environments are considerably slower than Linux volumes. Docker Desktop's disk image may reside on another drive, such as `D:\Docker`; the application uses named volumes and does not depend on that host path.

## Startup and offline operation

```sh
node scripts/setup.mjs
docker compose build
docker compose --profile tools build sandbox demo
docker compose up -d
docker compose exec api firmwarelens doctor --json
docker compose exec api firmwarelens access-token
```

Open http://localhost:8080 and sign in using the locally displayed token. Initial builds download base images, locked Python/npm dependencies, Debian packages, and checksummed Syft/Grype release binaries. Advisory updates and OpenWrt integration downloads are explicit. After preparing images, fixtures and optionally the database, the core demo requires no network and no paid AI service. Cloud AI is off by default; no local model is downloaded by FirmwareLens.

```sh
docker compose --profile tools run --rm demo
docker compose exec api python scripts/demo_workflow.py
docker compose cp api:/exports/. ./exports
```

Exports are written to the private `firmwarelens_exports` named volume; the copy command retrieves them into local `exports/`. Scan results live in PostgreSQL. The demo creates ordinary projects/uploads/jobs and never seeds analyzer results. Each scan records hashes, settings, rule/tool versions, database metadata, times and resource observations.

## Intelligence maintenance

Prepare a database before enabling advisory matching. Updates run in a dedicated maintenance container with network access, outside the offline analysis sandbox:

```sh
docker compose stop supervisor
docker compose --profile tools run --rm intelligence update
docker compose --profile tools run --rm intelligence status
docker compose start supervisor
```

Stop the supervisor for maintenance so database identity cannot change during a scan. An interrupted job returns to the queue and reruns against the new database. To import a previously prepared official Grype database, put the archive in `intelligence-import/` and run:

```sh
docker compose --profile tools run --rm intelligence-offline import /imports/database.tar.zst
```

The archive format must match the installed Grype database schema; retain its source, SHA-256 and date. `grype db import` validates its structure. Import is an operator-controlled intelligence operation, not an arbitrary firmware archive endpoint. Missing or stale intelligence is shown in coverage; advisory matches never establish exploitability.

## AI configuration

Set `FL_AI_PROVIDER=ollama` and `FL_AI_MODEL` to a model already installed on the configured Ollama server. Set `FL_OLLAMA_URL` when needed. No automatic pulls occur. For OpenAI set `FL_AI_PROVIDER=openai`, an available `FL_AI_MODEL`, `FL_OPENAI_API_KEY`, and explicit `FL_CLOUD_AI_ENABLED=true`. Then run `docker compose up -d --force-recreate api`. The UI discloses the bounded redacted evidence and question that will be sent. Model names stay configurable. No live provider has to be configured for the offline demo.

## Backups and restore

Back up PostgreSQL and the `firmwarelens_data` volume together after stopping API/supervisor writes. Include `.env` separately in an encrypted local backup and optionally preserve `firmwarelens_intelligence` to reproduce historical matches. Example on Linux/WSL:

```sh
mkdir -p backups
docker compose stop api supervisor
docker compose exec -T db pg_dump -U firmwarelens -d firmwarelens -Fc > backups/metadata.dump
docker run --rm --network none -v firmwarelens_data:/data:ro -v "$PWD/backups:/backup" alpine:3.22 tar -czf /backup/artifacts.tgz -C /data .
docker compose start api supervisor
```

Protect the backup: it contains original firmware and the local access credential. Restore into a fresh deployment with services stopped, matching application version, and the original `.env`. Restore the named-volume archive preserving ownership, then restore PostgreSQL with `pg_restore -U firmwarelens -d firmwarelens --clean --if-exists`. Start API/supervisor and run `doctor`. This is an operational recipe; destructive restore into an existing deployment is intentionally manual.

## Retention

Cancel active scans before deleting them or their project through the API/UI. Inputs shared with another project remain available. To preview old, unreferenced immutable artifacts:

```sh
docker compose exec api firmwarelens retention gc --days 30
docker compose exec api firmwarelens retention gc --days 30 --apply
```

Never use `docker compose down -v` unless you intend to delete all research metadata and artifacts. Normal `docker compose down` preserves volumes. Restart recovery relies on leases; allow 90 seconds after an abrupt shutdown.

## Troubleshooting

- **Doctor reports Docker unavailable:** start Docker Desktop/Linux engine. Never disable sandbox restrictions to get a scan running.
- **Sandbox self-test fails:** rebuild both images; check cgroup v2, seccomp and resource-limit support. The API may remain usable while analysis is unavailable.
- **Docker ReadTimeout during a scan:** finish heavy image builds and check Docker Desktop responsiveness, then submit a new scan. Failed attempts remain in history. Keep adequate engine memory and disk space; a busy runtime must not trigger unsafe host parsing.
- **Database update permission denied:** run `docker compose run --rm init`. Volume initialization creates an ownership marker to prevent empty-volume copy-up resetting permissions.
- **Database update temporary space exhausted:** the maintenance container reserves 512 MiB temporary space, independently of the analysis scratch limit. Large future database formats may need a reviewed increase.
- **Unsupported/partial image:** inspect stage diagnostics. Supply a supported filesystem/payload, decrypt externally only with authorization, or raise bounded scan settings if the artifact legitimately exceeds limits.
- **A large firmware has no components:** package-free firmware inventory can be incomplete. Check component-stage diagnostics; do not infer absence of third-party software.
- **UI CSRF error after changing address:** use exactly `FL_ORIGIN` (default `http://localhost:8080`), not a different hostname. Update both port and origin when changing the deployment port.
- **API/UI error details:** `docker compose logs --tail 100 api supervisor`; structured logs omit firmware text, secrets and request bodies.
- **PowerShell blocks npm.ps1:** use `npm.cmd` and `npx.cmd`; do not relax machine execution policy.
