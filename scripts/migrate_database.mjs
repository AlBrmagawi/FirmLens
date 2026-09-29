// Restore into a new volume, verify every row, then switch Compose. Keep the old volume.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdirSync, unlinkSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const docker = process.platform === "win32" ? "docker.exe" : "docker";
const run = (args, options = {}) =>
  execFileSync(docker, args, {
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
    maxBuffer: 128 * 1024 * 1024,
    ...options,
  });
const sql = (prefix, query) =>
  run([
    ...prefix,
    "psql",
    "-v",
    "ON_ERROR_STOP=1",
    "-U",
    "firmwarelens",
    "-d",
    "firmwarelens",
    "-At",
    "-c",
    query,
  ]).trim();
async function waitDatabase(prefix) {
  for (let attempt = 0; attempt < 180; attempt++) {
    try {
      if (sql(prefix, "SELECT 1") === "1") return;
    } catch {
      /* startup */
    }
    await delay(1000);
  }
  throw new Error("Database did not become ready");
}
function digest(prefix) {
  const tables = sql(
    prefix,
    "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename",
  )
    .split("\n")
    .filter(Boolean);
  return Object.fromEntries(
    tables.map((table) => {
      assert.match(table, /^[a-z_]+$/);
      return [
        table,
        sql(
          prefix,
          `SELECT count(*),md5(coalesce(string_agg(row_to_json(t)::text,'' ORDER BY row_to_json(t)::text COLLATE "C"),'')) FROM "${table}" t`,
        ),
      ];
    }),
  );
}
async function main() {
  const config = JSON.parse(run(["compose", "config", "--format", "json"]));
  const targetVolume = config.volumes.postgres.name;
  const targetImage = config.services.db.image;
  const port = config.services.api.ports.find(
    (entry) => entry.target === 8080,
  )?.published;
  assert(port, "Expected a published API port");
  const readinessUrl = `http://127.0.0.1:${port}/ready`;
  const current = run(["compose", "ps", "-q", "db"]).trim();
  assert(current, "Start the existing database before migration");
  const oldImage = run([
    "inspect",
    "--format",
    "{{.Config.Image}}",
    current,
  ]).trim();
  const mounts = JSON.parse(
    run(["inspect", "--format", "{{json .Mounts}}", current]),
  );
  const oldVolume = mounts.find(
    (mount) => mount.Destination === "/var/lib/postgresql/data",
  )?.Name;
  assert(oldVolume, "Expected an existing named PostgreSQL data volume");
  if (oldVolume === targetVolume) {
    assert.equal(
      oldImage,
      targetImage,
      "In-place database image changes require a separate migration assessment",
    );
    console.log(
      "Database already uses the configured release image and volume.",
    );
    return;
  }
  const known = run(["volume", "ls", "--format", "{{.Name}}"])
    .trim()
    .split(/\s+/);
  assert(
    !known.includes(targetVolume),
    "Target volume already exists; do not overwrite it. Inspect the previous migration first.",
  );
  const id = randomUUID();
  const container = `firmwarelens-migration-${id}`;
  const prefix = ["exec", container];
  const source = ["compose", "exec", "-T", "db"];
  mkdirSync("exports/backups", { recursive: true });
  const backup = `exports/backups/before-alpine-${id}.dump`;
  const environment = resolve(`exports/backups/migration-${id}.env`);
  const rollback = resolve(`exports/backups/rollback-${id}.json`);
  writeFileSync(
    rollback,
    JSON.stringify(
      {
        services: { db: { image: oldImage } },
        volumes: { postgres: { name: oldVolume } },
      },
      null,
      2,
    ),
  );
  writeFileSync(
    environment,
    `POSTGRES_USER=firmwarelens\nPOSTGRES_DB=firmwarelens\nPOSTGRES_PASSWORD=${config.services.db.environment.POSTGRES_PASSWORD}\n`,
    { mode: 0o600 },
  );
  let created = false;
  let switched = false;
  let complete = false;
  try {
    run(["compose", "stop", "api", "supervisor"]);
    const before = digest(source);
    const dump = run(
      [...source, "pg_dump", "-U", "firmwarelens", "-d", "firmwarelens", "-Fc"],
      { encoding: null },
    );
    writeFileSync(backup, dump, { mode: 0o600 });
    run([
      "volume",
      "create",
      "--label",
      `firmwarelens.migration=${id}`,
      "--label",
      "com.docker.compose.project=firmwarelens",
      "--label",
      "com.docker.compose.volume=postgres",
      targetVolume,
    ]);
    run([
      "run",
      "-d",
      "--name",
      container,
      "--label",
      `firmwarelens.migration=${id}`,
      "--network",
      "none",
      "--env-file",
      environment,
      "--mount",
      `type=volume,source=${targetVolume},target=/var/lib/postgresql/data`,
      targetImage,
    ]);
    created = true;
    // The final TCP listener starts after entrypoint initialization has finished.
    for (let attempt = 0; attempt < 180; attempt++) {
      try {
        run([
          ...prefix,
          "psql",
          "-h",
          "127.0.0.1",
          "-U",
          "firmwarelens",
          "-d",
          "firmwarelens",
          "-At",
          "-c",
          "SELECT 1",
        ]);
        break;
      } catch {
        if (attempt === 179)
          throw new Error("Migration target did not initialize");
      }
      await delay(1000);
    }
    run(
      [
        "exec",
        "-i",
        container,
        "pg_restore",
        "-U",
        "firmwarelens",
        "-d",
        "firmwarelens",
        "--exit-on-error",
      ],
      { input: dump },
    );
    assert.deepEqual(
      digest(prefix),
      before,
      "Restored database differs from source",
    );
    run(["stop", container]);
    const owner = run([
      "inspect",
      "--format",
      '{{index .Config.Labels "firmwarelens.migration"}}',
      container,
    ]).trim();
    assert.equal(owner, id);
    run(["rm", container]);
    created = false;
    switched = true;
    run(["compose", "up", "-d", "--no-build", "--no-deps", "db"]);
    await waitDatabase(source);
    assert.deepEqual(digest(source), before, "Database changed during cutover");
    run(["compose", "up", "-d", "--no-build", "api", "supervisor"]);
    for (let attempt = 0; attempt < 90; attempt++) {
      try {
        if ((await fetch(readinessUrl)).ok) {
          complete = true;
          break;
        }
      } catch {
        /* startup */
      }
      await delay(1000);
    }
    assert(complete, "Application readiness failed after cutover");
    const result = {
      old_image: oldImage,
      new_image: targetImage,
      old_volume_retained: oldVolume,
      new_volume: targetVolume,
      metadata_unchanged: true,
      table_count: Object.keys(before).length,
      logical_restore: true,
      application_ready: true,
    };
    writeFileSync(
      "exports/database-migration-validation.json",
      JSON.stringify(result, null, 2),
    );
    console.log(JSON.stringify(result, null, 2));
  } finally {
    unlinkSync(environment);
    if (created) {
      const owner = run([
        "inspect",
        "--format",
        '{{index .Config.Labels "firmwarelens.migration"}}',
        container,
      ]).trim();
      assert.equal(owner, id);
      run(["rm", "-f", container]);
    }
    if (!complete) {
      if (switched)
        run([
          "compose",
          "-f",
          "compose.yaml",
          "-f",
          rollback,
          "up",
          "-d",
          "--no-build",
          "--no-deps",
          "db",
        ]);
      run(["compose", "start", "api", "supervisor"]);
      console.error(
        `Migration incomplete. Original volume retained; private backup: ${backup}`,
      );
    }
  }
}
main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
