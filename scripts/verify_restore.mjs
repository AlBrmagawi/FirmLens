// Restore copies into disposable, labelled resources. Never replace live data.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { writeFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";

const docker = process.platform === "win32" ? "docker.exe" : "docker";
const run = (args, options = {}) =>
  execFileSync(docker, args, {
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
    maxBuffer: 128 * 1024 * 1024,
    ...options,
  });
const id = randomUUID();
const label = `firmwarelens.validation=${id}`;
const sourceDatabase = run(["compose", "ps", "-q", "db"]).trim();
const postgresImage =
  process.env.FL_RESTORE_IMAGE ??
  run(["inspect", "--format", "{{.Config.Image}}", sourceDatabase]).trim();
const container = `firmwarelens-restore-${id}`;
const data = `${container}-data`;
const postgres = `${container}-postgres`;
const ownedVolumes = [];
let created = false;
let stopped = false;
try {
  run(["compose", "stop", "api", "supervisor"]);
  stopped = true;
  for (const volume of [data, postgres]) {
    run(["volume", "create", "--label", label, volume]);
    ownedVolumes.push(volume);
  }
  const dump = run(
    [
      "compose",
      "exec",
      "-T",
      "db",
      "pg_dump",
      "-U",
      "firmwarelens",
      "-d",
      "firmwarelens",
      "-Fc",
    ],
    { encoding: null },
  );
  run([
    "run",
    "--rm",
    "--network",
    "none",
    "--user",
    "0:0",
    "--mount",
    "type=volume,source=firmwarelens_data,target=/source,readonly",
    "--mount",
    `type=volume,source=${data},target=/restore`,
    "firmwarelens-app:0.1.0",
    "sh",
    "-c",
    "tar -C /source -cf - . | tar -C /restore -xf -",
  ]);
  run([
    "run",
    "-d",
    "--name",
    container,
    "--label",
    label,
    "--network",
    "none",
    "--env",
    "POSTGRES_HOST_AUTH_METHOD=trust",
    "--env",
    "POSTGRES_USER=firmwarelens",
    "--env",
    "POSTGRES_DB=firmwarelens",
    "--mount",
    `type=volume,source=${postgres},target=/var/lib/postgresql/data`,
    postgresImage,
  ]);
  created = true;
  let ready = false;
  for (let n = 0; n < 60; n++) {
    try {
      run([
        "exec",
        container,
        "psql",
        "-h",
        "127.0.0.1",
        "-U",
        "firmwarelens",
        "-At",
        "-c",
        "SELECT 1",
        "-d",
        "firmwarelens",
      ]);
      ready = true;
      break;
    } catch {
      await delay(1000);
    }
  }
  assert(ready, "Isolated restore database did not become ready");
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
  const source = ["compose", "exec", "-T", "db"];
  const restored = ["exec", container];
  const sql = (prefix, query) =>
    run([
      ...prefix,
      "psql",
      "-U",
      "firmwarelens",
      "-d",
      "firmwarelens",
      "-At",
      "-c",
      query,
    ]).trim();
  const tables = sql(
    source,
    "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename",
  )
    .split("\n")
    .filter(Boolean);
  const counts = {};
  for (const table of tables) {
    assert.match(table, /^[a-z_]+$/);
    const query = `SELECT count(*), md5(coalesce(string_agg(row_to_json(t)::text, '' ORDER BY row_to_json(t)::text), '')) FROM "${table}" t`;
    const expected = sql(source, query);
    assert.equal(
      sql(restored, query),
      expected,
      `Restore changed table ${table}`,
    );
    counts[table] = Number(expected.split("|")[0]);
  }
  const verification = `
import hashlib, json, pathlib, stat
source, restored = pathlib.Path('/source'), pathlib.Path('/restore')
def manifest(root):
    result = {}
    for path in sorted(root.rglob('*')):
        entry = path.stat()
        result[str(path.relative_to(root))] = [stat.S_IMODE(entry.st_mode), entry.st_uid, entry.st_gid, hashlib.file_digest(path.open('rb'), 'sha256').hexdigest() if path.is_file() else None]
    return result
original = manifest(source)
assert original == manifest(restored), 'Restored bytes, paths or ownership changed'
artifacts = list((restored / 'artifacts').glob('*/firmware'))
for artifact in artifacts:
    assert hashlib.file_digest(artifact.open('rb'), 'sha256').hexdigest() == artifact.parent.name
assert (restored / 'admin-token').stat().st_mode & 0o777 == 0o600
print(json.dumps({'entries': len(original), 'verified_artifacts': len(artifacts), 'permissions_and_bytes_equal': True}))
`;
  const files = JSON.parse(
    run(
      [
        "run",
        "--rm",
        "-i",
        "--network",
        "none",
        "--read-only",
        "--user",
        "0:0",
        "--mount",
        "type=volume,source=firmwarelens_data,target=/source,readonly",
        "--mount",
        `type=volume,source=${data},target=/restore,readonly`,
        "firmwarelens-app:0.1.0",
        "python",
        "-",
      ],
      { input: verification },
    ),
  );
  const result = {
    restored_database_image: postgresImage,
    database_tables: counts,
    database_rows_equal: true,
    dump_bytes: dump.length,
    ...files,
  };
  writeFileSync(
    "exports/restore-validation.json",
    JSON.stringify(result, null, 2),
  );
  console.log(JSON.stringify(result, null, 2));
} finally {
  try {
    if (created) {
      const [details] = JSON.parse(run(["inspect", container]));
      assert.equal(details.Config.Labels["firmwarelens.validation"], id);
      run(["rm", "-f", container]);
    }
    for (const volume of ownedVolumes) {
      const [details] = JSON.parse(run(["volume", "inspect", volume]));
      assert.equal(details.Labels["firmwarelens.validation"], id);
      run(["volume", "rm", volume]);
    }
  } finally {
    if (stopped) run(["compose", "start", "api", "supervisor"]);
  }
}
let ready = false;
for (let n = 0; n < 90; n++) {
  try {
    ready = (await fetch("http://localhost:8080/ready")).ok;
  } catch {
    /* startup */
  }
  if (ready) break;
  await delay(1000);
}
assert(
  ready,
  "Original application did not become ready after backup exercise",
);
