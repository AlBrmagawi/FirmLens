// A small concurrency smoke check against real PostgreSQL, uploads and queue claims.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";

const docker = process.platform === "win32" ? "docker.exe" : "docker";
const token = execFileSync(
  docker,
  ["compose", "exec", "-T", "api", "firmwarelens", "access-token"],
  { encoding: "utf8" },
).trim();
const root = "http://localhost:8080/api/v1";
async function call(path, init = {}) {
  const response = await fetch(root + path, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      ...init.headers,
    },
  });
  assert(response.ok, `${init.method ?? "GET"} ${path}: ${response.status}`);
  return response.json();
}
const project = await call("/projects", {
  method: "POST",
  body: JSON.stringify({ name: "Concurrent request validation" }),
});
const base = `/projects/${project.id}`;
// A unique trailer leaves the tar payload unchanged while exercising first-time deduplication.
const payload = Buffer.concat([
  readFileSync("demo/generated/lab.tar"),
  Buffer.from(randomUUID()),
]);
const sha256 = createHash("sha256").update(payload).digest("hex");
const uploads = await Promise.all(
  Array.from({ length: 8 }, () =>
    call(base + "/artifacts", {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-Filename": "lab.tar",
      },
      body: payload,
    }),
  ),
);
assert(uploads.every((artifact) => artifact.id === sha256));
const key = randomUUID();
const scans = await Promise.all(
  Array.from({ length: 8 }, () =>
    call(base + "/scans", {
      method: "POST",
      headers: { "Idempotency-Key": key },
      body: JSON.stringify({
        artifact_id: sha256,
        label: "Concurrent retry",
        options: { components: false, vulnerabilities: false },
      }),
    }),
  ),
);
assert.equal(
  new Set(scans.map((scan) => scan.id)).size,
  1,
  "Concurrent retry created duplicate analyses",
);
const scanPath = base + "/scans/" + scans[0].id;
const started = performance.now();
const reads = await Promise.all(
  Array.from({ length: 50 }, () => call(scanPath)),
);
const readMs = Math.round(performance.now() - started);
assert(reads.every((scan) => scan.id === scans[0].id));
let scan;
for (let attempt = 0; attempt < 120; attempt++) {
  scan = await call(scanPath);
  if (!["running", "queued"].includes(scan.status)) break;
  await delay(500);
}
assert.equal(scan.status, "partial");
assert.equal(scan.attempts, 1);
assert(scan.summary.findings >= 12);
assert.equal((await call(base + "/scans")).total, 1);
const download = await fetch(
  root + base + "/artifacts/" + sha256 + "/download",
  { headers: { Authorization: `Bearer ${token}` } },
);
assert(download.ok);
assert.equal(
  createHash("sha256")
    .update(Buffer.from(await download.arrayBuffer()))
    .digest("hex"),
  sha256,
);
const result = {
  concurrent_uploads: 8,
  concurrent_idempotent_submissions: 8,
  unique_scans: 1,
  scan_attempts: scan.attempts,
  parallel_reads: 50,
  parallel_read_batch_ms: readMs,
  original_download_integrity: true,
  scan_id: scan.id,
};
writeFileSync(
  "exports/concurrency-validation.json",
  JSON.stringify(result, null, 2),
);
console.log(JSON.stringify(result, null, 2));
