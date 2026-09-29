// Scanner findings remain visible. This gate rejects critical matches, not all advisories.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const docker = process.platform === "win32" ? "docker.exe" : "docker";
const run = (args) =>
  execFileSync(docker, args, {
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
    maxBuffer: 10 * 1024 * 1024,
  });
const databaseImage = run(["compose", "config", "--images"])
  .trim()
  .split(/\s+/)
  .find((name) => name.startsWith("postgres:"));
assert(databaseImage);
const results = [];
for (const [name, target] of [
  ["app", "firmwarelens-app:0.1.0"],
  ["sandbox", "firmwarelens-sandbox:0.1.0"],
  ["database", databaseImage],
]) {
  const image = run(["image", "inspect", "--format", "{{.Id}}", target]).trim();
  run([
    "run",
    "--rm",
    "--network",
    "none",
    "--user",
    "0:0",
    "--read-only",
    "--cap-drop",
    "ALL",
    "--cap-add",
    "DAC_READ_SEARCH",
    "--security-opt",
    "no-new-privileges:true",
    "--memory",
    "2g",
    "--cpus",
    "1",
    "--tmpfs",
    "/tmp:rw,nosuid,nodev,size=2147483648",
    "--mount",
    "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock",
    "--mount",
    "type=volume,source=firmwarelens_intelligence,target=/intelligence,readonly",
    "--mount",
    `type=bind,source=${resolve("exports")},target=/reports`,
    "--env",
    "GRYPE_DB_CACHE_DIR=/intelligence",
    "--env",
    "GRYPE_DB_AUTO_UPDATE=false",
    "--env",
    "GRYPE_DB_VALIDATE_AGE=false",
    "--env",
    "GRYPE_CHECK_FOR_APP_UPDATE=false",
    "--env",
    "SYFT_CHECK_FOR_APP_UPDATE=false",
    "--entrypoint",
    "grype",
    "firmwarelens-sandbox:0.1.0",
    `docker:${target}`,
    "--output",
    "json",
    "--file",
    `/reports/${name}-image-audit.json`,
  ]);
  const report = JSON.parse(
    readFileSync(`exports/${name}-image-audit.json`, "utf8"),
  );
  const severity = {};
  for (const match of report.matches)
    severity[match.vulnerability.severity] =
      (severity[match.vulnerability.severity] ?? 0) + 1;
  const high = report.matches
    .filter((match) =>
      ["Critical", "High"].includes(match.vulnerability.severity),
    )
    .map((match) => ({
      id: match.vulnerability.id,
      package: match.artifact.name,
      installed: match.artifact.version,
      severity: match.vulnerability.severity,
      fix_state: match.vulnerability.fix.state,
      fixes: match.vulnerability.fix.versions,
      source: match.vulnerability.dataSource,
    }));
  results.push({ name, image, severity, high_and_critical: high });
  console.log(JSON.stringify({ name, severity }));
}
writeFileSync(
  "exports/image-validation.json",
  JSON.stringify(
    {
      gate: "No critical matches; high and lower matches remain disclosed for review",
      results,
    },
    null,
    2,
  ),
);
assert(
  results.every((result) => !result.severity.Critical),
  "Critical container advisories remain; inspect exports/image-validation.json",
);
