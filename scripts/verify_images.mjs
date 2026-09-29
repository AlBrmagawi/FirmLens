// Retain every match; reject high/critical/unknown findings without verified remediation evidence.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import {
  disposition,
  verifyAnalyzerScope,
  verifyBackport,
} from "./image_policy.mjs";

const docker = process.platform === "win32" ? "docker.exe" : "docker";
const run = (args) =>
  execFileSync(docker, args, {
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
    maxBuffer: 10 * 1024 * 1024,
  });
const databaseImage = run(["compose", "config", "--images", "db"]).trim();
assert(databaseImage);
const results = [];
for (const [name, target] of [
  ["app", "firmwarelens-app:0.1.0"],
  ["sandbox", "firmwarelens-sandbox:0.1.0"],
  ["database", databaseImage],
]) {
  const image = run(["image", "inspect", "--format", "{{.Id}}", target]).trim();
  const inspectFile = (path) =>
    run([
      "run",
      "--rm",
      "--network",
      "none",
      "--read-only",
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges:true",
      "--entrypoint",
      "cat",
      target,
      path,
    ]);
  const receipt = inspectFile(
    "/usr/local/share/firmwarelens/backports/zlib.txt",
  );
  const checksums = run([
    "run",
    "--rm",
    "--network",
    "none",
    "--read-only",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges:true",
    "--entrypoint",
    "sha256sum",
    target,
    "/usr/lib/libz.so.1.3.2",
    "/opt/zlib-backport/CVE-2026-85091.patch",
    "/opt/zlib-backport/regression.c",
    "/usr/local/share/firmwarelens/backports/zlib-regression",
  ]);
  const hashes = Object.fromEntries(
    [...checksums.matchAll(/^([a-f0-9]{64})  (\S+)$/gm)].map((match) => [
      match[2],
      match[1],
    ]),
  );
  const evidence = {
    zlib_backport_verified: verifyBackport(
      receipt,
      hashes,
      readFileSync("security/zlib/CVE-2026-85091.patch"),
      readFileSync("security/zlib/regression.c"),
    ),
    zlib_receipt: receipt,
    installed_hashes: hashes,
    grype_client_only_verified: false,
  };
  if (name === "sandbox") {
    const packages = inspectFile(
      "/usr/local/share/firmwarelens/analyzers/grype-packages.txt",
    );
    const build = inspectFile(
      "/usr/local/share/firmwarelens/analyzers/grype-build.txt",
    );
    evidence.grype_client_only_verified = verifyAnalyzerScope(packages, build);
    evidence.grype_docker_packages = packages
      .trim()
      .split(/\s+/)
      .filter((pkg) => /github.com\/(docker|moby)\//.test(pkg));
  }
  assert(
    evidence.zlib_backport_verified,
    `${name}: backport bytes or regression receipt differ from reviewed source`,
  );
  run([
    "run",
    "--rm",
    "--network",
    "none",
    "--read-only",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges:true",
    "--memory",
    "64m",
    "--pids-limit",
    "8",
    "--entrypoint",
    "/usr/local/share/firmwarelens/backports/zlib-regression",
    target,
  ]);
  evidence.installed_zlib_regression = "passed";
  const rawReport = run([
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
  ]);
  // Write as the invoking host user, with no writable host mount in the scanner.
  writeFileSync(`exports/${name}-image-audit.json`, rawReport);
  const report = JSON.parse(
    readFileSync(`exports/${name}-image-audit.json`, "utf8"),
  );
  const severity = {};
  for (const match of report.matches)
    severity[match.vulnerability.severity] =
      (severity[match.vulnerability.severity] ?? 0) + 1;
  const high = report.matches
    .filter((match) =>
      ["Critical", "High", "Unknown"].includes(match.vulnerability.severity),
    )
    .map((match) => ({
      id: match.vulnerability.id,
      package: match.artifact.name,
      installed: match.artifact.version,
      severity: match.vulnerability.severity,
      fix_state: match.vulnerability.fix.state,
      fixes: match.vulnerability.fix.versions,
      source: match.vulnerability.dataSource,
      disposition: disposition(match, evidence),
    }));
  const blocking = high.filter(
    (match) => match.disposition.status === "blocked",
  );
  results.push({
    name,
    image,
    severity,
    evidence,
    high_and_critical: high,
    blocking,
  });
  console.log(JSON.stringify({ name, severity, blocking: blocking.length }));
}
writeFileSync(
  "exports/image-validation.json",
  JSON.stringify(
    {
      gate: "No high, critical or unknown matches without verified backport or package-scope evidence; retain all scanner matches",
      results,
    },
    null,
    2,
  ),
);
assert(
  results.every((result) => result.blocking.length === 0),
  "Unresolved container advisories remain; inspect exports/image-validation.json",
);
