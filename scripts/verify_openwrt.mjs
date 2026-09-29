// Optional real-firmware check; first prepare the pinned sample with openwrt_integration.py.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const docker = process.platform === "win32" ? "docker.exe" : "docker";
const name = "openwrt-23.05.5-rootfs.squashfs";
const sha256 = createHash("sha256")
  .update(readFileSync(`demo/generated/${name}`))
  .digest("hex");
assert.equal(
  sha256,
  "c27bb3ab1f955b46940b9752a546bede813c9324b73be004202027091065a806",
);
const cli = (args) =>
  JSON.parse(
    execFileSync(
      docker,
      ["compose", "exec", "-T", "api", "firmwarelens", ...args, "--json"],
      { encoding: "utf8", timeout: 720000 },
    ),
  );
const project = cli(["project", "create", "OpenWrt release validation"]);
const scan = cli([
  "scan",
  `/demo/${name}`,
  "--project",
  project.id,
  "--allow-partial",
]);
assert.equal(scan.status, "partial");
assert.equal(scan.artifact_id, sha256);
assert(scan.summary.files > 1000 && scan.summary.components > 100);
assert.equal(
  scan.stages.find((stage) => stage.id === "extraction").state,
  "partial",
);
assert(
  scan.stages
    .filter((stage) => stage.id !== "extraction")
    .every((stage) => stage.state === "success"),
);
writeFileSync("exports/openwrt-validation.json", JSON.stringify(scan, null, 2));
console.log(
  JSON.stringify(
    {
      id: scan.id,
      status: scan.status,
      summary: scan.summary,
      duration_ms: scan.manifest.duration_ms,
    },
    null,
    2,
  ),
);
