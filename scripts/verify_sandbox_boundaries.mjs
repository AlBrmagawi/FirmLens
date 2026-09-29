// Exercise real failure paths without changing the prepared intelligence volume.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const docker = process.platform === "win32" ? "docker.exe" : "docker";
const run = (args, options = {}) =>
  execFileSync(docker, args, {
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
    ...options,
  });
const id = randomUUID();
const volume = `firmwarelens-validation-${id}`;
const demo = JSON.parse(readFileSync("exports/demo-results.json", "utf8"));
const artifact = demo.scans.lab.artifact_id;
assert.match(artifact, /^[0-9a-f]{64}$/);
run(["volume", "create", "--label", `firmwarelens.validation=${id}`, volume]);
try {
  run(["compose", "stop", "supervisor"]);
  const code = `
import json, uuid
from firmwarelens.config import settings
from firmwarelens.sandbox import run_sandbox, Cancelled, SandboxError
from firmwarelens.schemas import ScanOptions, Limits
import docker
config = settings().model_copy(update={"data_volume": "firmwarelens_data", "intelligence_volume": ${JSON.stringify(volume)}})
artifact = ${JSON.stringify(artifact)}
outcomes = {}
jobs = []
def analyze(options, config=config, cancel=lambda: False):
    job = str(uuid.uuid4())
    jobs.append(job)
    return run_sandbox(config, job, artifact, options, cancel, lambda *args: None)
missing = analyze(ScanOptions())
assert missing.outcome == "partial"
assert len(missing.findings) >= 12
assert next(s for s in missing.stages if s.id == "vulnerabilities").state == "failure"
assert "unavailable" in next(s for s in missing.stages if s.id == "vulnerabilities").message
outcomes["missing_intelligence"] = {"status": missing.outcome, "retained_findings": len(missing.findings)}
bounded = analyze(ScanOptions(limits=Limits(max_files=1)))
assert bounded.outcome == "failed" and bounded.stages[0].state == "failure"
outcomes["file_budget"] = bounded.outcome
try:
    analyze(ScanOptions(), cancel=lambda: True)
    raise AssertionError("Cancellation did not stop analysis")
except Cancelled:
    outcomes["immediate_cancellation"] = "passed"
try:
    analyze(ScanOptions(), config=config.model_copy(update={"job_timeout": 0}))
    raise AssertionError("Wall-time budget did not stop analysis")
except SandboxError as exc:
    assert "wall-time" in str(exc)
    outcomes["wall_time_budget"] = "passed"
client = docker.from_env()
try:
    for job in jobs:
        assert not client.containers.list(all=True, filters={"label": f"firmwarelens.scan={job}"})
finally:
    client.close()
outcomes["all_test_containers_removed"] = True
print(json.dumps(outcomes))
`;
  const result = JSON.parse(
    run(
      [
        "run",
        "--rm",
        "-i",
        "--user",
        "0:0",
        "--network",
        "none",
        "--mount",
        "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock",
        "firmwarelens-app:0.1.0",
        "python",
        "-",
      ],
      { input: code, timeout: 240000 },
    ),
  );
  writeFileSync(
    "exports/sandbox-validation.json",
    JSON.stringify(result, null, 2),
  );
  console.log(JSON.stringify(result, null, 2));
} finally {
  try {
    const [details] = JSON.parse(run(["volume", "inspect", volume]));
    assert.equal(details.Labels["firmwarelens.validation"], id);
    run(["volume", "rm", volume]);
  } finally {
    run(["compose", "start", "supervisor"]);
  }
}
