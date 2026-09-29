import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';

const docker = process.platform === 'win32' ? 'docker.exe' : 'docker';
const token = execFileSync(docker, ['compose', 'exec', '-T', 'api', 'firmwarelens', 'access-token'], { encoding: 'utf8' }).trim();
const demo = JSON.parse(readFileSync('exports/demo-results.json', 'utf8'));
async function call(path, method = 'GET', body) {
  const response = await fetch(`http://localhost:8080/api/v1${path}`, {
    method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  assert(response.ok, `${method} ${path}: ${response.status}`);
  return response.json();
}
const originalBase = `/projects/${demo.project.id}`;
const before = await call(`${originalBase}/scans/${demo.scans.lab.id}`);
execFileSync(docker, ['compose', 'restart', 'api', 'supervisor'], { stdio: 'pipe' });
let ready = false;
for (let attempt = 0; attempt < 90; attempt++) {
  try { ready = (await fetch('http://localhost:8080/ready')).ok; } catch { /* startup */ }
  if (ready) break;
  await delay(1000);
}
assert(ready, 'Application did not become ready after restart');
const after = await call(`${originalBase}/scans/${before.id}`);
assert.deepEqual(after, before, 'Persisted immutable result changed after restart');
const project = await call('/projects', 'POST', { name: 'Operations validation' });
const base = `/projects/${project.id}`;
const upload = await fetch(`http://localhost:8080/api/v1${base}/artifacts`, {
  method: 'POST', headers: { Authorization: `Bearer ${token}`, 'X-Filename': 'lab.tar', 'Content-Type': 'application/octet-stream' },
  body: readFileSync('demo/generated/lab.tar'),
});
assert(upload.ok, 'Operation fixture upload failed');
const artifact = await upload.json();
const interrupted = await call(`${base}/scans`, 'POST', { artifact_id: artifact.id, label: 'Abrupt restart validation' });
let recovering;
for (let attempt = 0; attempt < 100; attempt++) {
  recovering = await call(`${base}/scans/${interrupted.id}`);
  if (recovering.status === 'running') break;
  await delay(100);
}
assert.equal(recovering.status, 'running');
execFileSync(docker, ['compose', 'kill', '-s', 'SIGKILL', 'supervisor'], { stdio: 'pipe' });
const supervisor = execFileSync(docker, ['compose', 'ps', '-a', '-q', 'supervisor'], { encoding: 'utf8' }).trim();
for (let attempt = 0; attempt < 60; attempt++) {
  const running = execFileSync(docker, ['inspect', '--format', '{{.State.Running}}', supervisor], { encoding: 'utf8' }).trim();
  if (running === 'false') break;
  await delay(100);
}
execFileSync(docker, ['compose', 'start', 'supervisor'], { stdio: 'pipe' });
assert.equal(execFileSync(docker, ['inspect', '--format', '{{.State.Running}}', supervisor], { encoding: 'utf8' }).trim(), 'true', 'Supervisor was not restarted');
for (let attempt = 0; attempt < 180; attempt++) {
  recovering = await call(`${base}/scans/${interrupted.id}`);
  if (!['queued', 'running'].includes(recovering.status)) break;
  await delay(1000);
}
assert(['complete', 'partial'].includes(recovering.status), 'Interrupted job did not recover');
assert.equal(recovering.attempts, 2, 'Expired lease did not trigger bounded retry');
const job = await call(`${base}/scans`, 'POST', { artifact_id: artifact.id, label: 'Cancellation validation' });
let current;
for (let attempt = 0; attempt < 100; attempt++) {
  current = await call(`${base}/scans/${job.id}`);
  if (current.status === 'running') break;
  await delay(100);
}
assert.equal(current.status, 'running', 'Did not observe running job before cancellation');
await call(`${base}/scans/${job.id}/cancel`, 'POST');
for (let attempt = 0; attempt < 60; attempt++) {
  current = await call(`${base}/scans/${job.id}`);
  if (current.status === 'cancelled') break;
  await delay(500);
}
assert.equal(current.status, 'cancelled');
const containers = execFileSync(docker, ['ps', '-a', '-q', '--filter', `label=firmwarelens.scan=${job.id}`], { encoding: 'utf8' }).trim();
assert.equal(containers, '', 'Cancelled analysis container was not cleaned up');
let threshold;
try {
  execFileSync(docker, ['compose', 'exec', '-T', 'api', 'firmwarelens', 'scan', '/demo/lab.tar', '--project', project.id, '--label', 'CLI threshold validation', '--allow-partial', '--fail-on', 'high', '--json'], { encoding: 'utf8' });
  assert.fail('CLI did not signal the high-severity threshold');
} catch (error) {
  assert.equal(error.status, 3, 'CLI threshold exit code must be 3');
  threshold = JSON.parse(error.stdout);
  assert(threshold.summary.severity.high > 0);
}
const results = { restart_preserved_scan: before.id, recovered_scan: interrupted.id, recovery_attempts: recovering.attempts, cancelled_running_scan: job.id, container_removed: true, threshold_scan: threshold.id, threshold_exit: 3 };
writeFileSync('exports/operations-validation.json', JSON.stringify(results, null, 2));
console.log(JSON.stringify(results, null, 2));
