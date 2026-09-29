import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const docker = process.platform === 'win32' ? 'docker.exe' : 'docker';
const manifests = [];
const image = execFileSync(docker, ['image', 'inspect', 'firmwarelens-demo:0.1.0', '--format', '{{.Id}}'], { encoding: 'utf8' }).trim();
for (const run of ['a', 'b']) {
  const output = resolve(`.tools/repro-${randomUUID()}-${run}`);
  mkdirSync(output, { recursive: true });
  execFileSync(docker, ['run', '--rm', '--network', 'none', '--mount', `type=bind,source=${output},target=/out`, image], { stdio: 'pipe', timeout: 120000 });
  manifests.push(JSON.parse(readFileSync(`${output}/manifest.json`, 'utf8')));
}
assert.deepEqual(manifests[0], manifests[1], 'Repeated fixture builds differ');
assert.equal(Object.keys(manifests[0].sha256).length, 14);
const results = { builder_image: image, identical_artifacts: 14, manifest: manifests[0] };
mkdirSync('exports', { recursive: true });
writeFileSync('exports/reproducibility-validation.json', JSON.stringify(results, null, 2));
console.log(`Verified byte-identical SHA-256 values for all 14 artifacts across two builds using ${image}`);
