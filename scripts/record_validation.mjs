// Record measured local outputs for the case study; this never creates scan results.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
const read = name => JSON.parse(readFileSync(`exports/${name}`, 'utf8').replace(/^\uFEFF/, ''));
const demo = read('demo-results.json');
const summarize = scan => ({
  scan_id: scan.id, artifact_sha256: scan.artifact_id, status: scan.status,
  summary: scan.summary, started_at: scan.manifest.started_at,
  stages: scan.stages.map(({ id, state, message }) => ({ id, state, message })),
  measurements: Object.fromEntries(['duration_ms', 'peak_rss_kib', 'child_peak_rss_kib'].map(key => [key, scan.manifest[key]])),
  tools: Object.fromEntries(['firmwarelens', 'python', 'pyelftools', 'rules', 'syft', 'grype', 'intelligence', 'sandbox'].map(key => [key, scan.manifest[key]])),
});
const audit = read('browser-audit.json');
mkdirSync('docs/validation', { recursive: true });
writeFileSync('docs/validation/measured-results.json', JSON.stringify({
  recorded_at: new Date().toISOString(),
  synthetic: Object.fromEntries(Object.entries(demo.scans).map(([name, scan]) => [name, summarize(scan)])),
  comparison_counts: Object.fromEntries(Object.entries(demo.comparison.findings).map(([key, values]) => [key, values.length])),
  formats: read('format-validation.json'),
  openwrt: summarize(read('openwrt-scan.json')),
  browser: { views: audit.results.map(view => ({ name: view.view, violations: view.violations.length })), viewport: audit.overflow.width, document_width: audit.overflow.scrollWidth },
}, null, 2) + '\n');
console.log('Recorded actual results in docs/validation/measured-results.json');
