import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';

if (!existsSync('.env')) {
  writeFileSync('.env', `POSTGRES_PASSWORD=${randomBytes(32).toString('hex')}\nFL_PORT=8080\nFL_ORIGIN=http://localhost:8080\nFL_AI_PROVIDER=disabled\nFL_AI_MODEL=\nFL_CLOUD_AI_ENABLED=false\nFL_OPENAI_API_KEY=\n`, { mode: 0o600, flag: 'wx' });
  console.log('Created local .env with a random database credential. No credential was logged.');
} else console.log('Existing .env preserved.');
for (const path of ['demo/generated', 'exports', 'intelligence-import']) mkdirSync(path, { recursive: true });
console.log('Next: docker compose build && docker compose --profile tools build sandbox demo && docker compose up -d');
