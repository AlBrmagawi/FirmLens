import { copyFileSync, mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

const require = createRequire(import.meta.url);
const source = dirname(require.resolve("swagger-ui-dist/package.json"));
mkdirSync("public/vendor/swagger", { recursive: true });
for (const file of [
  "swagger-ui-bundle.js",
  "swagger-ui.css",
  "LICENSE",
  "NOTICE",
]) {
  copyFileSync(join(source, file), join("public/vendor/swagger", file));
}
