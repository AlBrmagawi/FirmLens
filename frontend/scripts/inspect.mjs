import { chromium } from "@playwright/test";
import assert from "node:assert/strict";
import AxeBuilder from "@axe-core/playwright";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
const token = execFileSync(
  process.platform === "win32" ? "docker.exe" : "docker",
  ["compose", "exec", "-T", "api", "firmwarelens", "access-token"],
  { cwd: resolve(".."), encoding: "utf8" },
).trim();
const demo = JSON.parse(readFileSync("../exports/demo-results.json", "utf8"));
const browser = await chromium.launch();
const context = await browser.newContext({
  viewport: { width: 1440, height: 1000 },
});
const page = await context.newPage();
const errors = [];
page.on("pageerror", (error) => errors.push(error.message));
await page.goto("http://localhost:8080");
await page.getByLabel("Local access token").fill(token);
await page.getByRole("button", { name: "Open workbench" }).click();
const pid = demo.project.id,
  lab = demo.scans.lab.id,
  revised = demo.scans.revised.id;
mkdirSync("../docs/screenshots", { recursive: true });
const results = [];
for (const [name, route] of [
  ["dashboard", `#/${pid}`],
  ["overview", `#/${pid}/${lab}/overview`],
  ["findings", `#/${pid}/${lab}/findings`],
  ["components", `#/${pid}/${lab}/components`],
  ["files", `#/${pid}/${lab}/files`],
  ["comparison", `#/${pid}/${revised}/compare`],
  ["assistant", `#/${pid}/${lab}/assistant`],
  ["reports", `#/${pid}/${lab}/reports`],
  ["settings", "#/settings"],
]) {
  await page.goto("http://localhost:8080/" + route);
  await page.waitForTimeout(1600);
  if (name === "findings") {
    await page
      .locator(".finding-link")
      .filter({ hasText: "SSH configuration permits permitrootlogin" })
      .click();
    await page.getByRole("heading", { name: "Traceable evidence" }).waitFor();
  }
  if (name === "files") {
    await page
      .getByRole("button", { name: "etc/ssh/sshd_config", exact: true })
      .click();
    await page.waitForTimeout(400);
  }
  if (name === "comparison") {
    await page.getByRole("button", { name: "Compare releases" }).click();
    await page.getByRole("heading", { name: "Finding changes" }).waitFor();
  }
  const accessibility = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
    .analyze();
  results.push({
    view: name,
    violations: accessibility.violations.map((v) => ({
      id: v.id,
      nodes: v.nodes.map((n) => ({
        target: n.target,
        summary: n.failureSummary,
      })),
    })),
  });
  if (["dashboard", "overview", "findings", "comparison"].includes(name))
    await page.screenshot({
      path: `../docs/screenshots/${name}.png`,
      fullPage: true,
    });
}
await page.setViewportSize({ width: 390, height: 844 });
await page.goto(`http://localhost:8080/#/${pid}`);
await page.waitForTimeout(1000);
const overflow = await page.evaluate(() => ({
  width: innerWidth,
  scrollWidth: document.documentElement.scrollWidth,
  elements: [...document.querySelectorAll("*")]
    .filter((e) => e.getBoundingClientRect().right > innerWidth + 1)
    .slice(0, 30)
    .map((e) => ({
      tag: e.tagName,
      class: e.className,
      right: e.getBoundingClientRect().right,
      width: e.getBoundingClientRect().width,
    })),
}));
await page.screenshot({
  path: "../docs/screenshots/mobile.png",
  fullPage: true,
});
writeFileSync(
  "../exports/browser-audit.json",
  JSON.stringify({ results, overflow, errors }, null, 2),
);
console.log(JSON.stringify({ results, overflow, errors }, null, 2));
await browser.close();
assert(
  results.every((view) => view.violations.length === 0),
  "Accessibility violations found",
);
assert(
  overflow.scrollWidth <= overflow.width,
  "Mobile document overflows viewport",
);
assert.equal(errors.length, 0, "Browser runtime errors found");
