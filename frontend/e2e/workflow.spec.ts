import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

test("API documentation loads its schema and assets locally", async ({
  page,
}) => {
  const external: string[] = [];
  page.on("request", (request) => {
    if (!request.url().startsWith("http://localhost:8080"))
      external.push(request.url());
  });
  await page.goto("/api/docs");
  await expect(page.locator(".swagger-ui .info .title")).toContainText(
    "FirmwareLens",
  );
  await expect(page.locator(".opblock").first()).toBeVisible();
  expect(external).toEqual([]);
});

const token =
  process.env.FL_TOKEN ??
  execFileSync(
    process.platform === "win32" ? "docker.exe" : "docker",
    ["compose", "exec", "-T", "api", "firmwarelens", "access-token"],
    { cwd: resolve(".."), encoding: "utf8" },
  ).trim();

test("upload → inspect → triage → compare → export, with accessible navigation", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/");
  await page.getByLabel("Local access token").fill(token);
  await page.getByRole("button", { name: "Open workbench" }).click();
  await page.getByRole("button", { name: "New project", exact: true }).click();
  await page
    .getByLabel("Project name", { exact: true })
    .fill("Browser validation lab");
  await page
    .getByLabel("Research scope")
    .fill("End-to-end verification using source-built synthetic firmware.");
  await page
    .getByRole("button", { name: "Create project", exact: true })
    .click();
  await page.getByRole("button", { name: "New analysis", exact: true }).click();
  await page
    .locator("#firmware")
    .setInputFiles(resolve("../demo/generated/lab.tar"));
  await page.getByLabel("Release label").fill("Browser · lab release");
  await page.getByRole("button", { name: "Start analysis" }).click();
  await expect(page.locator(".scan-subtitle .badge")).toHaveText(
    /partial|complete/,
    { timeout: 150000 },
  );
  await page.getByRole("link", { name: "Findings", exact: true }).click();
  await page
    .locator(".finding-link")
    .filter({ hasText: "SSH configuration permits permitrootlogin" })
    .click();
  await expect(
    page.getByRole("heading", { name: "Traceable evidence" }),
  ).toBeVisible();
  await page.getByLabel("Status", { exact: true }).selectOption("acknowledged");
  await page
    .getByLabel("Research notes")
    .fill("Validated directive; network reachability remains unknown.");
  await page.getByRole("button", { name: "Save assessment" }).click();
  await expect(page.getByLabel("Status", { exact: true })).toHaveValue(
    "acknowledged",
  );
  await page.getByRole("button", { name: "Close finding detail" }).click();
  await page.getByRole("link", { name: "Components", exact: true }).click();
  await expect(
    page.getByRole("cell", { name: /busybox/ }).first(),
  ).toBeVisible();
  await page.getByRole("link", { name: "Files", exact: true }).click();
  await page
    .getByRole("button", { name: "etc/device.conf", exact: true })
    .click();
  await expect(page.locator(".file-preview .code")).toContainText("[REDACTED]");
  await expect(page.locator("main")).not.toContainText(
    "SYNTHETIC_LAB_ONLY_DO_NOT_USE",
  );
  await page.getByRole("button", { name: "Analyze another release" }).click();
  await page
    .locator("#firmware")
    .setInputFiles(resolve("../demo/generated/revised.tar"));
  await page.getByLabel("Release label").fill("Browser · revised release");
  await page.getByRole("button", { name: "Start analysis" }).click();
  await expect(page.locator(".scan-subtitle .badge")).toHaveText(
    /partial|complete/,
    { timeout: 150000 },
  );
  await page.getByRole("link", { name: "Compare", exact: true }).click();
  await page.getByRole("button", { name: "Compare releases" }).click();
  await expect(
    page.getByRole("heading", { name: "Finding changes" }),
  ).toBeVisible();
  await expect(
    page.getByText("no longer detected", { exact: true }),
  ).toBeVisible();
  await page.getByRole("link", { name: "Reports", exact: true }).click();
  const download = page.waitForEvent("download");
  await page.getByRole("link", { name: "Download HTML", exact: true }).click();
  expect((await download).suggestedFilename()).toMatch(/\.html$/);
  await page.getByRole("link", { name: "Assistant", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "AI assistance is disabled" }),
  ).toBeVisible();
  const accessibility = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
    .analyze();
  expect(accessibility.violations).toEqual([]);
  expect(errors).toEqual([]);
});

test("login and research overview fit a narrow viewport", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(page.getByLabel("Local access token")).toBeVisible();
  await page.getByLabel("Local access token").fill(token);
  await page.getByRole("button", { name: "Open workbench" }).click();
  await expect(
    page.getByRole("heading", { name: "Research overview." }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await expect(
    page.getByRole("button", { name: "New project", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page.getByLabel("Local access token")).toBeVisible();
});
