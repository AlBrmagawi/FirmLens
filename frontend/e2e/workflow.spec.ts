import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

test("API documentation loads its schema and assets locally", async ({
  page,
  baseURL,
}) => {
  const external: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).origin !== new URL(baseURL!).origin)
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
  const saved = page.waitForResponse(
    (response) =>
      response.request().method() === "PATCH" &&
      response.url().includes("/findings/"),
  );
  await page.getByRole("button", { name: "Save assessment" }).click();
  expect((await saved).ok()).toBe(true);
  await page.reload();
  await expect(page.getByLabel("Status", { exact: true })).toHaveValue(
    "acknowledged",
  );
  await expect(page.getByLabel("Research notes")).toHaveValue(
    "Validated directive; network reachability remains unknown.",
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
  const report = await download;
  expect(report.suggestedFilename()).toMatch(/\.html$/);
  const content = readFileSync((await report.path())!, "utf8");
  expect(content).toContain("FirmwareLens");
  expect(content).not.toContain("SYNTHETIC_LAB_ONLY_DO_NOT_USE");
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
  await page.setViewportSize({ width: 320, height: 844 });
  await page.goto("/");
  await expect(page.getByLabel("Local access token")).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  const loginAccessibility = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
    .analyze();
  expect(loginAccessibility.violations).toEqual([]);
  await page.getByLabel("Local access token").fill(token);
  await page.getByRole("button", { name: "Open workbench" }).click();
  await expect(
    page.getByRole("heading", { name: "Research overview." }),
  ).toBeVisible();
  for (const width of [320, 390, 768]) {
    await page.setViewportSize({ width, height: 844 });
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    await expect(
      page.getByRole("button", { name: "New project", exact: true }),
    ).toBeVisible();
  }
  await expect(
    page.getByRole("button", { name: "New project", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page.getByLabel("Local access token")).toBeVisible();
});

test("keyboard dialogs preserve uploads and recover from upload errors", async ({
  page,
}) => {
  await page.goto("/");
  await page.getByLabel("Local access token").fill(token);
  await page.getByRole("button", { name: "Open workbench" }).click();
  const opener = page.getByRole("button", { name: "New project", exact: true });
  await opener.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(opener).toBeFocused();
  await opener.click();
  await page
    .getByLabel("Project name", { exact: true })
    .fill("Keyboard and error validation");
  await page
    .getByRole("button", { name: "Create project", exact: true })
    .click();
  await page.getByRole("button", { name: "New analysis", exact: true }).click();
  await page
    .locator("#firmware")
    .setInputFiles(resolve("../demo/generated/lab.tar"));
  let release!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route("**/artifacts", async (route) => {
    await held;
    await route.fulfill({
      status: 413,
      contentType: "application/json",
      body: JSON.stringify({
        error: { code: "413", message: "Upload exceeds configured size limit" },
      }),
    });
  });
  try {
    await page.getByRole("button", { name: "Start analysis" }).click();
    await expect(
      page.getByRole("button", { name: "Preparing scan" }),
    ).toBeDisabled();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toBeVisible();
  } finally {
    release();
  }
  await expect(page.getByRole("alert")).toContainText(
    "Upload exceeds configured size limit",
  );
  await expect(
    page.getByRole("button", { name: "Start analysis" }),
  ).toBeEnabled();
  await page.unroute("**/artifacts");
  await page.locator("#firmware").setInputFiles({
    name: "r".repeat(110) + ".img",
    mimeType: "application/octet-stream",
    buffer: Buffer.from("Unsupported firmware regression fixture"),
  });
  await page.getByRole("button", { name: "Start analysis" }).click();
  await expect(page.locator(".scan-subtitle .badge")).toHaveText(
    "unsupported",
    { timeout: 60000 },
  );
  await expect(
    page.getByText("Analysis coverage", { exact: true }),
  ).toBeVisible();
});
