const { test, expect } = require("@playwright/test");

const restoreUrl = "http://dashboard-restore:8799";
const strictUrl = "http://dashboard-strict:8799";

function cssTimeToMilliseconds(value) {
  if (value.endsWith("ms")) return Number.parseFloat(value);
  if (value.endsWith("s")) return Number.parseFloat(value) * 1_000;
  throw new Error(`unsupported CSS time: ${value}`);
}

async function openWhenReady(page, url) {
  let lastError;
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      const response = await page.goto(url, { waitUntil: "domcontentloaded" });
      if (response && response.ok()) {
        await expect(page.getByText("live", { exact: true })).toBeVisible();
        return;
      }
    } catch (error) {
      lastError = error;
    }
    await page.waitForTimeout(250);
  }
  throw lastError || new Error(`dashboard did not become ready: ${url}`);
}

test("desktop renders truthful lifecycle outcomes", async ({ page }) => {
  const errors = [];
  page.on("console", message => {
    if (message.type() === "error" || message.type() === "warning") errors.push(message.text());
  });
  await page.setViewportSize({ width: 1440, height: 900 });
  await openWhenReady(page, restoreUrl);

  await expect(page).toHaveTitle("Promtect — Dashboard");
  await expect(page.getByRole("heading", { name: "Mask, forward, restore" })).toBeVisible();
  await expect(page.getByText("restore on", { exact: true })).toBeVisible();
  await expect(page.getByText("Secrets masked", { exact: true })).toBeVisible();
  await expect(page.getByText("Requests blocked", { exact: true })).toBeVisible();
  await expect(page.getByText("Secrets restored", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Output secrets", { exact: true })).toBeVisible();
  await expect(page.getByText("Failures", { exact: true })).toBeVisible();
  await expect(page.getByText("interrupted", { exact: true })).toBeVisible();
  expect(errors).toEqual([]);
});

test("strict mode never renders restore on", async ({ page }) => {
  await openWhenReady(page, strictUrl);
  await expect(page.getByText("strict mode", { exact: true })).toBeVisible();
  await expect(page.getByText("Restore off", { exact: true })).toBeVisible();
  await expect(page.getByText("restore on", { exact: true })).toHaveCount(0);
});

test("tabs support keyboard navigation and preserve focus", async ({ page }) => {
  await openWhenReady(page, restoreUrl);
  const overview = page.getByRole("tab", { name: "Overview" });
  await overview.focus();
  await expect(overview).toBeFocused();
  await page.keyboard.press("ArrowRight");

  const endpoints = page.getByRole("tab", { name: "Endpoints" });
  await expect(endpoints).toBeFocused();
  await expect(endpoints).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("tabpanel")).toHaveAttribute("aria-labelledby", "tab-endpoints");
  await expect(page.getByRole("heading", { name: "GET /metrics" })).toBeVisible();
});

test("mobile layout contains wide tables without page overflow", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await openWhenReady(page, restoreUrl);

  const sizes = await page.evaluate(() => ({
    body: document.documentElement.scrollWidth,
    viewport: document.documentElement.clientWidth,
    table: document.querySelector(".al-table").scrollWidth,
    wrapper: document.querySelector(".al-tablewrap").clientWidth,
  }));
  expect(sizes.body).toBeLessThanOrEqual(sizes.viewport);
  expect(sizes.table).toBeGreaterThan(sizes.wrapper);
  await expect(page.getByRole("tab", { name: "Overview" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Refresh metrics" })).toBeVisible();
});

test("reduced motion disables decorative movement", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await openWhenReady(page, restoreUrl);

  const motion = await page.evaluate(() => {
    const rise = getComputedStyle(document.querySelector(".al-rise"));
    const pulse = getComputedStyle(document.querySelector(".al-wire__pulse"));
    return { duration: rise.animationDuration, transform: rise.transform, pulseOpacity: pulse.opacity };
  });
  expect(cssTimeToMilliseconds(motion.duration)).toBeCloseTo(0.001, 6);
  expect(motion.transform).toBe("none");
  expect(motion.pulseOpacity).toBe("0");
});
