// Browser acceptance for the first routed milestone. The test interacts only
// with product controls and xterm input, so it cannot fabricate operational
// state through a test hook or bypass the real Wasm Worker.

import { expect, test, type Page } from "@playwright/test";
import { readFile } from "node:fs/promises";

async function submitCli(page: Page, command: string): Promise<void> {
  // xterm's hidden textarea is its supported keyboard boundary. Waiting for it
  // to become writable also proves that the pthread startup gate completed.
  const input = page.getByLabel("Terminal input");
  await expect(input).toBeEnabled();
  await input.focus();
  await input.pressSequentially(command, { delay: 2 });
  await input.press("Enter");
  // Commands are serialized through one Worker and a bounded C++ mailbox. A
  // short UI-level wait prevents the next line from becoming intentional type
  // ahead while still leaving all device timers on the real monotonic clock.
  await page.waitForTimeout(120);
}

async function equipRouter(page: Page): Promise<void> {
  await submitCli(page, "configure exclusive");
  await submitCli(page, "card 1 card-type iom4-e");
  await submitCli(page, "card 1 mda 1 mda-type me10-10gb-sfp+");
  await submitCli(page, "commit");

  await page.getByRole("button", { name: "Cards", exact: true }).click();
  await page.getByRole("button", { name: "Insert iom4-e", exact: true }).click();
  await page.getByRole("button", { name: "Insert me10-10gb-sfp+", exact: true }).click();
  // Card and MDA initialization deliberately consume 2 s and 1 s of real
  // monotonic time. The ready status is observed rather than time-warped.
  await expect(page.getByText("ready", { exact: true })).toHaveCount(2,
    { timeout: 8_000 });
}

test("runs, fails and restores the complete first routed path", async ({ page }, testInfo) => {
  await page.goto("/");
  expect(await page.evaluate(() => crossOriginIsolated)).toBe(true);
  await expect(page.getByText("R1 console", { exact: true })).toBeVisible();
  await equipRouter(page);

  // Selecting Host A exposes the product ping action. Its result comes from
  // encoded ARP and ICMP frames crossing both physical links and the router.
  await page.getByText("Host A", { exact: true }).first().click();
  await page.getByRole("button", { name: "Ping Host B", exact: true }).click();
  await expect(page.locator(".operation-result")).toContainText("packet transmitted");
  await expect(page.locator(".operation-result")).toContainText("0.00% packet loss");

  // A structural checkpoint must preserve terminal bytes that have not been
  // submitted. Read the portable wrapper, import it through the normal file
  // action, then export once more to prove the active editor was restored.
  const terminalInput = page.getByLabel("Terminal input");
  await terminalInput.focus();
  await terminalInput.pressSequentially("show por", { delay: 2 });
  const checkpointDownload = page.waitForEvent("download");
  await page.getByTitle("More project actions").click();
  await page.getByRole("button", { name: "Export checkpoint", exact: true }).click();
  const checkpointPath = await (await checkpointDownload).path();
  expect(checkpointPath).toBeTruthy();
  const checkpointManifest = JSON.parse(await readFile(checkpointPath!, "utf8"));
  expect(checkpointManifest.mode).toBe("checkpoint");
  expect(checkpointManifest.checkpointBase64.length).toBeGreaterThan(0);
  expect(checkpointManifest.terminalPresentation.editors["md-configuration"].buffer)
    .toBe("show por");
  const importInput = page.locator('input[type="file"][accept^=".netsim"]');
  await importInput.setInputFiles(checkpointPath!);
  await expect(page.getByLabel("Terminal input")).toBeEnabled();
  const restoredDownload = page.waitForEvent("download");
  await page.getByTitle("More project actions").click();
  await page.getByRole("button", { name: "Export checkpoint", exact: true }).click();
  const restoredPath = await (await restoredDownload).path();
  const restoredManifest = JSON.parse(await readFile(restoredPath!, "utf8"));
  expect(restoredManifest.terminalPresentation.editors["md-configuration"].buffer)
    .toBe("show por");

  // A carrier failure is applied through the inspector and must make the same
  // diagnostic fail. No topology graph shortcut is allowed to answer it.
  await page.getByText("R1", { exact: true }).first().click();
  await page.getByRole("button", { name: "Ports", exact: true }).click();
  await page.getByRole("button", { name: "Disconnect", exact: true }).first().click();
  await page.getByText("Host A", { exact: true }).first().click();
  await page.getByRole("button", { name: "Ping Host B", exact: true }).click();
  // Product UI intentionally does not leak internal drop reasons or runtime
  // transport errors. The generic failure still proves no reply crossed the
  // disconnected medium; detailed reasons remain in router diagnostics.
  await expect(page.locator(".operation-result"))
    .toContainText("could not be completed");

  // Project export is a public, portable wrapper. Read the downloaded file to
  // confirm profile locking and then import the exact same bytes through UI.
  const downloadPromise = page.waitForEvent("download");
  await page.locator(".top-actions").getByRole("button", { name: /Export/ }).click();
  const download = await downloadPromise;
  const path = await download.path();
  expect(path).toBeTruthy();
  const manifest = JSON.parse(await readFile(path!, "utf8"));
  expect(manifest.mode).toBe("project");
  expect(manifest.profileLock.release).toBe("26.7.R1");
  await importInput.setInputFiles(path!);
  await expect(page.getByText("R1 console", { exact: true })).toBeVisible();

  // Reload exercises IndexedDB autosave plus hardware reconciliation in a new
  // Worker. Readiness after reload implies the browser observed two distinct
  // pthread owners because RuntimeClient refuses to open otherwise.
  await page.waitForTimeout(700);
  await page.reload();
  await expect(page.getByText("R1 console", { exact: true })).toBeVisible();
  await page.getByText("R1", { exact: true }).first().click();
  await page.getByRole("button", { name: "Cards", exact: true }).click();
  await expect(page.getByText("ready", { exact: true })).toHaveCount(2,
    { timeout: 8_000 });
  await expect(page.getByLabel("Terminal input")).toBeEnabled();
  await page.screenshot({ path: testInfo.outputPath("first-milestone.png"), fullPage: true });
});
