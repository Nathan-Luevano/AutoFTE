#!/usr/bin/env node
// Screenshots the static AutoFTE dashboard as autofte-dashboard.png, an
// intermediate input to scripts/stitch-demo.sh (which folds it into the
// README's autofte-demo-combined.gif -- see CONTRIBUTING.md). Not itself
// checked in; this script is, so the screenshot step is reproducible.
//
// Renders autofte-demo-output/dashboard/index.html in headless Chromium
// (via puppeteer) and saves a full-page PNG.
//
// Requires: `autofte demo` already run (so the dashboard HTML exists), and
// puppeteer installed (`npm install puppeteer`).
//
// Usage: node scripts/screenshot-dashboard.mjs [dashboard-html] [out.png]

import puppeteer from "puppeteer";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dashboardHtml =
  process.argv[2] ?? path.join(repoRoot, "autofte-demo-output", "dashboard", "index.html");
const outPng = process.argv[3] ?? path.join(repoRoot, "autofte-dashboard.png");

const browser = await puppeteer.launch({ headless: "new", args: ["--no-sandbox"] });
try {
  const page = await browser.newPage();
  // deviceScaleFactor: 1 keeps the PNG a reasonable size for a repo asset
  // (2x produced a ~960KB file for not much visible gain).
  await page.setViewport({ width: 1100, height: 800, deviceScaleFactor: 1 });
  await page.goto(`file://${dashboardHtml}`, { waitUntil: "networkidle0" });
  await page.screenshot({ path: outPng, fullPage: true });
  console.log(`Wrote ${outPng}`);
} finally {
  await browser.close();
}
