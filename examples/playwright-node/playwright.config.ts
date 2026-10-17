import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  outputDir: "./test-results",
  // Keep every test's network.har, also for passing tests, so the privacy gate can scan them.
  preserveOutput: "always",
  reporter: [["list"]],
  // Lets the fictional legacy ad call go out over plain HTTP so the HAR shows an unencrypted flow.
  use: { ...devices["Desktop Chrome"], launchOptions: { args: ["--allow-running-insecure-content"] } },
});
