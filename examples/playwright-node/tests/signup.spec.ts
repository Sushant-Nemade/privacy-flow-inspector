import { readFileSync } from "node:fs";
import path from "node:path";
import { expect, test } from "../privacy-fixture";

const SITE = path.resolve(__dirname, "../../demo-shop");
const PERSONA = {
  full_name: "Jane Test",
  email: "jane.test@example.com",
  phone: "+49 151 23456789",
  iban: "DE89370400440532013000",
  kvnr: "A123456780",
  diagnosis: "J45.9",
};

// The fictional chat server does not exist; the fixture records what the page sends without connecting.
test.use({ connectWebSockets: false });

test("signup flow of the fictional demo shop", async ({ page }) => {
  await page.context().route("**/*", async (route) => {
    const url = route.request().url();
    if (url === "https://shop.example/") {
      await route.fulfill({ contentType: "text/html", body: readFileSync(path.join(SITE, "index.html"), "utf-8") });
    } else if (url === "https://shop.example/app.js") {
      await route.fulfill({ contentType: "text/javascript", body: readFileSync(path.join(SITE, "app.js"), "utf-8") });
    } else if (url.startsWith("https://shop.example/api/")) {
      await route.fulfill({ contentType: "application/json", body: '{"ok":true}' });
    } else {
      await route.fulfill({
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "https://shop.example",
          "Access-Control-Allow-Headers": "content-type, authorization",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        },
      });
    }
  });
  await page.goto("https://shop.example/");
  for (const [name, value] of Object.entries(PERSONA)) {
    await page.fill(`input[name=${name}]`, value);
  }
  await page.click("button[type=submit]");
  await expect(page.locator("#status")).toHaveText(/Account created/);
});
