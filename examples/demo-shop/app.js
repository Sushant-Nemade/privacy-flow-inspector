// Fictional demo app. Hosts ending in .test or .example do not exist; the recorder answers them locally.
async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function base64url(text) {
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fakeJwt(claims) {
  return `${base64url(JSON.stringify({ alg: "HS256", typ: "JWT" }))}.${base64url(JSON.stringify(claims))}.demo-signature`;
}

async function send(url, options = {}) {
  try {
    await fetch(url, { mode: "cors", ...options });
  } catch (error) {
    console.warn("demo request failed", url, error);
  }
}

document.getElementById("signup").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = Object.fromEntries(new FormData(event.target));
  const json = { "Content-Type": "application/json" };
  const phoneDigits = form.phone.replace(/\D/g, "");

  // First party: expected processing over HTTPS (reported as info/low for review, not as a leak).
  await send("https://shop.example/api/signup", {
    method: "POST",
    headers: json,
    body: JSON.stringify({ full_name: form.full_name, email: form.email, phone: form.phone }),
  });
  await send("https://shop.example/api/intake", {
    method: "POST",
    headers: { ...json, Authorization: `Bearer ${fakeJwt({ sub: "user-42", email: form.email })}` },
    body: JSON.stringify({ kvnr: form.kvnr, diagnosis: form.diagnosis }),
  });

  // Third party analytics: plain email and name in a JSON body.
  await send("https://api.analytics-vendor.test/v1/track", {
    method: "POST",
    headers: json,
    body: JSON.stringify({ event: "signup", traits: { email: form.email, full_name: form.full_name } }),
  });

  // Ad pixel: hashed email and phone in the query string (still personal data).
  const em = await sha256Hex(form.email.trim().toLowerCase());
  const ph = await sha256Hex(phoneDigits);
  await send(`https://collect.pixel-tracker.test/p?ev=Lead&em=${em}&ph=${ph}`);

  // Legacy ad server over plain HTTP, with the email inside a nested page URL.
  const page = `https://shop.example/welcome?email=${encodeURIComponent(form.email)}`;
  await send(`http://ads.legacy-ads.test/i.gif?ref=${encodeURIComponent(page)}`);

  // Session replay vendor: Base64-wrapped form snapshot including health data.
  const snapshot = btoa(JSON.stringify({ form: { kvnr: form.kvnr, diagnosis: form.diagnosis } }));
  await send("https://rec.session-cam.test/v2/events", {
    method: "POST",
    headers: { "Content-Type": "text/plain" },
    body: snapshot,
  });

  // Map widget: precise coordinates in the URL.
  await send("https://maps.geo-widgets.test/tiles?lat=52.520008&lng=13.404954&z=17");

  // Payment processor: IBAN and email, approved in the config as a contracted processor.
  await send("https://api.payments-processor.test/v1/mandates", {
    method: "POST",
    headers: json,
    body: JSON.stringify({ iban: form.iban, email: form.email }),
  });

  document.getElementById("status").textContent = "Account created (demo).";
});
