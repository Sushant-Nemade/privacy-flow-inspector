import { readFileSync, writeFileSync } from "node:fs";
import { test as base } from "@playwright/test";

type SentMessage = { type: "send"; time: number; opcode: 1 | 2; data: string };
type Socket = { url: string; started: string; messages: SentMessage[] };

export type PrivacyOptions = {
  /** Forward WebSocket traffic to the real server. Set false when the test mocks the server. */
  connectWebSockets: boolean;
};

/**
 * Records one HAR per test at `<test output dir>/network.har` with request bodies embedded.
 * Playwright does not write WebSocket messages into HAR files, so messages the page sends are
 * captured through routeWebSocket and added in Chrome DevTools' `_webSocketMessages` format.
 */
export const test = base.extend<PrivacyOptions & { harPath: string }>({
  connectWebSockets: [true, { option: true }],
  harPath: async ({}, use, testInfo) => {
    await use(testInfo.outputPath("network.har"));
  },
  context: async ({ browser, harPath, connectWebSockets }, use) => {
    const sockets: Socket[] = [];
    const context = await browser.newContext({ recordHar: { path: harPath, content: "embed" } });
    await context.routeWebSocket(/^wss?:\/\//, (ws) => {
      const socket: Socket = { url: ws.url(), started: new Date().toISOString(), messages: [] };
      sockets.push(socket);
      const server = connectWebSockets ? ws.connectToServer() : undefined;
      ws.onMessage((message) => {
        const binary = typeof message !== "string";
        socket.messages.push({
          type: "send",
          time: Date.now() / 1000,
          opcode: binary ? 2 : 1,
          data: binary ? Buffer.from(message).toString("base64") : message,
        });
        server?.send(message);
      });
      server?.onMessage((message) => ws.send(message));
    });
    await use(context);
    await context.close();
    addWebSocketMessages(harPath, sockets);
  },
});

function addWebSocketMessages(harPath: string, sockets: Socket[]): void {
  if (sockets.length === 0) return;
  const har = JSON.parse(readFileSync(harPath, "utf-8"));
  const entries: Array<Record<string, any>> = har.log.entries;
  for (const socket of sockets) {
    const existing = entries.find((entry) => entry.request?.url === socket.url && !entry._webSocketMessages);
    if (existing) {
      existing._resourceType = "websocket";
      existing._webSocketMessages = socket.messages;
      continue;
    }
    entries.push({
      startedDateTime: socket.started,
      time: 0,
      request: {
        method: "GET",
        url: socket.url,
        httpVersion: "HTTP/1.1",
        headers: [],
        queryString: [],
        cookies: [],
        headersSize: -1,
        bodySize: 0,
      },
      response: {
        status: 101,
        statusText: "Switching Protocols",
        httpVersion: "HTTP/1.1",
        headers: [],
        cookies: [],
        content: { size: 0, mimeType: "x-unknown" },
        redirectURL: "",
        headersSize: -1,
        bodySize: 0,
      },
      cache: {},
      timings: { send: 0, wait: 0, receive: 0 },
      _resourceType: "websocket",
      _webSocketMessages: socket.messages,
    });
  }
  writeFileSync(harPath, JSON.stringify(har, null, 2));
}

export { expect } from "@playwright/test";
