import assert from "node:assert/strict";
import test from "node:test";
import type { AddressInfo } from "node:net";
import { serve } from "@hono/node-server";
import type { Hono } from "hono";
import WebSocket from "ws";
import { DnsO1AcmeIssuer } from "./acme.js";
import { InMemoryDnsProvider } from "./dns/memory.js";
import { canonicalClaimPayload, canonicalTunnelAuthPayload } from "./names.js";
import { createServer } from "./server.js";
import { FakeAcmeClient } from "./test-support/fake-acme-client.js";
import { InMemoryCertRateLimiter, InMemoryNameStore } from "./test-support/memory-stores.js";
import { didKeySigner, type Signer } from "./test-support/signing.js";
import { MAX_FRAME_PAYLOAD_BYTES, encodeFrame, parseFrame } from "./tunnel/protocol.js";
import { SUPERSEDED_CLOSE_CODE, TunnelRegistry } from "./tunnel/registry.js";
import {
  CLOSE_INVALID_SIGNATURE,
  CLOSE_NAME_NOT_CLAIMED,
  CLOSE_NOT_OWNER,
  CLOSE_STALE_SEQUENCE,
  type AttachTunnelUpgradeOptions,
  attachTunnelUpgrade,
} from "./tunnel/upgrade.js";

const API_HOSTNAME = "api.tinycloud.link";

type UpgradeOverrides = Partial<Omit<AttachTunnelUpgradeOptions, "registry" | "nameStore">>;

async function startTunnelServer(
  upgradeOverrides: UpgradeOverrides = {},
  tunnelMaxBodyBytes?: number
) {
  const nameStore = new InMemoryNameStore();
  const dnsProvider = new InMemoryDnsProvider();
  const rateLimiter = new InMemoryCertRateLimiter();
  const fakeAcmeClient = new FakeAcmeClient();
  const acmeIssuer = new DnsO1AcmeIssuer({
    directoryUrl: "https://fake-acme.test/directory",
    accountKeyPem: "fake-account-key",
    email: "ops@tinycloud.xyz",
    dnsProvider,
    clientFactory: () => fakeAcmeClient,
    checkPropagation: async () => {},
  });
  const registry = new TunnelRegistry();
  const app = createServer({
    nameStore,
    dnsProvider,
    acmeIssuer,
    rateLimiter,
    tunnelRegistry: registry,
    apiHostname: API_HOSTNAME,
    tunnelMaxBodyBytes,
  });

  const server = await new Promise<ReturnType<typeof serve>>((resolve) => {
    const s = serve({ fetch: app.fetch, port: 0 }, () => resolve(s));
  });
  attachTunnelUpgrade(server, { registry, nameStore, authTimeoutMs: 1000, ...upgradeOverrides });
  const port = (server.address() as AddressInfo).port;

  const sockets = new Set<WebSocket>();

  return {
    app,
    nameStore,
    registry,
    port,
    /** Opens a tunnel WebSocket client and tracks it so `close()` can force-terminate any left open by a failing test. */
    connect(name: string): WebSocket {
      const ws = new WebSocket(`ws://127.0.0.1:${port}/v1/tunnel/${name}`);
      sockets.add(ws);
      ws.once("close", () => sockets.delete(ws));
      return ws;
    },
    async close(): Promise<void> {
      for (const ws of sockets) {
        ws.terminate();
      }
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

type TunnelTestHarness = Awaited<ReturnType<typeof startTunnelServer>>;

/** Runs a test body against a fresh harness, guaranteeing the server (and any sockets it opened) is torn down even if the body throws. */
async function withHarness(
  body: (harness: TunnelTestHarness) => Promise<void>,
  upgradeOverrides: UpgradeOverrides = {},
  tunnelMaxBodyBytes?: number
): Promise<void> {
  const harness = await startTunnelServer(upgradeOverrides, tunnelMaxBodyBytes);
  try {
    await body(harness);
  } finally {
    await harness.close();
  }
}

/** Resolves true if the WS connection is rejected (errors or closes) before ever reaching 'open', false if it opens. Used to assert an upgrade-time limiter dropped the connection pre-handshake. */
function connectionWasRejected(ws: WebSocket): Promise<boolean> {
  return new Promise((resolve) => {
    ws.once("open", () => resolve(false));
    ws.once("error", () => resolve(true));
    ws.once("close", () => resolve(true));
  });
}

async function claim(app: Hono, name: string, signer: Signer, sequence: number): Promise<void> {
  const unsigned = {
    version: 1 as const,
    action: "claim" as const,
    name,
    subject: signer.subject,
    lanIps: ["192.168.1.50"],
    sequence,
  };
  const signature = await signer.sign(canonicalClaimPayload(unsigned));
  const res = await app.request(`/v1/names/${name}`, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...unsigned, signature }),
  });
  assert.equal(res.status, 201);
}

async function sendAuth(ws: WebSocket, signer: Signer, name: string, sequence: number): Promise<void> {
  const unsigned = {
    version: 1 as const,
    action: "tunnel" as const,
    name,
    subject: signer.subject,
    sequence,
  };
  const signature = await signer.sign(canonicalTunnelAuthPayload(unsigned));
  await new Promise<void>((resolve, reject) => {
    ws.once("open", () => {
      ws.send(JSON.stringify({ ...unsigned, signature }));
      resolve();
    });
    ws.once("error", reject);
  });
}

function waitForClose(ws: WebSocket): Promise<{ code: number; reason: string }> {
  return new Promise((resolve) => {
    ws.once("close", (code, reasonBuf) => resolve({ code, reason: reasonBuf.toString() }));
  });
}

function waitForMessage(ws: WebSocket): Promise<unknown> {
  return new Promise((resolve, reject) => {
    ws.once("message", (data) => {
      try {
        resolve(JSON.parse(data.toString()));
      } catch (error) {
        reject(error);
      }
    });
    ws.once("close", (code, reasonBuf) => reject(new Error(`closed before message: ${code} ${reasonBuf}`)));
  });
}

/** A minimal "node" that answers every proxied request with a fixed response, echoing the request body back. */
function runEchoNode(ws: WebSocket): void {
  ws.on("message", (data) => {
    const frame = parseFrame(data.toString());
    if (frame.type !== "requestBody" || !frame.done) return;
    const { id } = frame;
    ws.send(
      encodeFrame({
        type: "response",
        id,
        status: 200,
        headers: [["content-type", "text/plain"]],
      })
    );
    ws.send(encodeFrame({ type: "responseBody", id, chunk: frame.chunk, done: true }));
  });
}

test("tunnel auth is rejected for an unclaimed name", () =>
  withHarness(async (harness) => {
    const signer = didKeySigner(101);
    const ws = harness.connect("ghost");
    await sendAuth(ws, signer, "ghost", 1);
    const { code } = await waitForClose(ws);
    assert.equal(code, CLOSE_NAME_NOT_CLAIMED);
  }));

test("tunnel auth is rejected for a non-owning subject", () =>
  withHarness(async (harness) => {
    const owner = didKeySigner(102);
    const attacker = didKeySigner(103);
    await claim(harness.app, "notyours", owner, 1);

    const ws = harness.connect("notyours");
    await sendAuth(ws, attacker, "notyours", 2);
    const { code } = await waitForClose(ws);
    assert.equal(code, CLOSE_NOT_OWNER);
  }));

test("tunnel auth is rejected when signed by the wrong key", () =>
  withHarness(async (harness) => {
    const owner = didKeySigner(104);
    const forger = didKeySigner(105);
    await claim(harness.app, "forged-tunnel", owner, 1);

    const ws = harness.connect("forged-tunnel");
    const unsigned = {
      version: 1 as const,
      action: "tunnel" as const,
      name: "forged-tunnel",
      subject: owner.subject,
      sequence: 2,
    };
    const signature = await forger.sign(canonicalTunnelAuthPayload(unsigned));
    await new Promise<void>((resolve) => ws.once("open", () => resolve()));
    ws.send(JSON.stringify({ ...unsigned, signature }));
    const { code } = await waitForClose(ws);
    assert.equal(code, CLOSE_INVALID_SIGNATURE);
  }));

test("tunnel auth is rejected for a stale sequence", () =>
  withHarness(async (harness) => {
    const signer = didKeySigner(106);
    await claim(harness.app, "stale-tunnel", signer, 5);

    const ws = harness.connect("stale-tunnel");
    await sendAuth(ws, signer, "stale-tunnel", 5);
    const { code } = await waitForClose(ws);
    assert.equal(code, CLOSE_STALE_SEQUENCE);
  }));

test("valid tunnel auth is acked and bumps the stored sequence", () =>
  withHarness(async (harness) => {
    const signer = didKeySigner(107);
    await claim(harness.app, "goodtunnel", signer, 1);

    const ws = harness.connect("goodtunnel");
    const messagePromise = waitForMessage(ws);
    await sendAuth(ws, signer, "goodtunnel", 2);
    const ack = await messagePromise;
    assert.deepEqual(ack, { type: "ack" });

    const record = await harness.nameStore.get("goodtunnel");
    assert.equal(record?.sequence, 2);
  }));

test("proxies an HTTP request through the tunnel to a mock node and back (framing roundtrip)", () =>
  withHarness(async (harness) => {
    const signer = didKeySigner(108);
    await claim(harness.app, "echonode", signer, 1);

    const ws = harness.connect("echonode");
    const ackPromise = waitForMessage(ws);
    await sendAuth(ws, signer, "echonode", 2);
    await ackPromise;
    runEchoNode(ws);

    const res = await harness.app.request("/hello?x=1", {
      method: "POST",
      headers: { host: "echonode.tinycloud.link", "content-type": "text/plain" },
      body: "ping",
    });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("content-type"), "text/plain");
    assert.equal(await res.text(), "ping");
  }));

test("returns 502 when no tunnel is connected for the requested host", () =>
  withHarness(async (harness) => {
    const res = await harness.app.request("/anything", {
      headers: { host: "notconnected.tinycloud.link" },
    });
    assert.equal(res.status, 502);
  }));

test("requests for the API's own hostname are never proxied through a tunnel", () =>
  withHarness(async (harness) => {
    const res = await harness.app.request("/health", { headers: { host: API_HOSTNAME } });
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true });
  }));

test("newest tunnel connection wins: the older socket is evicted and the new one serves the tunnel", () =>
  withHarness(async (harness) => {
    const signer = didKeySigner(109);
    await claim(harness.app, "handoff", signer, 1);

    const first = harness.connect("handoff");
    const firstAck = waitForMessage(first);
    await sendAuth(first, signer, "handoff", 2);
    await firstAck;

    const firstClosed = waitForClose(first);

    const second = harness.connect("handoff");
    const secondAck = waitForMessage(second);
    await sendAuth(second, signer, "handoff", 3);
    await secondAck;
    runEchoNode(second);

    const { code } = await firstClosed;
    assert.equal(code, SUPERSEDED_CLOSE_CODE);

    // Proves the *second* connection is the one actually serving the tunnel now.
    const res = await harness.app.request("/still-alive", {
      headers: { host: "handoff.tinycloud.link" },
    });
    assert.equal(res.status, 200);
  }));

test("request headers travel to the node as an array of [name, value] pairs", () =>
  withHarness(async (harness) => {
    const signer = didKeySigner(111);
    await claim(harness.app, "headerscheck", signer, 1);

    const ws = harness.connect("headerscheck");
    const ackPromise = waitForMessage(ws);
    await sendAuth(ws, signer, "headerscheck", 2);
    await ackPromise;

    let capturedHeaders: Array<[string, string]> | undefined;
    ws.on("message", (data) => {
      const frame = parseFrame(data.toString());
      if (frame.type === "request") {
        capturedHeaders = frame.headers;
      }
    });
    runEchoNode(ws);

    const res = await harness.app.request("/x", {
      headers: { host: "headerscheck.tinycloud.link", "x-custom": "hello" },
    });
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(capturedHeaders));
    assert.ok(capturedHeaders?.some(([key, value]) => key.toLowerCase() === "x-custom" && value === "hello"));
  }));

test("duplicate Set-Cookie response headers survive the tunnel roundtrip", () =>
  withHarness(async (harness) => {
    const signer = didKeySigner(112);
    await claim(harness.app, "cookienode", signer, 1);

    const ws = harness.connect("cookienode");
    const ackPromise = waitForMessage(ws);
    await sendAuth(ws, signer, "cookienode", 2);
    await ackPromise;

    ws.on("message", (data) => {
      const frame = parseFrame(data.toString());
      if (frame.type !== "requestBody" || !frame.done) return;
      const { id } = frame;
      ws.send(
        encodeFrame({
          type: "response",
          id,
          status: 200,
          headers: [
            ["set-cookie", "a=1"],
            ["set-cookie", "b=2"],
          ],
        })
      );
      ws.send(encodeFrame({ type: "responseBody", id, chunk: "", done: true }));
    });

    const res = await harness.app.request("/set-cookies", {
      headers: { host: "cookienode.tinycloud.link" },
    });
    assert.equal(res.status, 200);
    assert.deepEqual(res.headers.getSetCookie(), ["a=1", "b=2"]);
  }));

test("a request body larger than one body-frame chunk is split across multiple requestBody frames and reassembles correctly", () =>
  withHarness(async (harness) => {
    const signer = didKeySigner(113);
    await claim(harness.app, "bigbody", signer, 1);

    const ws = harness.connect("bigbody");
    const ackPromise = waitForMessage(ws);
    await sendAuth(ws, signer, "bigbody", 2);
    await ackPromise;

    // Larger than protocol.ts's BODY_CHUNK_BYTES (256KB), so the relay must
    // split it across at least two requestBody frames.
    const bigBody = "x".repeat(300 * 1024);

    let requestBodyFrameCount = 0;
    const chunks: string[] = [];
    ws.on("message", (data) => {
      const frame = parseFrame(data.toString());
      if (frame.type !== "requestBody") return;
      requestBodyFrameCount += 1;
      chunks.push(frame.chunk);
      if (!frame.done) return;
      const id = frame.id;
      const body = Buffer.concat(chunks.map((c) => Buffer.from(c, "base64"))).toString("utf8");
      ws.send(encodeFrame({ type: "response", id, status: 200, headers: [["content-type", "text/plain"]] }));
      ws.send(encodeFrame({ type: "responseBody", id, chunk: Buffer.from(body).toString("base64"), done: true }));
    });

    const res = await harness.app.request("/upload", {
      method: "POST",
      headers: { host: "bigbody.tinycloud.link" },
      body: bigBody,
    });
    assert.equal(res.status, 200);
    assert.equal(await res.text(), bigBody);
    assert.ok(requestBodyFrameCount > 1, `expected multiple requestBody frames, got ${requestBodyFrameCount}`);
  }));

test("a request body over the configured limit is rejected with 413 before reaching the tunnel", () =>
  withHarness(
    async (harness) => {
      const signer = didKeySigner(114);
      await claim(harness.app, "toobig", signer, 1);

      const ws = harness.connect("toobig");
      const ackPromise = waitForMessage(ws);
      await sendAuth(ws, signer, "toobig", 2);
      await ackPromise;
      runEchoNode(ws);

      const res = await harness.app.request("/upload", {
        method: "POST",
        headers: { host: "toobig.tinycloud.link" },
        body: "x".repeat(200),
      });
      assert.equal(res.status, 413);
    },
    {},
    100 // TUNNEL_MAX_BODY_BYTES override for this test
  ));

test("a response body over the configured limit is aborted with 502 and the node is told via an error frame", () =>
  withHarness(
    async (harness) => {
      const signer = didKeySigner(115);
      await claim(harness.app, "hugeresponse", signer, 1);

      const ws = harness.connect("hugeresponse");
      const ackPromise = waitForMessage(ws);
      await sendAuth(ws, signer, "hugeresponse", 2);
      await ackPromise;

      let sawErrorFrame = false;
      ws.on("message", (data) => {
        const frame = parseFrame(data.toString());
        if (frame.type === "error") {
          sawErrorFrame = true;
          return;
        }
        if (frame.type !== "requestBody" || !frame.done) return;
        const { id } = frame;
        ws.send(encodeFrame({ type: "response", id, status: 200, headers: [] }));
        // Stream a body well past the 100-byte test limit.
        ws.send(encodeFrame({ type: "responseBody", id, chunk: Buffer.from("x".repeat(200)).toString("base64"), done: false }));
        ws.send(encodeFrame({ type: "responseBody", id, chunk: "", done: true }));
      });

      const res = await harness.app.request("/download", {
        headers: { host: "hugeresponse.tinycloud.link" },
      });
      assert.equal(res.status, 502);
      // Give the node's message handler a tick to observe the error frame the relay sent back.
      await new Promise((resolve) => setTimeout(resolve, 50));
      assert.equal(sawErrorFrame, true);
    },
    {},
    100 // TUNNEL_MAX_BODY_BYTES override for this test
  ));

test("the WebSocketServer enforces a max frame payload: an oversized single frame from the node closes the tunnel", () =>
  withHarness(async (harness) => {
    const signer = didKeySigner(116);
    await claim(harness.app, "oversizedframe", signer, 1);

    const ws = harness.connect("oversizedframe");
    const ackPromise = waitForMessage(ws);
    await sendAuth(ws, signer, "oversizedframe", 2);
    await ackPromise;

    const closed = waitForClose(ws);
    const oversizedChunk = "a".repeat(MAX_FRAME_PAYLOAD_BYTES + 1024);
    ws.send(encodeFrame({ type: "responseBody", id: "irrelevant", chunk: oversizedChunk, done: true }));

    const { code } = await closed;
    assert.equal(code, 1009); // RFC 6455 CLOSE_TOO_LARGE
  }));

test("per-IP connection attempts beyond the configured limit are dropped before the WS handshake completes", () =>
  withHarness(
    async (harness) => {
      const signer = didKeySigner(117);
      await claim(harness.app, "ratelimited", signer, 1);

      const first = harness.connect("ratelimited");
      assert.equal(await connectionWasRejected(first), false);
      first.terminate();

      const second = harness.connect("ratelimited");
      assert.equal(await connectionWasRejected(second), false);
      second.terminate();

      // The limit is 2/minute; this third attempt within the window must be dropped pre-handshake.
      const third = harness.connect("ratelimited");
      assert.equal(await connectionWasRejected(third), true);
    },
    { ipConnectionLimitPerMinute: 2 }
  ));

test("per-name churn beyond the configured limit drops further connection attempts for that name", () =>
  withHarness(
    async (harness) => {
      const signer = didKeySigner(118);
      await claim(harness.app, "churny", signer, 1);

      const first = harness.connect("churny");
      assert.equal(await connectionWasRejected(first), false);
      first.terminate();

      const second = harness.connect("churny");
      assert.equal(await connectionWasRejected(second), false);
      second.terminate();

      // The name-churn limit is 2/minute; this third attempt for the same name must be dropped.
      const third = harness.connect("churny");
      assert.equal(await connectionWasRejected(third), true);
    },
    { ipConnectionLimitPerMinute: 100, nameChurnLimitPerMinute: 2 }
  ));

test("a global concurrent-tunnel cap drops further connection attempts once reached", () =>
  withHarness(
    async (harness) => {
      const ownerA = didKeySigner(119);
      const ownerB = didKeySigner(120);
      await claim(harness.app, "capped-a", ownerA, 1);
      await claim(harness.app, "capped-b", ownerB, 1);

      const first = harness.connect("capped-a");
      const firstAck = waitForMessage(first);
      await sendAuth(first, ownerA, "capped-a", 2);
      await firstAck; // registry.size() === 1, at the configured cap.

      const second = harness.connect("capped-b");
      assert.equal(await connectionWasRejected(second), true);
    },
    { maxConcurrentTunnels: 1 }
  ));
