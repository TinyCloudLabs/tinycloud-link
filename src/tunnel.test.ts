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
import { encodeFrame, parseFrame } from "./tunnel/protocol.js";
import { SUPERSEDED_CLOSE_CODE, TunnelRegistry } from "./tunnel/registry.js";
import {
  CLOSE_INVALID_SIGNATURE,
  CLOSE_NAME_NOT_CLAIMED,
  CLOSE_NOT_OWNER,
  CLOSE_STALE_SEQUENCE,
  attachTunnelUpgrade,
} from "./tunnel/upgrade.js";

const API_HOSTNAME = "api.tinycloud.link";

async function startTunnelServer() {
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
  });

  const server = await new Promise<ReturnType<typeof serve>>((resolve) => {
    const s = serve({ fetch: app.fetch, port: 0 }, () => resolve(s));
  });
  attachTunnelUpgrade(server, { registry, nameStore, authTimeoutMs: 1000 });
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
async function withHarness(body: (harness: TunnelTestHarness) => Promise<void>): Promise<void> {
  const harness = await startTunnelServer();
  try {
    await body(harness);
  } finally {
    await harness.close();
  }
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
        headers: { "content-type": "text/plain" },
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
