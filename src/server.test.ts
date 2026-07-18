import assert from "node:assert/strict";
import test from "node:test";
import type { Hono } from "hono";
import { DnsO1AcmeIssuer } from "./acme.js";
import { InMemoryDnsProvider } from "./dns/memory.js";
import {
  canonicalCertRequestPayload,
  canonicalClaimPayload,
  canonicalDeletePayload,
  fqdnForName,
} from "./names.js";
import { createServer } from "./server.js";
import { createTestCsr } from "./test-support/csr.js";
import { FakeAcmeClient } from "./test-support/fake-acme-client.js";
import { InMemoryCertRateLimiter, InMemoryNameStore } from "./test-support/memory-stores.js";
import { didKeySigner, type Signer } from "./test-support/signing.js";

function buildApp(options: { nameUpdateRateLimitPerDay?: number } = {}) {
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
  });
  const app = createServer({
    nameStore,
    dnsProvider,
    acmeIssuer,
    rateLimiter,
    certRateLimitPerDay: 2,
    nameUpdateRateLimitPerDay: options.nameUpdateRateLimitPerDay,
  });
  return { app, dnsProvider };
}

async function claim(
  app: Hono,
  name: string,
  signer: Signer,
  lanIps: string[],
  sequence: number
): Promise<Response> {
  const unsigned = {
    version: 1 as const,
    action: "claim" as const,
    name,
    subject: signer.subject,
    lanIps,
    sequence,
  };
  const signature = await signer.sign(canonicalClaimPayload(unsigned));
  return app.request(`/v1/names/${name}`, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...unsigned, signature }),
  });
}

test("health check", async () => {
  const { app } = buildApp();
  const res = await app.request("/health");
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true });
});

test("attestation is 501 until configured", async () => {
  const { app } = buildApp();
  const res = await app.request("/attestation");
  assert.equal(res.status, 501);
});

test("claims a new name and publishes address records", async () => {
  const { app, dnsProvider } = buildApp();
  const signer = didKeySigner(21);
  const res = await claim(app, "livingroom", signer, ["192.168.1.5"], 1);
  assert.equal(res.status, 201);
  const body = (await res.json()) as { status: string };
  assert.equal(body.status, "created");
  assert.deepEqual(dnsProvider.addressRecords.get(fqdnForName("livingroom")), ["192.168.1.5"]);
});

test("GET returns the public record", async () => {
  const { app } = buildApp();
  const signer = didKeySigner(22);
  await claim(app, "kitchen", signer, ["192.168.1.6"], 1);
  const res = await app.request("/v1/names/kitchen");
  assert.equal(res.status, 200);
  const body = (await res.json()) as { subject: string; lanIps: string[] };
  assert.equal(body.subject, signer.subject);
  assert.deepEqual(body.lanIps, ["192.168.1.6"]);
});

test("GET 404s for an unclaimed name", async () => {
  const { app } = buildApp();
  const res = await app.request("/v1/names/doesnotexist");
  assert.equal(res.status, 404);
});

test("same subject can update lanIps with a higher sequence", async () => {
  const { app, dnsProvider } = buildApp();
  const signer = didKeySigner(23);
  await claim(app, "office", signer, ["192.168.1.7"], 1);
  const res = await claim(app, "office", signer, ["192.168.1.77"], 2);
  assert.equal(res.status, 200);
  assert.deepEqual(dnsProvider.addressRecords.get(fqdnForName("office")), ["192.168.1.77"]);
});

test("enforces the daily name update rate limit per name", async () => {
  const { app, dnsProvider } = buildApp({ nameUpdateRateLimitPerDay: 2 });
  const signer = didKeySigner(38);
  const first = await claim(app, "hammered", signer, ["192.168.1.19"], 1);
  const second = await claim(app, "hammered", signer, ["192.168.1.20"], 2);
  const third = await claim(app, "hammered", signer, ["192.168.1.21"], 3);
  assert.equal(first.status, 201);
  assert.equal(second.status, 200);
  assert.equal(third.status, 429);
  // The DNS provider was not touched by the rate-limited update.
  assert.deepEqual(dnsProvider.addressRecords.get(fqdnForName("hammered")), ["192.168.1.20"]);
});

test("rejects a stale sequence update", async () => {
  const { app } = buildApp();
  const signer = didKeySigner(24);
  await claim(app, "garage", signer, ["192.168.1.8"], 5);
  const res = await claim(app, "garage", signer, ["192.168.1.9"], 5);
  assert.equal(res.status, 409);
});

test("rejects a claim from a different subject once the name is owned (steal attempt)", async () => {
  const { app } = buildApp();
  const owner = didKeySigner(25);
  const attacker = didKeySigner(26);
  await claim(app, "attic", owner, ["192.168.1.10"], 1);
  const res = await claim(app, "attic", attacker, ["192.168.1.11"], 2);
  assert.equal(res.status, 409);
});

test("rejects public IP addresses", async () => {
  const { app } = buildApp();
  const signer = didKeySigner(27);
  const res = await claim(app, "basement", signer, ["8.8.8.8"], 1);
  assert.equal(res.status, 400);
});

test("rejects a claim signed by the wrong key", async () => {
  const { app } = buildApp();
  const signer = didKeySigner(28);
  const other = didKeySigner(29);
  const unsigned = {
    version: 1 as const,
    action: "claim" as const,
    name: "forged",
    subject: signer.subject,
    lanIps: ["192.168.1.12"],
    sequence: 1,
  };
  const signature = await other.sign(canonicalClaimPayload(unsigned));
  const res = await app.request("/v1/names/forged", {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...unsigned, signature }),
  });
  assert.equal(res.status, 401);
});

test("owner can delete a claimed name and its DNS records", async () => {
  const { app, dnsProvider } = buildApp();
  const signer = didKeySigner(30);
  await claim(app, "pantry", signer, ["192.168.1.13"], 1);
  const unsigned = {
    version: 1 as const,
    action: "delete" as const,
    name: "pantry",
    subject: signer.subject,
    sequence: 2,
  };
  const signature = await signer.sign(canonicalDeletePayload(unsigned));
  const res = await app.request("/v1/names/pantry", {
    method: "DELETE",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...unsigned, signature }),
  });
  assert.equal(res.status, 200);
  assert.equal(dnsProvider.addressRecords.has(fqdnForName("pantry")), false);
  const getRes = await app.request("/v1/names/pantry");
  assert.equal(getRes.status, 404);
});

test("delete is rejected for a non-owning subject", async () => {
  const { app } = buildApp();
  const owner = didKeySigner(31);
  const attacker = didKeySigner(32);
  await claim(app, "cellar", owner, ["192.168.1.14"], 1);
  const unsigned = {
    version: 1 as const,
    action: "delete" as const,
    name: "cellar",
    subject: attacker.subject,
    sequence: 2,
  };
  const signature = await attacker.sign(canonicalDeletePayload(unsigned));
  const res = await app.request("/v1/names/cellar", {
    method: "DELETE",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...unsigned, signature }),
  });
  assert.equal(res.status, 403);
});

test("issues a certificate for an owned name via DNS-01", async () => {
  const { app } = buildApp();
  const signer = didKeySigner(33);
  await claim(app, "certnode", signer, ["192.168.1.15"], 1);
  const domain = fqdnForName("certnode");
  const csr = createTestCsr(domain);
  const unsigned = {
    version: 1 as const,
    action: "cert" as const,
    name: "certnode",
    subject: signer.subject,
    csr,
    sequence: 2,
  };
  const signature = await signer.sign(canonicalCertRequestPayload(unsigned));
  const res = await app.request("/v1/certs/certnode", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...unsigned, signature }),
  });
  assert.equal(res.status, 200);
  const body = (await res.json()) as { certChainPem: string; notAfter: string };
  assert.match(body.certChainPem, /BEGIN CERTIFICATE/);
  assert.equal(Number.isNaN(Date.parse(body.notAfter)), false);
});

test("rejects a cert request whose CSR domain does not match the claimed name", async () => {
  const { app } = buildApp();
  const signer = didKeySigner(34);
  await claim(app, "mismatch", signer, ["192.168.1.16"], 1);
  const csr = createTestCsr(fqdnForName("someoneelse"));
  const unsigned = {
    version: 1 as const,
    action: "cert" as const,
    name: "mismatch",
    subject: signer.subject,
    csr,
    sequence: 2,
  };
  const signature = await signer.sign(canonicalCertRequestPayload(unsigned));
  const res = await app.request("/v1/certs/mismatch", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...unsigned, signature }),
  });
  assert.equal(res.status, 400);
});

test("rejects a cert request for a name not owned by the subject", async () => {
  const { app } = buildApp();
  const owner = didKeySigner(35);
  const attacker = didKeySigner(36);
  await claim(app, "notyours", owner, ["192.168.1.17"], 1);
  const domain = fqdnForName("notyours");
  const csr = createTestCsr(domain);
  const unsigned = {
    version: 1 as const,
    action: "cert" as const,
    name: "notyours",
    subject: attacker.subject,
    csr,
    sequence: 2,
  };
  const signature = await attacker.sign(canonicalCertRequestPayload(unsigned));
  const res = await app.request("/v1/certs/notyours", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...unsigned, signature }),
  });
  assert.equal(res.status, 403);
});

test("enforces the daily certificate rate limit per name", async () => {
  const { app } = buildApp(); // certRateLimitPerDay: 2
  const signer = didKeySigner(37);
  await claim(app, "ratelimited", signer, ["192.168.1.18"], 1);
  const domain = fqdnForName("ratelimited");

  async function requestCert(sequence: number): Promise<Response> {
    const csr = createTestCsr(domain);
    const unsigned = {
      version: 1 as const,
      action: "cert" as const,
      name: "ratelimited",
      subject: signer.subject,
      csr,
      sequence,
    };
    const signature = await signer.sign(canonicalCertRequestPayload(unsigned));
    return app.request("/v1/certs/ratelimited", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...unsigned, signature }),
    });
  }

  const first = await requestCert(2);
  const second = await requestCert(3);
  const third = await requestCert(4);
  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(third.status, 429);
});
