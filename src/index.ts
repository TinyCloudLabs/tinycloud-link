import * as acme from "acme-client";
import { serve } from "@hono/node-server";
import { DnsO1AcmeIssuer } from "./acme.js";
import { CloudflareDnsProvider } from "./dns/cloudflare.js";
import { PostgresAcmeAccountStore, PostgresCertRateLimiter, PostgresNameStore } from "./postgres.js";
import { createServer } from "./server.js";

const port = Number.parseInt(process.env.PORT ?? "3000", 10);
const databaseUrl = process.env.DATABASE_URL;
const cloudflareApiToken = process.env.CLOUDFLARE_API_TOKEN;
const cloudflareZoneId = process.env.CLOUDFLARE_ZONE_ID;
const acmeEmail = process.env.ACME_EMAIL;
const acmeDirectory =
  process.env.ACME_DIRECTORY ?? "https://acme-staging-v02.api.letsencrypt.org/directory";

if (!databaseUrl) throw new Error("DATABASE_URL is required");
if (!cloudflareApiToken) throw new Error("CLOUDFLARE_API_TOKEN is required");
if (!cloudflareZoneId) throw new Error("CLOUDFLARE_ZONE_ID is required");
if (!acmeEmail) throw new Error("ACME_EMAIL is required");

const nameStore = new PostgresNameStore(databaseUrl);
const acmeAccountStore = new PostgresAcmeAccountStore(databaseUrl);
const rateLimiter = new PostgresCertRateLimiter(databaseUrl);

await nameStore.init();
await acmeAccountStore.init?.();
await rateLimiter.init?.();

let accountKeyPem = await acmeAccountStore.getAccountKey();
if (!accountKeyPem) {
  const key = await acme.crypto.createPrivateKey();
  accountKeyPem = key.toString();
  await acmeAccountStore.saveAccountKey(accountKeyPem);
}

const dnsProvider = new CloudflareDnsProvider({
  apiToken: cloudflareApiToken,
  zoneId: cloudflareZoneId,
});

const acmeIssuer = new DnsO1AcmeIssuer({
  directoryUrl: acmeDirectory,
  accountKeyPem,
  email: acmeEmail,
  dnsProvider,
  challengePropagationDelayMs: 5000,
});

const app = createServer({
  nameStore,
  dnsProvider,
  acmeIssuer,
  rateLimiter,
  attestationDocument: process.env.ATTESTATION_DOCUMENT,
});

serve({ fetch: app.fetch, port });
console.log(`tinycloud-link listening on :${port}`);

const shutdown = async () => {
  await nameStore.close();
  await acmeAccountStore.close();
  await rateLimiter.close();
  process.exit(0);
};

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
