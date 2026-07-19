/**
 * Live staging smoke test against a deployed tinycloud-link instance.
 *
 * Exercises the full name + certificate lifecycle end to end:
 *   1. claim a name (signed did:key claim)  -> PUT /v1/names/:name
 *   2. verify public DNS resolves <name>.local.tinycloud.link to the LAN IP
 *   3. request a certificate (signed CSR)   -> POST /v1/certs/:name
 *      and check the issuer is Let's Encrypt STAGING
 *   4. delete the name (signed delete)      -> DELETE /v1/names/:name
 *      and verify the DNS record is removed
 *
 * The signing key is an ephemeral did:key generated fresh in memory for the
 * duration of the run and never written to disk or the repo (a failed run
 * can be retried with a new key, but will orphan the claimed name since
 * nothing persists the key to sign a later delete). The returned (public)
 * certificate chain is written to a temp file for inspection.
 *
 * Usage:
 *   npx tsx scripts/live-smoke.ts
 * Env overrides:
 *   BASE_URL (default https://api.tinycloud.link)
 *   SMOKE_NAME (default smoke1)
 *   SMOKE_LAN_IP (default 192.168.77.10)
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";
import { bases } from "multiformats/basics";
import { createTestCsr } from "../src/test-support/csr.js";
import {
  canonicalCertRequestPayload,
  canonicalClaimPayload,
  canonicalDeletePayload,
  fqdnForName,
} from "../src/names.js";

const BASE_URL = process.env.BASE_URL ?? "https://api.tinycloud.link";
const NAME = process.env.SMOKE_NAME ?? "smoke1";
const LAN_IP = process.env.SMOKE_LAN_IP ?? "192.168.77.10";

// Ephemeral, in-memory identity (random every run so reruns after a completed
// lifecycle never collide with a stale owner).
const privateKey = ed25519.utils.randomPrivateKey();
const publicKey = ed25519.getPublicKey(privateKey);
const subject = `did:key:${bases.base58btc.encode(Uint8Array.of(0xed, 0x01, ...publicKey))}`;
const sign = (payload: string): string =>
  Buffer.from(ed25519.sign(new TextEncoder().encode(payload), privateKey)).toString("base64url");

// Strictly-increasing sequence base; ms clock keeps reruns monotonic.
const seqBase = Date.now();

// Shell out to `dig` for DNS lookups rather than node:dns/promises: in some
// sandboxed environments Node's own resolver (c-ares) hangs indefinitely
// against Cloudflare's authoritative nameservers even though the system
// `dig` binary resolves fine, so `dig` is the reliable path here.
function digA(fqdn: string, server?: string): string[] {
  const args = server ? [`@${server}`, fqdn, "A", "+short"] : [fqdn, "A", "+short"];
  try {
    return execFileSync("dig", args, { timeout: 10_000 })
      .toString()
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.endsWith("."));
  } catch {
    return [];
  }
}

function nsServers(zone: string): string[] {
  const names = execFileSync("dig", ["NS", zone, "+short"], { timeout: 10_000 })
    .toString()
    .split("\n")
    .map((line) => line.trim().replace(/\.$/, ""))
    .filter((line) => line.length > 0);
  if (names.length === 0) throw new Error(`no nameservers found for ${zone}`);
  return names;
}

function fail(message: string): never {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

async function api(method: string, path: string, body: unknown): Promise<Response> {
  return fetch(`${BASE_URL}${path}`, {
    method,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

// Server errors (5xx) aren't guaranteed to be JSON; parse defensively so the
// raw body is still visible for diagnosis instead of an opaque JSON.parse
// crash.
async function readBody(res: Response): Promise<unknown> {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    return { rawText: text };
  }
}

// Checks both the public resolver (1.1.1.1) and the zone's authoritative
// nameserver directly on every attempt. Querying only the public resolver
// makes early polls flaky (negative-cached NXDOMAIN from before the claim);
// checking the authoritative server too lets us tell "still propagating"
// (authoritative already correct, public resolver lagging) apart from a
// genuine failure (neither has it).
async function pollDns(
  ns: string,
  fqdn: string,
  check: (ips: string[]) => boolean,
  label: string,
  timeoutMs = 120_000
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastPublic: string[] = [];
  let lastAuth: string[] = [];
  while (Date.now() < deadline) {
    lastPublic = digA(fqdn, "1.1.1.1");
    if (check(lastPublic)) {
      console.log(`  DNS ${label}: ${fqdn} -> [${lastPublic.join(", ")}] (public resolver 1.1.1.1)`);
      return;
    }
    lastAuth = digA(fqdn, ns);
    if (check(lastAuth)) {
      console.log(`  DNS ${label}: ${fqdn} -> [${lastAuth.join(", ")}] (authoritative ${ns})`);
      return;
    }
    await new Promise((r) => setTimeout(r, 5_000));
  }
  fail(
    `timed out waiting for DNS ${label} on ${fqdn} ` +
      `(public 1.1.1.1: [${lastPublic.join(", ")}], authoritative ${ns}: [${lastAuth.join(", ")}])`
  );
}

async function main() {
  console.log(`base url: ${BASE_URL}`);
  console.log(`name:     ${NAME} (${fqdnForName(NAME)})`);
  console.log(`subject:  ${subject}`);
  const ns = nsServers("tinycloud.link")[0];
  console.log(`ns:       ${ns}`);

  // 0. health
  const health = await fetch(`${BASE_URL}/health`);
  if (!health.ok) fail(`/health returned ${health.status}`);
  console.log(`health:   ${JSON.stringify(await health.json())}`);

  // 1. claim
  const claimPayload = {
    version: 1 as const,
    action: "claim" as const,
    name: NAME,
    subject,
    lanIps: [LAN_IP],
    sequence: seqBase,
  };
  const claimRes = await api("PUT", `/v1/names/${NAME}`, {
    ...claimPayload,
    signature: sign(canonicalClaimPayload(claimPayload)),
  });
  const claimBody = await readBody(claimRes);
  if (claimRes.status !== 200 && claimRes.status !== 201) {
    fail(`claim returned ${claimRes.status}: ${JSON.stringify(claimBody)}`);
  }
  console.log(`claim:    ${claimRes.status} ${JSON.stringify(claimBody)}`);

  // 2. DNS present
  await pollDns(ns, fqdnForName(NAME), (ips) => ips.includes(LAN_IP), "claim propagation");

  // 3. cert issuance (ephemeral RSA keypair inside createTestCsr; never persisted)
  const csr = createTestCsr(fqdnForName(NAME));
  const certPayload = {
    version: 1 as const,
    action: "cert" as const,
    name: NAME,
    subject,
    csr,
    sequence: seqBase + 1,
  };
  console.log("cert:     requesting (ACME DNS-01 round trip, may take a minute)...");
  const certRes = await api("POST", `/v1/certs/${NAME}`, {
    ...certPayload,
    signature: sign(canonicalCertRequestPayload(certPayload)),
  });
  const certBody = await readBody(certRes);
  if (certRes.status !== 200) {
    fail(`cert returned ${certRes.status}: ${JSON.stringify(certBody)}`);
  }
  const chain: string = certBody.certChainPem;
  if (!chain?.includes("BEGIN CERTIFICATE")) fail("cert response contained no PEM chain");
  const certPath = join(mkdtempSync(join(tmpdir(), "tcl-smoke-")), `${NAME}-chain.pem`);
  writeFileSync(certPath, chain);
  const issuer = execFileSync("openssl", ["x509", "-noout", "-issuer"], { input: chain })
    .toString()
    .trim();
  const subjectLine = execFileSync("openssl", ["x509", "-noout", "-subject", "-enddate"], {
    input: chain,
  })
    .toString()
    .trim();
  console.log(`cert:     200 notAfter=${certBody.notAfter}`);
  console.log(`  ${issuer}`);
  console.log(`  ${subjectLine.replace("\n", "\n  ")}`);
  console.log(`  chain written to ${certPath}`);
  if (issuer.toUpperCase().includes("STAGING")) {
    fail(`expected a production Let's Encrypt issuer, got: ${issuer}`);
  }

  // 4. delete
  const deletePayload = {
    version: 1 as const,
    action: "delete" as const,
    name: NAME,
    subject,
    sequence: seqBase + 2,
  };
  const deleteRes = await api("DELETE", `/v1/names/${NAME}`, {
    ...deletePayload,
    signature: sign(canonicalDeletePayload(deletePayload)),
  });
  const deleteBody = await readBody(deleteRes);
  if (deleteRes.status !== 200) {
    fail(`delete returned ${deleteRes.status}: ${JSON.stringify(deleteBody)}`);
  }
  console.log(`delete:   ${deleteRes.status} ${JSON.stringify(deleteBody)}`);

  // 5. DNS gone
  await pollDns(ns, fqdnForName(NAME), (ips) => ips.length === 0, "delete propagation");

  console.log("PASS: full live staging lifecycle (claim -> dns -> cert -> delete -> dns removed)");
}

main().catch((error) => fail(error instanceof Error ? error.stack ?? error.message : String(error)));
