import { Hono } from "hono";
import type { Context } from "hono";
import type { AcmeIssuer } from "./acme.js";
import type { DnsProvider } from "./dns/provider.js";
import {
  NameError,
  assertCsrMatchesDomain,
  fqdnForName,
  validateCertRequest,
  validateNameClaim,
  validateNameDelete,
  verifyCertRequest,
  verifyNameClaim,
  verifyNameDelete,
} from "./names.js";
import type { CertRateLimiter, NameStore } from "./storage.js";
import { DEFAULT_API_HOSTNAME, createTunnelMiddleware } from "./tunnel/host-router.js";
import type { TunnelRegistry } from "./tunnel/registry.js";

const DAY_MS = 24 * 60 * 60 * 1000;

export interface ServerConfig {
  nameStore: NameStore;
  dnsProvider: DnsProvider;
  acmeIssuer: AcmeIssuer;
  rateLimiter: CertRateLimiter;
  attestationDocument?: string;
  certRateLimitPerDay?: number;
  nameUpdateRateLimitPerDay?: number;
  /** When set, requests whose Host header names a claimed tunnel (rather than `apiHostname`) are proxied through it. Omit to leave tunnel routing disabled entirely (no behavior change to the /v1 API). */
  tunnelRegistry?: TunnelRegistry;
  /** The control-plane API's own hostname, exempted from tunnel routing. Defaults to "api.tinycloud.link". */
  apiHostname?: string;
}

// Prefixes name-update entries so they share the cert rate-limit store without
// colliding with cert issuances (claimed names can never contain a colon).
function nameUpdateRateLimitKey(name: string): string {
  return `name-update:${name}`;
}

export function createServer(config: ServerConfig): Hono {
  const app = new Hono();
  const rateLimit = config.certRateLimitPerDay ?? 5;
  const nameUpdateRateLimit = config.nameUpdateRateLimitPerDay ?? 30;

  if (config.tunnelRegistry) {
    app.use(
      "*",
      createTunnelMiddleware(config.tunnelRegistry, {
        apiHostname: config.apiHostname ?? DEFAULT_API_HOSTNAME,
      })
    );
  }

  app.get("/health", (c) => c.json({ ok: true }));

  app.get("/attestation", (c) => {
    if (!config.attestationDocument) {
      return c.json({ error: "attestation not configured" }, 501);
    }
    return c.json({ document: config.attestationDocument });
  });

  app.get("/v1/names/:name", async (c) => {
    const name = decodeURIComponent(c.req.param("name")).toLowerCase();
    const record = await config.nameStore.get(name);
    if (!record) {
      return c.json({ error: "name not found" }, 404);
    }
    return c.json({
      name: record.name,
      subject: record.subject,
      lanIps: record.lanIps,
      updatedAt: record.updatedAt,
    });
  });

  app.put("/v1/names/:name", async (c) => {
    const urlName = decodeURIComponent(c.req.param("name")).toLowerCase();
    let claim;
    try {
      claim = validateNameClaim(await c.req.json());
    } catch (error) {
      return validationError(c, error);
    }
    if (claim.name !== urlName) {
      return c.json({ error: "body.name must match URL name" }, 400);
    }

    const existing = await config.nameStore.get(claim.name);
    if (existing && existing.subject !== claim.subject) {
      return c.json({ error: "name already claimed by a different subject" }, 409);
    }

    let verified = false;
    try {
      verified = await verifyNameClaim(claim);
    } catch (error) {
      return validationError(c, error);
    }
    if (!verified) {
      return c.json({ error: "invalid record signature" }, 401);
    }

    const recentUpdates = await config.rateLimiter.countRecentIssuances(
      nameUpdateRateLimitKey(claim.name),
      DAY_MS
    );
    if (recentUpdates >= nameUpdateRateLimit) {
      return c.json({ error: "name update rate limit exceeded for this name" }, 429);
    }

    const status = await config.nameStore.put({
      name: claim.name,
      subject: claim.subject,
      lanIps: claim.lanIps,
      sequence: claim.sequence,
      updatedAt: new Date().toISOString(),
    });
    if (status === "stale") {
      return c.json({ error: "stale record sequence" }, 409);
    }

    await config.dnsProvider.upsertAddressRecords(fqdnForName(claim.name), claim.lanIps);
    await config.rateLimiter.recordIssuance(nameUpdateRateLimitKey(claim.name));

    return c.json(
      { name: claim.name, subject: claim.subject, lanIps: claim.lanIps, status },
      status === "created" ? 201 : 200
    );
  });

  app.delete("/v1/names/:name", async (c) => {
    const urlName = decodeURIComponent(c.req.param("name")).toLowerCase();
    let del;
    try {
      del = validateNameDelete(await c.req.json());
    } catch (error) {
      return validationError(c, error);
    }
    if (del.name !== urlName) {
      return c.json({ error: "body.name must match URL name" }, 400);
    }

    const existing = await config.nameStore.get(del.name);
    if (!existing) {
      return c.json({ error: "name not found" }, 404);
    }
    if (existing.subject !== del.subject) {
      return c.json({ error: "subject does not own this name" }, 403);
    }

    let verified = false;
    try {
      verified = await verifyNameDelete(del);
    } catch (error) {
      return validationError(c, error);
    }
    if (!verified) {
      return c.json({ error: "invalid record signature" }, 401);
    }

    const status = await config.nameStore.delete(del.name, del.sequence);
    if (status === "stale") {
      return c.json({ error: "stale record sequence" }, 409);
    }
    if (status === "not_found") {
      return c.json({ error: "name not found" }, 404);
    }

    await config.dnsProvider.deleteAddressRecords(fqdnForName(del.name));

    return c.json({ status: "deleted" });
  });

  app.post("/v1/certs/:name", async (c) => {
    const urlName = decodeURIComponent(c.req.param("name")).toLowerCase();
    let request;
    try {
      request = validateCertRequest(await c.req.json());
    } catch (error) {
      return validationError(c, error);
    }
    if (request.name !== urlName) {
      return c.json({ error: "body.name must match URL name" }, 400);
    }

    const existing = await config.nameStore.get(request.name);
    if (!existing) {
      return c.json({ error: "name not found" }, 404);
    }
    if (existing.subject !== request.subject) {
      return c.json({ error: "subject does not own this name" }, 403);
    }
    if (existing.sequence >= request.sequence) {
      return c.json({ error: "stale record sequence" }, 409);
    }

    let verified = false;
    try {
      verified = await verifyCertRequest(request);
    } catch (error) {
      return validationError(c, error);
    }
    if (!verified) {
      return c.json({ error: "invalid record signature" }, 401);
    }

    const expectedDomain = fqdnForName(request.name);
    try {
      assertCsrMatchesDomain(request.csr, expectedDomain);
    } catch (error) {
      return validationError(c, error);
    }

    const recentIssuances = await config.rateLimiter.countRecentIssuances(request.name, DAY_MS);
    if (recentIssuances >= rateLimit) {
      return c.json({ error: "certificate rate limit exceeded for this name" }, 429);
    }

    // Bump the stored sequence before the ACME round trip so a replayed/concurrent
    // request against the same sequence cannot trigger a second order.
    const bumpStatus = await config.nameStore.put({
      ...existing,
      sequence: request.sequence,
      updatedAt: new Date().toISOString(),
    });
    if (bumpStatus === "stale") {
      return c.json({ error: "stale record sequence" }, 409);
    }

    const result = await config.acmeIssuer.issueCertificate({
      csrPem: request.csr,
      domain: expectedDomain,
    });
    await config.rateLimiter.recordIssuance(request.name);

    return c.json({ certChainPem: result.certChainPem, notAfter: result.notAfter });
  });

  return app;
}

function validationError(c: Context, error: unknown) {
  if (error instanceof NameError) {
    return c.json({ error: error.message }, 400);
  }
  return c.json({ error: "invalid request" }, 400);
}
