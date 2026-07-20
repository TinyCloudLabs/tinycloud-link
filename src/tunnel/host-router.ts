import { timingSafeEqual } from "node:crypto";
import type { Context, MiddlewareHandler } from "hono";
import { REMOTE_DOMAIN_SUFFIX } from "../names.js";
import { DEFAULT_MAX_BODY_BYTES } from "./protocol.js";
import { TunnelProxyError, TunnelProxyTimeoutError, proxyRequest } from "./proxy.js";
import type { TunnelRegistry } from "./registry.js";

export const DEFAULT_API_HOSTNAME = "api.tinycloud.link";

// Headers the Cloudflare Worker front (see worker/src/index.ts) adds so the
// relay can recover the client's real Host: TLS for *.tinycloud.link now
// terminates at Cloudflare rather than at dstack-ingress, so every request
// this process sees has already been re-fetched by the Worker against
// `apiHostname`, and the original Host is gone. X_FORWARDED_HOST carries it
// back; X_FRONT_SECRET proves the pair actually came from the Worker rather
// than from a caller spoofing X-Forwarded-Host directly against the relay.
const X_FORWARDED_HOST = "x-forwarded-host";
const X_FRONT_SECRET = "x-front-secret";

/** Constant-time string equality, used to compare the front secret so a mismatched guess can't be timed. */
function secretsMatch(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  return bufA.length === bufB.length && timingSafeEqual(bufA, bufB);
}

class RequestBodyTooLargeError extends Error {}

/**
 * Reads a Request body while enforcing `maxBytes`, without ever buffering
 * more than the limit in memory: a Content-Length over the cap is rejected
 * without reading the stream at all, and a chunked/unsized body is read
 * incrementally and aborted the moment the running total crosses the cap.
 */
async function readLimitedBody(request: Request, maxBytes: number): Promise<Uint8Array> {
  if (!request.body) return new Uint8Array(0);

  const contentLength = request.headers.get("content-length");
  if (contentLength !== null && Number(contentLength) > maxBytes) {
    throw new RequestBodyTooLargeError();
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maxBytes) {
      await reader.cancel();
      throw new RequestBodyTooLargeError();
    }
    chunks.push(value);
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}

/**
 * Resolves an inbound Host header to a tunnel name, or null if this request
 * isn't for the tunnel namespace (either it's the control-plane API's own
 * hostname, or some other/malformed Host). `<name>.tinycloud.link` must be
 * exactly one label under the apex zone -- deeper labels are never tunnel
 * names (a claimed name is always a single DNS label, see names.ts).
 */
export function remoteNameFromHost(host: string | undefined, apiHostname: string): string | null {
  if (!host) return null;
  const hostname = host.split(":")[0]?.toLowerCase();
  if (!hostname || hostname === apiHostname.toLowerCase()) return null;

  const suffix = `.${REMOTE_DOMAIN_SUFFIX}`;
  if (!hostname.endsWith(suffix)) return null;

  const label = hostname.slice(0, -suffix.length);
  if (!label || label.includes(".")) return null;
  return label;
}

// Headers that describe the hop to the relay itself, not the tunneled
// request -- stripped so they aren't forwarded to the node as-is.
const HOP_BY_HOP_HEADERS = new Set(["connection", "keep-alive", "transfer-encoding", "upgrade", "host"]);

/**
 * Hono middleware that, for any request whose Host header names a claimed
 * tunnel (rather than the control-plane API's own hostname), proxies the
 * request through that name's WebSocket tunnel instead of running it through
 * the normal /v1 routes below. See README's "Ingress and TLS" section for
 * how *.tinycloud.link traffic reaches this process in the first place.
 */
export function createTunnelMiddleware(
  registry: TunnelRegistry,
  opts: { apiHostname: string; maxBodyBytes?: number; frontSecret?: string }
): MiddlewareHandler {
  const maxBodyBytes = opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;

  return async (c: Context, next) => {
    // Only trust X-Forwarded-Host when a front secret is configured *and*
    // the request's X-Front-Secret matches it. Otherwise resolve strictly
    // from Host, exactly as before the Worker front existed -- a caller
    // hitting the relay directly and spoofing X-Forwarded-Host without the
    // secret has no effect.
    const presentedSecret = c.req.header(X_FRONT_SECRET);
    const trusted =
      opts.frontSecret !== undefined &&
      presentedSecret !== undefined &&
      secretsMatch(presentedSecret, opts.frontSecret);
    const host = trusted ? c.req.header(X_FORWARDED_HOST) : c.req.header("host");

    const name = remoteNameFromHost(host, opts.apiHostname);
    if (!name) {
      await next();
      return;
    }

    const socket = registry.get(name);
    if (!socket) {
      return c.json({ error: `no active tunnel for "${name}"` }, 502);
    }

    const headers: Array<[string, string]> = [];
    c.req.raw.headers.forEach((value, key) => {
      const lower = key.toLowerCase();
      if (HOP_BY_HOP_HEADERS.has(lower)) return;
      // Strip the Worker-front headers themselves once trusted -- they
      // describe the Worker->relay hop, not something the tunneled node
      // should ever see (and the secret must never leave this process).
      if (trusted && (lower === X_FORWARDED_HOST || lower === X_FRONT_SECRET)) return;
      headers.push([key, value]);
    });

    const url = new URL(c.req.url);

    let body: Uint8Array;
    try {
      body = await readLimitedBody(c.req.raw, maxBodyBytes);
    } catch (error) {
      if (error instanceof RequestBodyTooLargeError) {
        return c.json({ error: `request body exceeds ${maxBodyBytes} byte limit` }, 413);
      }
      throw error;
    }

    try {
      const response = await proxyRequest(
        socket,
        {
          method: c.req.method,
          path: `${url.pathname}${url.search}`,
          headers,
          body,
        },
        { maxResponseBytes: maxBodyBytes }
      );
      const responseHeaders = new Headers();
      for (const [key, value] of response.headers) {
        responseHeaders.append(key, value);
      }
      return new Response(new Uint8Array(response.body), {
        status: response.status,
        headers: responseHeaders,
      });
    } catch (error) {
      if (error instanceof TunnelProxyTimeoutError) {
        return c.json({ error: "tunnel request timed out" }, 504);
      }
      if (error instanceof TunnelProxyError) {
        return c.json({ error: "tunnel request failed" }, 502);
      }
      throw error;
    }
  };
}
