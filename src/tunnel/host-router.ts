import type { Context, MiddlewareHandler } from "hono";
import { REMOTE_DOMAIN_SUFFIX } from "../names.js";
import { TunnelProxyError, TunnelProxyTimeoutError, proxyRequest } from "./proxy.js";
import type { TunnelRegistry } from "./registry.js";

export const DEFAULT_API_HOSTNAME = "api.tinycloud.link";

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
  opts: { apiHostname: string }
): MiddlewareHandler {
  return async (c: Context, next) => {
    const name = remoteNameFromHost(c.req.header("host"), opts.apiHostname);
    if (!name) {
      await next();
      return;
    }

    const socket = registry.get(name);
    if (!socket) {
      return c.json({ error: `no active tunnel for "${name}"` }, 502);
    }

    const headers: Record<string, string> = {};
    c.req.raw.headers.forEach((value, key) => {
      if (!HOP_BY_HOP_HEADERS.has(key.toLowerCase())) {
        headers[key] = value;
      }
    });

    const url = new URL(c.req.url);
    const body = new Uint8Array(await c.req.raw.arrayBuffer());

    try {
      const response = await proxyRequest(socket, {
        method: c.req.method,
        path: `${url.pathname}${url.search}`,
        headers,
        body,
      });
      return new Response(new Uint8Array(response.body), {
        status: response.status,
        headers: response.headers,
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
