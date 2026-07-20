/**
 * Cloudflare Worker front for `*.tinycloud.link`.
 *
 * dstack-ingress (the L4 proxy in front of the tinycloud-link relay on
 * Phala) can't terminate TLS for an arbitrary wildcard hostname -- see
 * README.md's "Ingress and TLS for tunnels" for the dstack#545 finding that
 * ruled that out. Cloudflare fronts the wildcard instead: Cloudflare
 * Universal SSL covers every first-level `*.tinycloud.link` hostname, and a
 * proxied DNS record (`*` -> api.tinycloud.link) routes all of that traffic
 * to this Worker.
 *
 * This Worker's only job is to forward the request to the relay's origin
 * (`api.tinycloud.link`, which stays DNS-only/unproxied so this Worker can
 * still reach it, and so a node's direct `wss://api.tinycloud.link` tunnel
 * connection is untouched by any of this) while telling the relay which
 * hostname the client actually asked for. The relay can't read that off the
 * HTTP Host header any more -- Host is now always `api.tinycloud.link`,
 * since that's who this Worker fetches -- so it travels instead as
 * `X-Forwarded-Host`, authenticated by a shared secret (`X-Front-Secret`) so
 * the relay only trusts that header when it actually came through this
 * Worker. See src/tunnel/host-router.ts on the relay side for the other
 * half of this contract.
 */

const ORIGIN_HOSTNAME = "api.tinycloud.link";
const ORIGIN_ORIGIN = `https://${ORIGIN_HOSTNAME}`;

export interface Env {
  /**
   * Shared secret proving a request was actually forwarded by this Worker,
   * not a spoofed X-Forwarded-Host header sent straight to the origin. Set
   * via `wrangler secret put FRONT_SECRET` -- never committed to
   * wrangler.toml. Must match the relay's TUNNEL_FRONT_SECRET.
   */
  FRONT_SECRET: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const originUrl = new URL(`${url.pathname}${url.search}`, ORIGIN_ORIGIN);

    const headers = new Headers(request.headers);
    headers.delete("host");

    // api.tinycloud.link's own DNS record is unproxied, so under normal
    // operation this Worker never actually sees a request for it (see
    // wrangler.toml). Handled anyway because the route pattern has no way to
    // exclude it: forward it unchanged, with no X-Forwarded-Host/secret
    // added, so it's indistinguishable from a request that reached the relay
    // directly -- the relay's own apiHostname check already treats a bare
    // Host of api.tinycloud.link as the control-plane API.
    if (url.hostname.toLowerCase() !== ORIGIN_HOSTNAME) {
      headers.set("X-Forwarded-Host", url.hostname);
      headers.set("X-Front-Secret", env.FRONT_SECRET);
    }

    const init: RequestInit = {
      method: request.method,
      headers,
      // The relay answers redirects itself; don't let the edge follow them
      // and silently swap out the response the client should see.
      redirect: "manual",
    };

    // GET/HEAD can't carry a body. Everything else -- including a WebSocket
    // upgrade's initial request, whose Upgrade/Connection/Sec-WebSocket-*
    // headers are already preserved above -- streams the original body
    // through unmodified. `duplex: "half"` is required by the fetch spec
    // whenever the body is a ReadableStream.
    if (request.method !== "GET" && request.method !== "HEAD") {
      init.body = request.body;
      (init as { duplex?: "half" }).duplex = "half";
    }

    // For a WebSocket upgrade, fetch()'s Response carries a `webSocket` pair
    // once the origin completes the 101 handshake; returning that Response
    // as-is finishes the client-side upgrade too, so no special-casing is
    // needed here beyond forwarding the request faithfully. Whether the
    // upgrade actually succeeds end-to-end depends on the relay/tunneled
    // node supporting it at that path -- this Worker does not invent that
    // support, only avoids breaking it if present.
    return fetch(originUrl, init);
  },
};
