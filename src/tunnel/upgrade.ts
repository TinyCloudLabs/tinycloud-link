import type { ServerType } from "@hono/node-server";
import { WebSocketServer } from "ws";
import type WebSocket from "ws";
import { validateTunnelAuth, verifyTunnelAuth } from "../names.js";
import type { NameStore } from "../storage.js";
import { TunnelRegistry } from "./registry.js";
import { MAX_FRAME_PAYLOAD_BYTES, encodeFrame } from "./protocol.js";
import { AttemptLimiter } from "./rate-limit.js";
import { rawDataToString } from "./ws-util.js";

const TUNNEL_PATH_PATTERN = /^\/v1\/tunnel\/([^/]+)\/?$/;

// Close codes are in the 4000-4999 private-use range reserved by RFC 6455.
export const CLOSE_AUTH_TIMEOUT = 4408;
export const CLOSE_BAD_FRAME = 4400;
export const CLOSE_NAME_NOT_CLAIMED = 4404;
export const CLOSE_NOT_OWNER = 4403;
export const CLOSE_STALE_SEQUENCE = 4409;
export const CLOSE_INVALID_SIGNATURE = 4401;

const DEFAULT_AUTH_TIMEOUT_MS = 5_000;
const HEARTBEAT_INTERVAL_MS = 30_000;
const RATE_WINDOW_MS = 60_000;
const DEFAULT_IP_CONNECTION_LIMIT_PER_MINUTE = 30;
const DEFAULT_NAME_CHURN_LIMIT_PER_MINUTE = 10;
const DEFAULT_MAX_CONCURRENT_TUNNELS = 1000;

export interface AttachTunnelUpgradeOptions {
  registry: TunnelRegistry;
  nameStore: NameStore;
  authTimeoutMs?: number;
  /** Max WS upgrade attempts allowed per remote IP per minute before the connection is dropped pre-handshake. */
  ipConnectionLimitPerMinute?: number;
  /** Max WS upgrade attempts allowed per tunnel name per minute (limits reconnect/eviction churn on a single name). */
  nameChurnLimitPerMinute?: number;
  /** Max concurrently registered (authenticated) tunnels; further upgrade attempts are dropped once at the cap. Env-tunable via TUNNEL_MAX_CONCURRENT (see index.ts). */
  maxConcurrentTunnels?: number;
}

/**
 * Wires up wss://<host>/v1/tunnel/:name on the raw Node HTTP server behind a
 * Hono app (Hono/`@hono/node-server` don't handle WebSocket upgrades; this
 * hooks the server's 'upgrade' event directly, the standard `ws` pattern).
 */
export function attachTunnelUpgrade(server: ServerType, opts: AttachTunnelUpgradeOptions): void {
  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_FRAME_PAYLOAD_BYTES });
  const ipLimiter = new AttemptLimiter();
  const nameLimiter = new AttemptLimiter();
  const ipConnectionLimit = opts.ipConnectionLimitPerMinute ?? DEFAULT_IP_CONNECTION_LIMIT_PER_MINUTE;
  const nameChurnLimit = opts.nameChurnLimitPerMinute ?? DEFAULT_NAME_CHURN_LIMIT_PER_MINUTE;
  const maxConcurrentTunnels = opts.maxConcurrentTunnels ?? DEFAULT_MAX_CONCURRENT_TUNNELS;

  server.on("upgrade", (req, socket, head) => {
    const url = new URL(req.url ?? "", "http://tunnel.invalid");
    const match = TUNNEL_PATH_PATTERN.exec(url.pathname);
    if (!match) {
      socket.destroy();
      return;
    }
    const urlName = decodeURIComponent(match[1]).toLowerCase();

    // Every check below runs before any Postgres read (the first one is
    // nameStore.get, in authenticate() -- only reached after a WS handshake
    // and a first message). Rejecting here means an attacker exhausting
    // these limits never gets a completed WS handshake, let alone triggers a
    // database query.
    const ip = socket.remoteAddress ?? "unknown";
    if (ipLimiter.recordAndCount(`ip:${ip}`, RATE_WINDOW_MS) > ipConnectionLimit) {
      socket.destroy();
      return;
    }
    if (opts.registry.size() >= maxConcurrentTunnels) {
      socket.destroy();
      return;
    }
    if (nameLimiter.recordAndCount(`name:${urlName}`, RATE_WINDOW_MS) > nameChurnLimit) {
      socket.destroy();
      return;
    }

    wss.handleUpgrade(req, socket, head, (ws) => {
      handleConnection(ws, urlName, opts);
    });
  });
}

function handleConnection(ws: WebSocket, urlName: string, opts: AttachTunnelUpgradeOptions): void {
  // 'ws' emits 'error' as a plain EventEmitter event -- with no listener,
  // Node treats it as uncaught and crashes the process. This fires for
  // things like a frame exceeding the WebSocketServer's maxPayload (e.g. a
  // misbehaving node), which must close the one offending tunnel, not take
  // down the relay. The library already closes the socket itself in that
  // case (see ws's receiverOnError); this handler only exists to observe
  // the event so it isn't unhandled.
  ws.on("error", () => {});

  const authTimeoutMs = opts.authTimeoutMs ?? DEFAULT_AUTH_TIMEOUT_MS;
  const authTimer = setTimeout(() => {
    ws.close(CLOSE_AUTH_TIMEOUT, "no auth frame received in time");
  }, authTimeoutMs);

  ws.once("message", (data) => {
    clearTimeout(authTimer);
    authenticate(ws, urlName, data, opts).catch(() => {
      ws.close(1011, "internal error during authentication");
    });
  });
}

async function authenticate(
  ws: WebSocket,
  urlName: string,
  data: WebSocket.RawData,
  opts: AttachTunnelUpgradeOptions
): Promise<void> {
  let auth;
  try {
    auth = validateTunnelAuth(JSON.parse(rawDataToString(data)));
  } catch (error) {
    ws.close(CLOSE_BAD_FRAME, error instanceof Error ? error.message.slice(0, 120) : "invalid auth frame");
    return;
  }
  if (auth.name !== urlName) {
    ws.close(CLOSE_BAD_FRAME, "auth frame name must match the connection URL");
    return;
  }

  const existing = await opts.nameStore.get(auth.name);
  if (!existing) {
    ws.close(CLOSE_NAME_NOT_CLAIMED, "name is not claimed; claim it via PUT /v1/names/:name first");
    return;
  }
  if (existing.subject !== auth.subject) {
    ws.close(CLOSE_NOT_OWNER, "subject does not own this name");
    return;
  }
  if (existing.sequence >= auth.sequence) {
    ws.close(CLOSE_STALE_SEQUENCE, "stale sequence");
    return;
  }

  let verified = false;
  try {
    verified = await verifyTunnelAuth(auth);
  } catch {
    verified = false;
  }
  if (!verified) {
    ws.close(CLOSE_INVALID_SIGNATURE, "invalid record signature");
    return;
  }

  const bumpStatus = await opts.nameStore.put({
    ...existing,
    sequence: auth.sequence,
    updatedAt: new Date().toISOString(),
  });
  if (bumpStatus === "stale") {
    ws.close(CLOSE_STALE_SEQUENCE, "stale sequence");
    return;
  }

  // Multiple concurrent proxied requests each add their own 'message'/'close'
  // listener (see proxy.ts); raise the default EventEmitter cap to avoid
  // spurious MaxListenersExceededWarning noise under load.
  ws.setMaxListeners(100);

  opts.registry.register(auth.name, ws);
  ws.send(encodeFrame({ type: "ack" }));

  ws.on("close", () => opts.registry.unregister(auth.name, ws));

  // Standard ws heartbeat: ping every interval, and if the previous ping
  // never got a pong back, assume the peer is gone and terminate. Detects a
  // node that dropped off the network without a clean WS close (e.g. power
  // loss, NAT timeout) so a dead socket doesn't linger as "registered".
  let alive = true;
  ws.on("pong", () => {
    alive = true;
  });
  const heartbeat = setInterval(() => {
    if (!alive) {
      ws.terminate();
      return;
    }
    alive = false;
    ws.ping();
  }, HEARTBEAT_INTERVAL_MS);
  ws.on("close", () => clearInterval(heartbeat));
}
