import type { ServerType } from "@hono/node-server";
import { WebSocketServer } from "ws";
import type WebSocket from "ws";
import { validateTunnelAuth, verifyTunnelAuth } from "../names.js";
import type { NameStore } from "../storage.js";
import { TunnelRegistry } from "./registry.js";
import { encodeFrame } from "./protocol.js";
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

export interface AttachTunnelUpgradeOptions {
  registry: TunnelRegistry;
  nameStore: NameStore;
  authTimeoutMs?: number;
}

/**
 * Wires up wss://<host>/v1/tunnel/:name on the raw Node HTTP server behind a
 * Hono app (Hono/`@hono/node-server` don't handle WebSocket upgrades; this
 * hooks the server's 'upgrade' event directly, the standard `ws` pattern).
 */
export function attachTunnelUpgrade(server: ServerType, opts: AttachTunnelUpgradeOptions): void {
  const wss = new WebSocketServer({ noServer: true });

  server.on("upgrade", (req, socket, head) => {
    const url = new URL(req.url ?? "", "http://tunnel.invalid");
    const match = TUNNEL_PATH_PATTERN.exec(url.pathname);
    if (!match) {
      socket.destroy();
      return;
    }
    const urlName = decodeURIComponent(match[1]).toLowerCase();

    wss.handleUpgrade(req, socket, head, (ws) => {
      handleConnection(ws, urlName, opts);
    });
  });
}

function handleConnection(ws: WebSocket, urlName: string, opts: AttachTunnelUpgradeOptions): void {
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
