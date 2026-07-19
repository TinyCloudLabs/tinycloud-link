/**
 * Wire protocol for the tunnel relay's HTTP-over-WebSocket framing.
 *
 * A node opens one outbound WebSocket to wss://api.tinycloud.link/v1/tunnel/<name>
 * and authenticates with a single `TunnelAuthFrame` (see ../names.ts's
 * TunnelAuthRecord). After the relay acks, every subsequent frame on the
 * socket is one of the request/response frames below: the relay sends
 * `request` + `requestBody` frames for each inbound HTTPS request to
 * <name>.tinycloud.link, and the node replies with `response` +
 * `responseBody` frames carrying the same `id`. Frames are JSON text
 * messages, one per WebSocket message (no batching).
 *
 * This file is the source of truth for a Rust client implementation --
 * every frame shape a node must produce or consume is defined here.
 */
import type { TunnelAuthRecord } from "../names.js";

/** First message a node sends after the WebSocket opens. */
export type TunnelAuthFrame = TunnelAuthRecord & { type?: undefined };

/** Sent by the relay once auth succeeds. The tunnel is live after this. */
export interface TunnelAckFrame {
  type: "ack";
}

/**
 * Sent by the relay on auth failure (immediately before closing the socket),
 * or by either side on a per-request failure (carries the request `id`).
 */
export interface TunnelErrorFrame {
  type: "error";
  id?: string;
  message: string;
}

/** Relay -> node: the head of an inbound HTTP request for <name>.tinycloud.link. */
export interface TunnelRequestFrame {
  type: "request";
  id: string;
  method: string;
  /** Path + query string, e.g. "/foo?bar=1". Always starts with "/". */
  path: string;
  headers: Record<string, string>;
}

/** Relay -> node: a chunk of the request body. Always sent at least once per request, even if empty. */
export interface TunnelRequestBodyFrame {
  type: "requestBody";
  id: string;
  /** Base64-encoded body bytes for this chunk (may be an empty string). */
  chunk: string;
  done: boolean;
}

/** Node -> relay: the head of the response to a proxied request. */
export interface TunnelResponseFrame {
  type: "response";
  id: string;
  status: number;
  headers: Record<string, string>;
}

/** Node -> relay: a chunk of the response body. Always sent at least once per request, even if empty. */
export interface TunnelResponseBodyFrame {
  type: "responseBody";
  id: string;
  chunk: string;
  done: boolean;
}

export type TunnelFrame =
  | TunnelAckFrame
  | TunnelErrorFrame
  | TunnelRequestFrame
  | TunnelRequestBodyFrame
  | TunnelResponseFrame
  | TunnelResponseBodyFrame;

export function encodeFrame(frame: TunnelFrame | TunnelAuthFrame): string {
  return JSON.stringify(frame);
}

/** Parses and minimally shape-checks a raw WebSocket text message into a TunnelFrame. */
export function parseFrame(raw: string): TunnelFrame {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("frame is not valid JSON");
  }
  if (parsed === null || typeof parsed !== "object" || typeof (parsed as { type?: unknown }).type !== "string") {
    throw new Error('frame must be an object with a string "type"');
  }
  return parsed as TunnelFrame;
}
