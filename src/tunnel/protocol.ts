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
 *
 * Size limits (see README's "Remote reachability: the tunnel relay" section
 * for the full contract): the relay's WebSocketServer enforces
 * `MAX_FRAME_PAYLOAD_BYTES` on every inbound WS message (src/tunnel/upgrade.ts),
 * so no single frame -- request or response -- may serialize to more than
 * that many bytes. A body larger than `BODY_CHUNK_BYTES` must be split across
 * multiple `requestBody`/`responseBody` frames (only the last carries
 * `done: true`); `BODY_CHUNK_BYTES` is sized so a base64-encoded chunk plus
 * its JSON envelope always stays well under `MAX_FRAME_PAYLOAD_BYTES`.
 * `DEFAULT_MAX_BODY_BYTES` bounds the total (reassembled) size of a request
 * or response body; a node must not send, and the relay will not forward, a
 * body larger than this (configurable via `TUNNEL_MAX_BODY_BYTES` on the
 * relay -- see README).
 */
import type { TunnelAuthRecord } from "../names.js";

/** Max size in bytes of a single WebSocket message the relay will accept from a node (see src/tunnel/upgrade.ts's WebSocketServer maxPayload). */
export const MAX_FRAME_PAYLOAD_BYTES = 1 * 1024 * 1024;

/** Chunk size (pre-base64, in bytes) used to split a request/response body across multiple body frames. Base64 expands this by ~4/3, plus JSON envelope overhead, staying comfortably under MAX_FRAME_PAYLOAD_BYTES. */
export const BODY_CHUNK_BYTES = 256 * 1024;

/** Default cap (bytes) on a full reassembled request or response body; overridable via the TUNNEL_MAX_BODY_BYTES env var. */
export const DEFAULT_MAX_BODY_BYTES = 25 * 1024 * 1024;

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
  /** Ordered [name, value] pairs, one per header line -- an array (not an object) so duplicate header names (e.g. multiple Cookie lines) survive rather than colliding on one object key. */
  headers: Array<[string, string]>;
}

/** Relay -> node: a chunk of the request body. Always sent at least once per request, even if empty. A body larger than BODY_CHUNK_BYTES is split across multiple requestBody frames; only the last has done: true. */
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
  /** Ordered [name, value] pairs -- an array (not an object) so duplicate header names, most importantly Set-Cookie, survive rather than colliding on one object key. */
  headers: Array<[string, string]>;
}

/** Node -> relay: a chunk of the response body. Always sent at least once per request, even if empty. A body larger than BODY_CHUNK_BYTES should be split across multiple responseBody frames; only the last has done: true. */
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
