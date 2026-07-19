import { randomUUID } from "node:crypto";
import type WebSocket from "ws";
import { BODY_CHUNK_BYTES, DEFAULT_MAX_BODY_BYTES, encodeFrame, parseFrame } from "./protocol.js";
import { rawDataToString } from "./ws-util.js";

export interface TunnelProxyRequest {
  method: string;
  /** Path + query string, e.g. "/foo?bar=1". */
  path: string;
  /** Ordered [name, value] pairs (see protocol.ts) so duplicate header names survive. */
  headers: Array<[string, string]>;
  body: Uint8Array;
}

export interface TunnelProxyResponse {
  status: number;
  /** Ordered [name, value] pairs (see protocol.ts) so duplicate header names, e.g. Set-Cookie, survive. */
  headers: Array<[string, string]>;
  body: Uint8Array;
}

export class TunnelProxyError extends Error {}
export class TunnelProxyTimeoutError extends TunnelProxyError {}
export class TunnelProxyBodyTooLargeError extends TunnelProxyError {}

const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * Sends one HTTP request down an authenticated tunnel socket and resolves
 * with the aggregated response once the node signals `done`. Concurrency
 * safe: each call uses its own request id and only inspects frames carrying
 * that id, so multiple proxyRequest calls can run concurrently over the same
 * socket.
 */
export function proxyRequest(
  socket: WebSocket,
  request: TunnelProxyRequest,
  opts: { timeoutMs?: number; maxResponseBytes?: number } = {}
): Promise<TunnelProxyResponse> {
  const id = randomUUID();
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxResponseBytes = opts.maxResponseBytes ?? DEFAULT_MAX_BODY_BYTES;

  return new Promise<TunnelProxyResponse>((resolve, reject) => {
    let status: number | undefined;
    let headers: Array<[string, string]> | undefined;
    const bodyChunks: Buffer[] = [];
    let bodyBytes = 0;
    let settled = false;

    const cleanup = () => {
      settled = true;
      clearTimeout(timer);
      socket.off("message", onMessage);
      socket.off("close", onClose);
    };

    const fail = (error: Error) => {
      if (settled) return;
      cleanup();
      reject(error);
    };

    const timer = setTimeout(() => {
      fail(new TunnelProxyTimeoutError(`tunnel request ${id} timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    const onClose = () => {
      fail(new TunnelProxyError(`tunnel socket closed before request ${id} completed`));
    };

    const onMessage = (data: WebSocket.RawData) => {
      if (settled) return;
      let frame;
      try {
        frame = parseFrame(rawDataToString(data));
      } catch {
        return; // ignore malformed frames rather than tearing down the socket
      }
      if (frame.type === "response" && frame.id === id) {
        status = frame.status;
        headers = frame.headers;
        return;
      }
      if (frame.type === "responseBody" && frame.id === id) {
        if (frame.chunk.length > 0) {
          const chunk = Buffer.from(frame.chunk, "base64");
          bodyBytes += chunk.length;
          if (bodyBytes > maxResponseBytes) {
            socket.send(
              encodeFrame({ type: "error", id, message: `response body exceeds ${maxResponseBytes} byte limit` })
            );
            fail(new TunnelProxyBodyTooLargeError(`response body for request ${id} exceeded ${maxResponseBytes} bytes`));
            return;
          }
          bodyChunks.push(chunk);
        }
        if (frame.done) {
          if (status === undefined || headers === undefined) {
            fail(new TunnelProxyError(`request ${id} completed without a response head`));
            return;
          }
          cleanup();
          resolve({ status, headers, body: Buffer.concat(bodyChunks) });
        }
        return;
      }
      if (frame.type === "error" && frame.id === id) {
        fail(new TunnelProxyError(`node reported an error for request ${id}: ${frame.message}`));
      }
    };

    socket.on("message", onMessage);
    socket.on("close", onClose);

    socket.send(
      encodeFrame({ type: "request", id, method: request.method, path: request.path, headers: request.headers })
    );

    // Split the body across multiple requestBody frames of at most
    // BODY_CHUNK_BYTES each so no single WS message risks tripping the
    // relay's/node's WebSocketServer maxPayload (see protocol.ts). An empty
    // body still sends exactly one frame, done: true.
    const body = Buffer.from(request.body);
    let offset = 0;
    do {
      const end = Math.min(offset + BODY_CHUNK_BYTES, body.length);
      const done = end >= body.length;
      socket.send(
        encodeFrame({
          type: "requestBody",
          id,
          chunk: body.subarray(offset, end).toString("base64"),
          done,
        })
      );
      offset = end;
    } while (offset < body.length);
  });
}
