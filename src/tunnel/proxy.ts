import { randomUUID } from "node:crypto";
import type WebSocket from "ws";
import { encodeFrame, parseFrame } from "./protocol.js";
import { rawDataToString } from "./ws-util.js";

export interface TunnelProxyRequest {
  method: string;
  /** Path + query string, e.g. "/foo?bar=1". */
  path: string;
  headers: Record<string, string>;
  body: Uint8Array;
}

export interface TunnelProxyResponse {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}

export class TunnelProxyError extends Error {}
export class TunnelProxyTimeoutError extends TunnelProxyError {}

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
  opts: { timeoutMs?: number } = {}
): Promise<TunnelProxyResponse> {
  const id = randomUUID();
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  return new Promise<TunnelProxyResponse>((resolve, reject) => {
    let status: number | undefined;
    let headers: Record<string, string> | undefined;
    const bodyChunks: Buffer[] = [];
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
          bodyChunks.push(Buffer.from(frame.chunk, "base64"));
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
    socket.send(
      encodeFrame({
        type: "requestBody",
        id,
        chunk: Buffer.from(request.body).toString("base64"),
        done: true,
      })
    );
  });
}
