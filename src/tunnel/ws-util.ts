import type WebSocket from "ws";

/** ws's default binaryType ("nodebuffer") always delivers a Buffer; this also covers the other RawData shapes defensively. */
export function rawDataToString(data: WebSocket.RawData): string {
  if (Array.isArray(data)) {
    return Buffer.concat(data).toString("utf8");
  }
  if (data instanceof ArrayBuffer) {
    return Buffer.from(data).toString("utf8");
  }
  return data.toString("utf8");
}
