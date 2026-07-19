import type WebSocket from "ws";

// Close code for a socket evicted by a newer registration for the same name.
// 4000-4999 is the private-use range reserved by RFC 6455. Distinct from
// upgrade.ts's CLOSE_STALE_SEQUENCE (4409): that's an auth-time rejection,
// this is a normal lifecycle eviction of an already-authenticated tunnel.
export const SUPERSEDED_CLOSE_CODE = 4410;

interface Entry {
  socket: WebSocket;
  connectedAt: number;
}

/**
 * Tracks the single live tunnel socket per name. "Newest wins": registering
 * a new socket for a name that already has one closes the old one instead of
 * rejecting the new connection, matching a node that reconnects (e.g. after
 * a network blip) taking over from a stale socket the relay hasn't noticed
 * is dead yet.
 */
export class TunnelRegistry {
  private readonly entries = new Map<string, Entry>();

  register(name: string, socket: WebSocket): void {
    const existing = this.entries.get(name);
    if (existing && existing.socket !== socket) {
      existing.socket.close(SUPERSEDED_CLOSE_CODE, "superseded by a newer connection");
    }
    this.entries.set(name, { socket, connectedAt: Date.now() });
  }

  get(name: string): WebSocket | undefined {
    return this.entries.get(name)?.socket;
  }

  /** Removes `socket` from the registry, but only if it's still the current entry for `name` -- avoids a stale socket's close/error handler clobbering a newer registration. */
  unregister(name: string, socket: WebSocket): void {
    const existing = this.entries.get(name);
    if (existing && existing.socket === socket) {
      this.entries.delete(name);
    }
  }

  size(): number {
    return this.entries.size;
  }
}
