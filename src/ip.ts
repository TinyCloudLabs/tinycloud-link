import { isIP } from "node:net";

/**
 * lanIps in this service must be private-range addresses: the namespace exists
 * to give LAN devices a name+cert for a node's local IP, never a public one.
 */
export function isPrivateAddress(address: string): boolean {
  const version = isIP(address);
  if (version === 4) return isPrivateIPv4(address);
  if (version === 6) return isPrivateIPv6(address);
  return false;
}

function isPrivateIPv4(address: string): boolean {
  const octets = address.split(".").map(Number);
  const [a, b] = octets;
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local
  if (a === 127) return true; // 127.0.0.0/8 loopback
  return false;
}

function isPrivateIPv6(address: string): boolean {
  // Normalize to the full 8x16-bit group form so shorthand ("::"), expanded,
  // and IPv4-embedded spellings all classify identically. Fail closed on
  // anything that does not normalize cleanly.
  const groups = expandIPv6(address);
  if (!groups) return false;

  if (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) return true; // ::1 loopback
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    // ::ffff:a.b.c.d IPv4-mapped -- classify by the embedded IPv4
    return isPrivateIPv4(embeddedIPv4(groups[6], groups[7]));
  }
  if (
    groups[0] === 0x0064 &&
    groups[1] === 0xff9b &&
    groups.slice(2, 6).every((g) => g === 0)
  ) {
    // 64:ff9b::/96 NAT64 -- classify by the embedded IPv4
    return isPrivateIPv4(embeddedIPv4(groups[6], groups[7]));
  }
  if (groups[0] === 0x2002) {
    // 2002::/16 6to4 -- classify by the embedded IPv4
    return isPrivateIPv4(embeddedIPv4(groups[1], groups[2]));
  }
  if ((groups[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((groups[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  return false;
}

/** Expands a valid IPv6 address into its 8 16-bit groups, or null if it cannot. */
function expandIPv6(address: string): number[] | null {
  let addr = address.toLowerCase();

  // Rewrite a trailing dotted-quad (e.g. "::ffff:192.168.1.1") as two hex groups.
  const v4Match = addr.match(/^(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (v4Match) {
    const octets = v4Match[2].split(".").map(Number);
    if (octets.some((o) => o > 255)) return null;
    const hi = ((octets[0] << 8) | octets[1]).toString(16);
    const lo = ((octets[2] << 8) | octets[3]).toString(16);
    addr = `${v4Match[1]}${hi}:${lo}`;
  }

  const halves = addr.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 0 : head.length !== 8) return null;
  const parts = halves.length === 2 ? [...head, ...Array(missing).fill("0"), ...tail] : head;

  const groups: number[] = [];
  for (const part of parts) {
    if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
    groups.push(Number.parseInt(part, 16));
  }
  return groups.length === 8 ? groups : null;
}

function embeddedIPv4(hi: number, lo: number): string {
  return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
}
