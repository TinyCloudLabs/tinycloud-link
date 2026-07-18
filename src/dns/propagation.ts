import dns from "node:dns";

/** Zone whose authoritative nameservers we consult directly (bypasses recursive caching). */
const DEFAULT_ZONE = "tinycloud.link";
const DEFAULT_PUBLIC_RESOLVER_IP = "1.1.1.1";
const DEFAULT_POLL_INTERVAL_MS = 2000;
const DEFAULT_AUTHORITATIVE_GRACE_MS = 10000;
const DEFAULT_QUERY_TIMEOUT_MS = 5000;

export interface TxtResolver {
  resolveTxt(hostname: string): Promise<string[][]>;
}

export type AuthoritativeResolverFactory = (
  zone: string,
  queryTimeoutMs: number
) => Promise<TxtResolver>;

export interface WaitForTxtPropagationOptions {
  /** Zone to resolve NS records for. Defaults to the tinycloud.link registrable domain. */
  zone?: string;
  publicResolverIp?: string;
  /** Delay before the first poll, so we don't burn the timeout budget on certain early misses. */
  initialDelayMs?: number;
  /** Overall budget before giving up. */
  timeoutMs?: number;
  pollIntervalMs?: number;
  /** Extra wait required after the authoritative servers first show the record, since they're a
   *  single vantage point rather than a proxy for what the CA's validators will see. */
  authoritativeGraceMs?: number;
  /** Per-DNS-query timeout; a hung query counts as "not visible yet" rather than blocking. */
  queryTimeoutMs?: number;
  /** Injectable for tests; defaults to a real resolver pointed at publicResolverIp. */
  publicResolver?: TxtResolver;
  /** Injectable for tests; defaults to resolving the zone's NS records to a real resolver. */
  authoritativeResolverFactory?: AuthoritativeResolverFactory;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Races a promise against a timeout, resolving to `onTimeout` instead of hanging forever. */
async function withTimeout<T>(promise: Promise<T>, ms: number, onTimeout: T): Promise<T> {
  let timer: NodeJS.Timeout;
  const timeoutPromise = new Promise<T>((resolve) => {
    timer = setTimeout(() => resolve(onTimeout), ms);
  });
  try {
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    clearTimeout(timer!);
  }
}

async function safeResolveTxt(
  resolver: TxtResolver,
  hostname: string,
  queryTimeoutMs: number
): Promise<string[][]> {
  return withTimeout(
    resolver.resolveTxt(hostname).catch(() => [] as string[][]),
    queryTimeoutMs,
    []
  );
}

function containsValue(records: string[][], expectedValue: string): boolean {
  return records.some((parts) => parts.join("").trim() === expectedValue);
}

/**
 * Default authoritative resolver: resolves the zone's NS records once, resolves each nameserver
 * hostname to an IP, and queries those IPs directly (skipping any recursive resolver's cache).
 */
async function buildAuthoritativeResolver(
  zone: string,
  queryTimeoutMs: number
): Promise<TxtResolver> {
  const nsHosts = await withTimeout(dns.promises.resolveNs(zone), queryTimeoutMs, []);
  if (nsHosts.length === 0) {
    throw new Error(`no NS records found for zone ${zone}`);
  }

  const ips: string[] = [];
  for (const host of nsHosts) {
    const addrs = await withTimeout(
      dns.promises.resolve4(host).catch(() => [] as string[]),
      queryTimeoutMs,
      []
    );
    ips.push(...addrs);
  }
  if (ips.length === 0) {
    throw new Error(`could not resolve any nameserver addresses for zone ${zone} (ns: ${nsHosts.join(", ")})`);
  }

  const resolver = new dns.promises.Resolver({ timeout: queryTimeoutMs, tries: 1 });
  resolver.setServers(ips);
  return resolver;
}

/**
 * Polls DNS until an ACME dns-01 challenge TXT value is actually visible, instead of guessing
 * with a fixed sleep. Checks a public recursive resolver (1.1.1.1, a reasonable proxy for what
 * most CA validation vantage points will see) and the zone's own authoritative nameservers
 * (queried directly). Resolves as soon as the public resolver shows the value, or once the
 * authoritative servers have shown it for at least `authoritativeGraceMs`. Throws if neither
 * happens within `timeoutMs`.
 */
export async function waitForTxtPropagation(
  recordName: string,
  expectedValue: string,
  options: WaitForTxtPropagationOptions = {}
): Promise<void> {
  const zone = options.zone ?? DEFAULT_ZONE;
  const publicResolverIp = options.publicResolverIp ?? DEFAULT_PUBLIC_RESOLVER_IP;
  const initialDelayMs = options.initialDelayMs ?? envInt("ACME_PROPAGATION_DELAY_MS", 10000);
  const timeoutMs = options.timeoutMs ?? envInt("ACME_PROPAGATION_TIMEOUT_MS", 120000);
  const pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const authoritativeGraceMs = options.authoritativeGraceMs ?? DEFAULT_AUTHORITATIVE_GRACE_MS;
  const queryTimeoutMs = options.queryTimeoutMs ?? DEFAULT_QUERY_TIMEOUT_MS;
  const sleep = options.sleep ?? defaultSleep;
  const now = options.now ?? (() => Date.now());

  const publicResolver =
    options.publicResolver ??
    (() => {
      const resolver = new dns.promises.Resolver({ timeout: queryTimeoutMs, tries: 1 });
      resolver.setServers([publicResolverIp]);
      return resolver;
    })();

  const authoritativeResolverFactory = options.authoritativeResolverFactory ?? buildAuthoritativeResolver;

  const start = now();
  if (initialDelayMs > 0) {
    await sleep(initialDelayMs);
  }

  let authoritativeResolver: TxtResolver | null = null;
  let authoritativeUnavailable = false;
  let authoritativeFirstVisibleAt: number | null = null;

  for (;;) {
    const publicRecords = await safeResolveTxt(publicResolver, recordName, queryTimeoutMs);
    if (containsValue(publicRecords, expectedValue)) {
      return;
    }

    if (!authoritativeResolver && !authoritativeUnavailable) {
      try {
        authoritativeResolver = await authoritativeResolverFactory(zone, queryTimeoutMs);
      } catch {
        authoritativeUnavailable = true;
      }
    }

    if (authoritativeResolver) {
      const authoritativeRecords = await safeResolveTxt(authoritativeResolver, recordName, queryTimeoutMs);
      if (containsValue(authoritativeRecords, expectedValue)) {
        if (authoritativeFirstVisibleAt === null) {
          authoritativeFirstVisibleAt = now();
        }
        if (now() - authoritativeFirstVisibleAt >= authoritativeGraceMs) {
          return;
        }
      } else {
        authoritativeFirstVisibleAt = null;
      }
    }

    if (now() - start >= timeoutMs) {
      throw new Error(
        `timed out after ${timeoutMs}ms waiting for ${recordName} TXT record (expected "${expectedValue}") to propagate`
      );
    }

    await sleep(pollIntervalMs);
  }
}
