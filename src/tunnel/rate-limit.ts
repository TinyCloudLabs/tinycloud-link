/**
 * In-memory sliding-window attempt counter for the tunnel WS upgrade path
 * (per-IP connection attempts, per-name churn). Same count/prune pattern as
 * the Postgres-backed cert-issuance rate limiter (src/postgres.ts's
 * PostgresCertRateLimiter and its in-memory test double), but deliberately
 * not backed by Postgres: these are short (per-minute) windows checked on
 * every single upgrade attempt, before any Postgres read happens (see
 * src/tunnel/upgrade.ts) -- adding a Postgres round trip here would defeat
 * the point, and resetting on process restart is fine for this use case.
 */
export class AttemptLimiter {
  private readonly attempts = new Map<string, number[]>();

  /** Records one attempt for `key` now, and returns how many attempts for `key` fall within the last `windowMs` (including this one), pruning older entries as a side effect. */
  recordAndCount(key: string, windowMs: number): number {
    const cutoff = Date.now() - windowMs;
    const existing = this.attempts.get(key);
    const pruned = existing ? existing.filter((at) => at >= cutoff) : [];
    pruned.push(Date.now());
    this.attempts.set(key, pruned);
    return pruned.length;
  }
}
