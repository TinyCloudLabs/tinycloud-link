import type {
  AcmeAccountStore,
  CertRateLimiter,
  DeleteResult,
  NameRecordRow,
  NameStore,
  PutResult,
} from "../storage.js";

export class InMemoryNameStore implements NameStore {
  private readonly rows = new Map<string, NameRecordRow>();

  async get(name: string): Promise<NameRecordRow | null> {
    return this.rows.get(name) ?? null;
  }

  async put(row: NameRecordRow): Promise<PutResult> {
    const existing = this.rows.get(row.name);
    if (existing && existing.sequence >= row.sequence) {
      return "stale";
    }
    this.rows.set(row.name, { ...row, lanIps: [...row.lanIps] });
    return existing ? "updated" : "created";
  }

  async delete(name: string, sequence: number): Promise<DeleteResult> {
    const existing = this.rows.get(name);
    if (!existing) return "not_found";
    if (existing.sequence >= sequence) return "stale";
    this.rows.delete(name);
    return "deleted";
  }

  async close(): Promise<void> {}
}

export class InMemoryAcmeAccountStore implements AcmeAccountStore {
  private key: string | null = null;

  async getAccountKey(): Promise<string | null> {
    return this.key;
  }

  async saveAccountKey(pem: string): Promise<void> {
    this.key = pem;
  }

  async close(): Promise<void> {}
}

export class InMemoryCertRateLimiter implements CertRateLimiter {
  private readonly issuances: Array<{ name: string; at: number }> = [];

  async recordIssuance(name: string): Promise<void> {
    this.issuances.push({ name, at: Date.now() });
  }

  async countRecentIssuances(name: string, windowMs: number): Promise<number> {
    const cutoff = Date.now() - windowMs;
    return this.issuances.filter((entry) => entry.name === name && entry.at >= cutoff).length;
  }

  async close(): Promise<void> {}
}
