import pg from "pg";
import type { AcmeAccountStore, CertRateLimiter, DeleteResult, NameRecordRow, NameStore, PutResult } from "./storage.js";

const { Pool } = pg;

/** Postgres-backed name claims, modeled on location-registry's postgres.ts sequence-guard pattern. */
export class PostgresNameStore implements NameStore {
  private readonly pool: pg.Pool;

  constructor(connectionString: string) {
    this.pool = new Pool({ connectionString });
  }

  async init(): Promise<void> {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS names (
        name TEXT PRIMARY KEY,
        subject TEXT NOT NULL,
        lan_ips JSONB NOT NULL,
        sequence BIGINT NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL,
        stored_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE INDEX IF NOT EXISTS idx_names_subject ON names(subject);
    `);
  }

  async get(name: string): Promise<NameRecordRow | null> {
    const result = await this.pool.query<{
      name: string;
      subject: string;
      lan_ips: string[];
      sequence: string;
      updated_at: Date;
    }>("SELECT name, subject, lan_ips, sequence, updated_at FROM names WHERE name = $1", [name]);
    const row = result.rows[0];
    if (!row) return null;
    return {
      name: row.name,
      subject: row.subject,
      lanIps: row.lan_ips,
      sequence: Number(row.sequence),
      updatedAt: row.updated_at.toISOString(),
    };
  }

  async put(row: NameRecordRow): Promise<PutResult> {
    const result = await this.pool.query<{ inserted: boolean }>(
      `
      INSERT INTO names (name, subject, lan_ips, sequence, updated_at)
      VALUES ($1, $2, $3::jsonb, $4, $5)
      ON CONFLICT (name) DO UPDATE SET
        subject = EXCLUDED.subject,
        lan_ips = EXCLUDED.lan_ips,
        sequence = EXCLUDED.sequence,
        updated_at = EXCLUDED.updated_at,
        stored_at = now()
      WHERE names.sequence < EXCLUDED.sequence
      RETURNING xmax = 0 AS inserted
      `,
      [row.name, row.subject, JSON.stringify(row.lanIps), row.sequence, row.updatedAt]
    );

    if (result.rowCount === 0) {
      return "stale";
    }
    return result.rows[0]?.inserted ? "created" : "updated";
  }

  async delete(name: string, sequence: number): Promise<DeleteResult> {
    const result = await this.pool.query(
      "DELETE FROM names WHERE name = $1 AND sequence < $2",
      [name, sequence]
    );
    if (result.rowCount && result.rowCount > 0) {
      return "deleted";
    }

    const existing = await this.pool.query("SELECT 1 FROM names WHERE name = $1", [name]);
    return existing.rowCount && existing.rowCount > 0 ? "stale" : "not_found";
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

/** Persists the single ACME account key used to place orders against the configured directory. */
export class PostgresAcmeAccountStore implements AcmeAccountStore {
  private readonly pool: pg.Pool;

  constructor(connectionString: string) {
    this.pool = new Pool({ connectionString });
  }

  async init(): Promise<void> {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS acme_account (
        id TEXT PRIMARY KEY DEFAULT 'default',
        account_key_pem TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);
  }

  async getAccountKey(): Promise<string | null> {
    const result = await this.pool.query<{ account_key_pem: string }>(
      "SELECT account_key_pem FROM acme_account WHERE id = 'default'"
    );
    return result.rows[0]?.account_key_pem ?? null;
  }

  async saveAccountKey(pem: string): Promise<void> {
    await this.pool.query(
      `INSERT INTO acme_account (id, account_key_pem) VALUES ('default', $1)
       ON CONFLICT (id) DO UPDATE SET account_key_pem = EXCLUDED.account_key_pem`,
      [pem]
    );
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

/** Tracks cert issuances per name so /v1/certs/:name can enforce a daily quota against LE limits. */
export class PostgresCertRateLimiter implements CertRateLimiter {
  private readonly pool: pg.Pool;

  constructor(connectionString: string) {
    this.pool = new Pool({ connectionString });
  }

  async init(): Promise<void> {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS cert_issuances (
        id BIGSERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        issued_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE INDEX IF NOT EXISTS idx_cert_issuances_name_issued_at
        ON cert_issuances(name, issued_at);
    `);
  }

  async recordIssuance(name: string): Promise<void> {
    await this.pool.query("INSERT INTO cert_issuances (name) VALUES ($1)", [name]);
  }

  async countRecentIssuances(name: string, windowMs: number): Promise<number> {
    const result = await this.pool.query<{ count: string }>(
      "SELECT count(*) FROM cert_issuances WHERE name = $1 AND issued_at > now() - $2::interval",
      [name, `${windowMs} milliseconds`]
    );
    return Number(result.rows[0]?.count ?? 0);
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
