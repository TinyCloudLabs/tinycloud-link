export interface NameRecordRow {
  name: string;
  subject: string;
  lanIps: string[];
  sequence: number;
  updatedAt: string;
}

export type PutResult = "created" | "updated" | "stale";
export type DeleteResult = "deleted" | "stale" | "not_found";

export interface NameStore {
  init?(): Promise<void>;
  get(name: string): Promise<NameRecordRow | null>;
  put(row: NameRecordRow): Promise<PutResult>;
  delete(name: string, sequence: number): Promise<DeleteResult>;
  close(): Promise<void>;
}

export interface AcmeAccountStore {
  init?(): Promise<void>;
  getAccountKey(): Promise<string | null>;
  saveAccountKey(pem: string): Promise<void>;
  close(): Promise<void>;
}

export interface CertRateLimiter {
  init?(): Promise<void>;
  recordIssuance(name: string): Promise<void>;
  countRecentIssuances(name: string, windowMs: number): Promise<number>;
  close(): Promise<void>;
}
