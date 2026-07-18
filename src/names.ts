import forge from "node-forge";
import { isPrivateAddress } from "./ip.js";
import { isSupportedSubject, verifySignedPayload } from "./crypto-verify.js";

export const DOMAIN_SUFFIX = "local.tinycloud.link";
export const MAX_LAN_IPS = 8;

export function fqdnForName(name: string): string {
  return `${name}.${DOMAIN_SUFFIX}`;
}

const NAME_LABEL_PATTERN = /^[a-z0-9]([a-z0-9-]{1,30}[a-z0-9])?$/;

// Reserved so a claimed name can never collide with infrastructure, the
// zone apex, or a future first-party subdomain under local.tinycloud.link.
export const RESERVED_NAMES: ReadonlySet<string> = new Set([
  "www",
  "api",
  "admin",
  "root",
  "mail",
  "ftp",
  "ns",
  "ns1",
  "ns2",
  "localhost",
  "local",
  "tinycloud",
  "status",
  "docs",
  "app",
  "dashboard",
  "cert",
  "certs",
  "acme",
  "dns",
  "health",
  "attestation",
  "v1",
  "test",
  "staging",
]);

export class NameError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NameError";
  }
}

export function validateNameLabel(name: unknown): string {
  if (typeof name !== "string") {
    throw new NameError("name must be a string");
  }
  const lower = name.toLowerCase();
  if (lower.length < 3 || lower.length > 32) {
    throw new NameError("name must be 3-32 characters");
  }
  if (!NAME_LABEL_PATTERN.test(lower)) {
    throw new NameError(
      "name must be a dns-safe label (lowercase letters, digits, hyphens; cannot start or end with a hyphen)"
    );
  }
  if (lower.startsWith("xn--")) {
    throw new NameError('name must not be a punycode ("xn--") label');
  }
  if (RESERVED_NAMES.has(lower)) {
    throw new NameError(`name "${lower}" is reserved`);
  }
  return lower;
}

function validateSubject(subject: unknown): string {
  if (typeof subject !== "string" || !isSupportedSubject(subject)) {
    throw new NameError("subject must be a did:pkh or did:key DID");
  }
  return subject;
}

function validateSequence(sequence: unknown): number {
  if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 0) {
    throw new NameError("sequence must be a non-negative safe integer");
  }
  return sequence;
}

function validateSignature(signature: unknown): string {
  if (typeof signature !== "string" || signature.length === 0) {
    throw new NameError("signature must be a non-empty string");
  }
  return signature;
}

function validateLanIps(lanIps: unknown): string[] {
  if (!Array.isArray(lanIps) || lanIps.length === 0) {
    throw new NameError("lanIps must be a non-empty array");
  }
  if (lanIps.length > MAX_LAN_IPS) {
    throw new NameError(`lanIps must contain at most ${MAX_LAN_IPS} addresses`);
  }
  for (const ip of lanIps) {
    if (typeof ip !== "string" || !isPrivateAddress(ip)) {
      throw new NameError(`lanIps entry is not a private-range IPv4/IPv6 address: ${String(ip)}`);
    }
  }
  return [...(lanIps as string[])];
}

// --- claim (PUT /v1/names/:name) ---

export interface NameClaimPayload {
  version: 1;
  action: "claim";
  name: string;
  subject: string;
  lanIps: string[];
  sequence: number;
}

export interface NameClaimRecord extends NameClaimPayload {
  signature: string;
}

export function canonicalClaimPayload(payload: NameClaimPayload): string {
  return JSON.stringify({
    version: payload.version,
    action: payload.action,
    name: payload.name,
    subject: payload.subject,
    lanIps: payload.lanIps,
    sequence: payload.sequence,
  });
}

export function validateNameClaim(input: unknown): NameClaimRecord {
  if (input === null || typeof input !== "object") {
    throw new NameError("body must be an object");
  }
  const body = input as Partial<NameClaimRecord>;
  if (body.version !== 1) {
    throw new NameError("version must be 1");
  }
  if (body.action !== "claim") {
    throw new NameError('action must be "claim"');
  }

  return {
    version: 1,
    action: "claim",
    name: validateNameLabel(body.name),
    subject: validateSubject(body.subject),
    lanIps: validateLanIps(body.lanIps),
    sequence: validateSequence(body.sequence),
    signature: validateSignature(body.signature),
  };
}

export async function verifyNameClaim(record: NameClaimRecord): Promise<boolean> {
  return verifySignedPayload(record.subject, canonicalClaimPayload(record), record.signature);
}

// --- delete (DELETE /v1/names/:name) ---

export interface NameDeletePayload {
  version: 1;
  action: "delete";
  name: string;
  subject: string;
  sequence: number;
}

export interface NameDeleteRecord extends NameDeletePayload {
  signature: string;
}

export function canonicalDeletePayload(payload: NameDeletePayload): string {
  return JSON.stringify({
    version: payload.version,
    action: payload.action,
    name: payload.name,
    subject: payload.subject,
    sequence: payload.sequence,
  });
}

export function validateNameDelete(input: unknown): NameDeleteRecord {
  if (input === null || typeof input !== "object") {
    throw new NameError("body must be an object");
  }
  const body = input as Partial<NameDeleteRecord>;
  if (body.version !== 1) {
    throw new NameError("version must be 1");
  }
  if (body.action !== "delete") {
    throw new NameError('action must be "delete"');
  }

  return {
    version: 1,
    action: "delete",
    name: validateNameLabel(body.name),
    subject: validateSubject(body.subject),
    sequence: validateSequence(body.sequence),
    signature: validateSignature(body.signature),
  };
}

export async function verifyNameDelete(record: NameDeleteRecord): Promise<boolean> {
  return verifySignedPayload(record.subject, canonicalDeletePayload(record), record.signature);
}

// --- cert request (POST /v1/certs/:name) ---

export interface CertRequestPayload {
  version: 1;
  action: "cert";
  name: string;
  subject: string;
  csr: string;
  sequence: number;
}

export interface CertRequestRecord extends CertRequestPayload {
  signature: string;
}

export function canonicalCertRequestPayload(payload: CertRequestPayload): string {
  return JSON.stringify({
    version: payload.version,
    action: payload.action,
    name: payload.name,
    subject: payload.subject,
    csr: payload.csr,
    sequence: payload.sequence,
  });
}

export function validateCertRequest(input: unknown): CertRequestRecord {
  if (input === null || typeof input !== "object") {
    throw new NameError("body must be an object");
  }
  const body = input as Partial<CertRequestRecord>;
  if (body.version !== 1) {
    throw new NameError("version must be 1");
  }
  if (body.action !== "cert") {
    throw new NameError('action must be "cert"');
  }
  if (typeof body.csr !== "string" || !body.csr.includes("BEGIN CERTIFICATE REQUEST")) {
    throw new NameError("csr must be a PEM-encoded PKCS#10 certificate request");
  }

  return {
    version: 1,
    action: "cert",
    name: validateNameLabel(body.name),
    subject: validateSubject(body.subject),
    csr: body.csr,
    sequence: validateSequence(body.sequence),
    signature: validateSignature(body.signature),
  };
}

export async function verifyCertRequest(record: CertRequestRecord): Promise<boolean> {
  return verifySignedPayload(record.subject, canonicalCertRequestPayload(record), record.signature);
}

/**
 * Enforces that the CSR's CN and its complete SAN set is exactly the
 * expected <name>.local.tinycloud.link domain as a single dNSName entry --
 * nothing broader, nothing else, no SAN entries of any other type.
 */
export function assertCsrMatchesDomain(csrPem: string, expectedDomain: string): void {
  let csr: forge.pki.CertificateSigningRequest;
  try {
    csr = forge.pki.certificationRequestFromPem(csrPem);
  } catch {
    throw new NameError("csr must be a valid PEM-encoded PKCS#10 certificate request");
  }

  const cnField = csr.subject.getField("CN");
  const cn = cnField ? cnField.value : undefined;

  const extensionRequest = csr.getAttribute({ name: "extensionRequest" });
  const sanExtension = (extensionRequest?.extensions ?? []).find(
    (ext: { name?: string }) => ext.name === "subjectAltName"
  ) as { altNames?: Array<{ type: number; value: string }> } | undefined;
  const altNames = sanExtension?.altNames ?? [];
  for (const entry of altNames) {
    if (entry.type !== 2) {
      // 2 = dNSName
      throw new NameError(
        `csr subjectAltName must contain only a dNSName entry for ${expectedDomain} (found an entry of type ${entry.type})`
      );
    }
  }
  const sanNames = altNames.map((entry) => entry.value);

  const names = new Set<string>([...(cn ? [cn] : []), ...sanNames]);

  if (names.size === 0) {
    throw new NameError("csr must include a CN or subjectAltName DNS entry");
  }
  if (names.size > 1 || !names.has(expectedDomain)) {
    throw new NameError(`csr CN/SAN must be exactly ${expectedDomain}`);
  }
}
