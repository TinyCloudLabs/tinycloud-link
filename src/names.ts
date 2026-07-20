import * as x509 from "@peculiar/x509";
import { isPrivateAddress } from "./ip.js";
import { isSupportedSubject, verifySignedPayload } from "./crypto-verify.js";

export const DOMAIN_SUFFIX = "local.tinycloud.link";
export const MAX_LAN_IPS = 8;

export function fqdnForName(name: string): string {
  return `${name}.${DOMAIN_SUFFIX}`;
}

// The tunnel relay's namespace: <name>.tinycloud.link (the public apex zone,
// not the LAN-only local.tinycloud.link zone above). A name claimed via
// PUT /v1/names/:name is the same name a subject can open a tunnel for --
// there is one name registry, two surfaces (LAN A/AAAA records vs. a remote
// WebSocket tunnel).
export const REMOTE_DOMAIN_SUFFIX = "tinycloud.link";

export function remoteFqdnForName(name: string): string {
  return `${name}.${REMOTE_DOMAIN_SUFFIX}`;
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

// --- tunnel registration (first frame sent over wss://.../v1/tunnel/:name) ---
//
// Same signed-payload scheme as claim/delete/cert above: the node proves it
// owns `name` (already claimed via PUT /v1/names/:name) with a signature
// over a canonical payload and a strictly-increasing sequence, reusing the
// name record's own sequence counter for replay protection.

export interface TunnelAuthPayload {
  version: 1;
  action: "tunnel";
  name: string;
  subject: string;
  sequence: number;
}

export interface TunnelAuthRecord extends TunnelAuthPayload {
  signature: string;
}

export function canonicalTunnelAuthPayload(payload: TunnelAuthPayload): string {
  return JSON.stringify({
    version: payload.version,
    action: payload.action,
    name: payload.name,
    subject: payload.subject,
    sequence: payload.sequence,
  });
}

export function validateTunnelAuth(input: unknown): TunnelAuthRecord {
  if (input === null || typeof input !== "object") {
    throw new NameError("body must be an object");
  }
  const body = input as Partial<TunnelAuthRecord>;
  if (body.version !== 1) {
    throw new NameError("version must be 1");
  }
  if (body.action !== "tunnel") {
    throw new NameError('action must be "tunnel"');
  }

  return {
    version: 1,
    action: "tunnel",
    name: validateNameLabel(body.name),
    subject: validateSubject(body.subject),
    sequence: validateSequence(body.sequence),
    signature: validateSignature(body.signature),
  };
}

export async function verifyTunnelAuth(record: TunnelAuthRecord): Promise<boolean> {
  return verifySignedPayload(record.subject, canonicalTunnelAuthPayload(record), record.signature);
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

// OID for the subjectAltName X.509 extension (RFC 5280).
const SUBJECT_ALT_NAME_OID = "2.5.29.17";

/**
 * Enforces that the CSR's CN and its complete SAN set is exactly the
 * expected <name>.local.tinycloud.link domain as a single dNSName entry --
 * nothing broader, nothing else, no SAN entries of any other type.
 *
 * Parses with @peculiar/x509 (not node-forge): forge cannot parse CSRs with
 * an EC (e.g. ECDSA P-256) public key at all ("OID is not RSA"), which would
 * reject every ECDSA node CSR outright regardless of its CN/SAN. @peculiar/x509
 * parses the CSR's subject and extensions independently of the key algorithm,
 * so RSA and ECDSA CSRs are validated identically.
 */
export function assertCsrMatchesDomain(csrPem: string, expectedDomain: string): void {
  let csr: x509.Pkcs10CertificateRequest;
  try {
    csr = new x509.Pkcs10CertificateRequest(csrPem);
  } catch {
    throw new NameError("csr must be a valid PEM-encoded PKCS#10 certificate request");
  }

  const cn = csr.subjectName.getField("CN")[0];

  const sanExtension = csr.extensions.find((ext) => ext.type === SUBJECT_ALT_NAME_OID);
  const altNames =
    sanExtension instanceof x509.SubjectAlternativeNameExtension ? sanExtension.names.items : [];
  for (const entry of altNames) {
    if (entry.type !== "dns") {
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
