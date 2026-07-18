/**
 * DID signature verification, ported from @tinycloud-registry/location-registry's
 * src/records.ts (packages/location-registry in TinyCloudLabs/registry). Same two
 * subject schemes: did:pkh (EIP-191 personal_sign over a canonical JSON payload)
 * and did:key (Ed25519, base58btc multibase, signature is base64url).
 */
import { bases } from "multiformats/basics";
import { ed25519 } from "@noble/curves/ed25519";
import { verifyMessage } from "viem";

export class SignatureVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SignatureVerificationError";
  }
}

export function isSupportedSubject(subject: string): boolean {
  return subject.startsWith("did:pkh:") || subject.startsWith("did:key:");
}

export async function verifySignedPayload(
  subject: string,
  payload: string,
  signature: string
): Promise<boolean> {
  if (subject.startsWith("did:pkh:")) {
    return verifyPkhSignature(subject, payload, signature);
  }
  if (subject.startsWith("did:key:")) {
    return verifyDidKeySignature(subject, payload, signature);
  }
  return false;
}

async function verifyPkhSignature(
  did: string,
  payload: string,
  signature: string
): Promise<boolean> {
  const parts = did.split(":");
  const address = parts[parts.length - 1];
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
    throw new SignatureVerificationError("did:pkh subject must end with an EVM address");
  }
  if (!/^0x[0-9a-fA-F]+$/.test(signature)) {
    throw new SignatureVerificationError("did:pkh signature must be a hex string");
  }

  return verifyMessage({
    address: address as `0x${string}`,
    message: payload,
    signature: signature as `0x${string}`,
  });
}

function verifyDidKeySignature(did: string, payload: string, signature: string): boolean {
  const publicKey = ed25519PublicKeyFromDidKey(did);
  const signatureBytes = decodeBase64Url(signature);
  if (signatureBytes.length !== 64) {
    throw new SignatureVerificationError("did:key signature must be a base64url Ed25519 signature");
  }

  return ed25519.verify(signatureBytes, new TextEncoder().encode(payload), publicKey);
}

function ed25519PublicKeyFromDidKey(did: string): Uint8Array {
  const identifier = did.slice("did:key:".length);
  if (!identifier.startsWith("z")) {
    throw new SignatureVerificationError("did:key must use base58btc multibase");
  }

  const bytes = bases.base58btc.decode(identifier);
  if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) {
    throw new SignatureVerificationError("did:key must be an Ed25519 public key");
  }

  return bytes.slice(2);
}

function decodeBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
  return Uint8Array.from(Buffer.from(padded, "base64"));
}
