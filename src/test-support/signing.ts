import { ed25519 } from "@noble/curves/ed25519";
import { bases } from "multiformats/basics";
import { privateKeyToAccount } from "viem/accounts";

export interface Signer {
  subject: string;
  sign(payload: string): Promise<string>;
}

export function pkhSigner(privateKeyHex: `0x${string}`): Signer {
  const account = privateKeyToAccount(privateKeyHex);
  return {
    subject: `did:pkh:eip155:1:${account.address}`,
    sign: (payload) => account.signMessage({ message: payload }),
  };
}

export function didKeySigner(seed: number): Signer {
  const privateKey = new Uint8Array(32).fill(seed);
  const publicKey = ed25519.getPublicKey(privateKey);
  const did = `did:key:${bases.base58btc.encode(Uint8Array.of(0xed, 0x01, ...publicKey))}`;
  return {
    subject: did,
    sign: async (payload) =>
      Buffer.from(ed25519.sign(new TextEncoder().encode(payload), privateKey)).toString("base64url"),
  };
}
