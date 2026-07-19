import { webcrypto } from "node:crypto";
import * as x509 from "@peculiar/x509";
import type { AcmeAuthorization, AcmeChallenge, AcmeClientLike, AcmeOrder } from "../acme.js";

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

/**
 * In-process fake of acme-client's Client. Stands in for a real ACME
 * directory in tests: drives the same createOrder -> getAuthorizations ->
 * completeChallenge -> finalizeOrder -> getCertificate flow as
 * DnsO1AcmeIssuer expects, and issues a self-signed leaf certificate for the
 * CSR's public key once challenges are "completed". No network calls.
 *
 * Uses @peculiar/x509 (not node-forge) so it can parse and sign CSRs for
 * either RSA or ECDSA node keys -- forge cannot parse an EC CSR at all.
 */
export class FakeAcmeClient implements AcmeClientLike {
  readonly completedChallenges: AcmeChallenge[] = [];
  private lastCsr: string | Buffer | undefined;
  private caKeysPromise = webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );

  async createAccount(): Promise<unknown> {
    return { status: "valid" };
  }

  async createOrder(input: {
    identifiers: Array<{ type: "dns"; value: string }>;
  }): Promise<AcmeOrder> {
    return {
      url: "https://fake-acme.test/order/1",
      status: "pending",
      identifiers: input.identifiers,
    };
  }

  async getAuthorizations(order: AcmeOrder): Promise<AcmeAuthorization[]> {
    return order.identifiers.map((identifier, index) => ({
      identifier,
      challenges: [
        {
          type: "dns-01",
          token: `token-${index}`,
          url: `https://fake-acme.test/challenge/${index}`,
          status: "pending",
        },
      ],
    }));
  }

  async getChallengeKeyAuthorization(challenge: AcmeChallenge): Promise<string> {
    return `${challenge.token}.fake-thumbprint`;
  }

  async completeChallenge(challenge: AcmeChallenge): Promise<AcmeChallenge> {
    this.completedChallenges.push(challenge);
    return { ...challenge, status: "valid" };
  }

  async waitForValidStatus<T>(item: T): Promise<T> {
    return item;
  }

  async finalizeOrder(order: AcmeOrder, csr: string | Buffer): Promise<AcmeOrder> {
    this.lastCsr = csr;
    return { ...order, status: "valid" };
  }

  async getCertificate(): Promise<string> {
    if (!this.lastCsr) {
      throw new Error("finalizeOrder must be called before getCertificate");
    }
    const csr = new x509.Pkcs10CertificateRequest(this.lastCsr.toString());
    const caKeys = await this.caKeysPromise;

    const cert = await x509.X509CertificateGenerator.create({
      serialNumber: "01",
      subject: csr.subjectName,
      issuer: "CN=Fake Test CA",
      notBefore: new Date(),
      notAfter: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
      signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
      publicKey: csr.publicKey,
      signingKey: caKeys.privateKey,
    });

    return cert.toString("pem");
  }
}
