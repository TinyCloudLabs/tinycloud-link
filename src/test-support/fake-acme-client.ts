import forge from "node-forge";
import type { AcmeAuthorization, AcmeChallenge, AcmeClientLike, AcmeOrder } from "../acme.js";

/**
 * In-process fake of acme-client's Client. Stands in for a real ACME
 * directory in tests: drives the same createOrder -> getAuthorizations ->
 * completeChallenge -> finalizeOrder -> getCertificate flow as
 * DnsO1AcmeIssuer expects, and issues a self-signed leaf certificate for the
 * CSR's public key once challenges are "completed". No network calls.
 */
export class FakeAcmeClient implements AcmeClientLike {
  readonly completedChallenges: AcmeChallenge[] = [];
  private lastCsr: string | Buffer | undefined;
  private readonly caKeys = forge.pki.rsa.generateKeyPair(1024);

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
    const csr = forge.pki.certificationRequestFromPem(this.lastCsr.toString());

    const cert = forge.pki.createCertificate();
    cert.publicKey = csr.publicKey!;
    cert.serialNumber = "01";
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);
    cert.setSubject(csr.subject.attributes);
    cert.setIssuer([{ name: "commonName", value: "Fake Test CA" }]);
    cert.sign(this.caKeys.privateKey, forge.md.sha256.create());

    return forge.pki.certificateToPem(cert);
  }
}
