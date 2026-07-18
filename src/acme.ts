import { X509Certificate } from "node:crypto";
import * as acme from "acme-client";
import type { DnsProvider } from "./dns/provider.js";

export interface AcmeIssueResult {
  certChainPem: string;
  notAfter: string;
}

export interface AcmeIssuer {
  issueCertificate(params: { csrPem: string; domain: string }): Promise<AcmeIssueResult>;
}

/**
 * Minimal surface of acme-client's Client we depend on. Kept as our own
 * interface (rather than importing acme-client's types directly) so tests can
 * supply a fully in-process fake instead of mocking the real ACME client.
 */
export interface AcmeChallenge {
  type: string;
  token: string;
  url: string;
  status: string;
}

export interface AcmeAuthorization {
  identifier: { type: string; value: string };
  challenges: AcmeChallenge[];
}

export interface AcmeOrder {
  url: string;
  status: string;
  identifiers: Array<{ type: string; value: string }>;
}

export interface AcmeClientLike {
  createAccount(input: { termsOfServiceAgreed: boolean; contact?: string[] }): Promise<unknown>;
  createOrder(input: { identifiers: Array<{ type: "dns"; value: string }> }): Promise<AcmeOrder>;
  getAuthorizations(order: AcmeOrder): Promise<AcmeAuthorization[]>;
  getChallengeKeyAuthorization(challenge: AcmeChallenge): Promise<string>;
  completeChallenge(challenge: AcmeChallenge): Promise<AcmeChallenge>;
  waitForValidStatus(item: AcmeChallenge | AcmeOrder): Promise<unknown>;
  finalizeOrder(order: AcmeOrder, csr: string | Buffer): Promise<AcmeOrder>;
  getCertificate(order: AcmeOrder): Promise<string>;
}

export type AcmeClientFactory = (directoryUrl: string, accountKeyPem: string) => AcmeClientLike;

export function defaultAcmeClientFactory(
  directoryUrl: string,
  accountKeyPem: string
): AcmeClientLike {
  return new acme.Client({
    directoryUrl,
    accountKey: accountKeyPem,
  }) as unknown as AcmeClientLike;
}

export interface DnsO1AcmeIssuerOptions {
  directoryUrl: string;
  accountKeyPem: string;
  email: string;
  dnsProvider: DnsProvider;
  clientFactory?: AcmeClientFactory;
  /** Delay after publishing the DNS-01 TXT record, before asking the CA to validate. */
  challengePropagationDelayMs?: number;
}

/** Issues a certificate via ACME DNS-01, brokering the challenge through a DnsProvider. */
export class DnsO1AcmeIssuer implements AcmeIssuer {
  constructor(private readonly opts: DnsO1AcmeIssuerOptions) {}

  async issueCertificate({
    csrPem,
    domain,
  }: {
    csrPem: string;
    domain: string;
  }): Promise<AcmeIssueResult> {
    const client = (this.opts.clientFactory ?? defaultAcmeClientFactory)(
      this.opts.directoryUrl,
      this.opts.accountKeyPem
    );

    await client.createAccount({
      termsOfServiceAgreed: true,
      contact: [`mailto:${this.opts.email}`],
    });

    const order = await client.createOrder({ identifiers: [{ type: "dns", value: domain }] });
    const authorizations = await client.getAuthorizations(order);

    const cleanups: Array<() => Promise<void>> = [];
    try {
      for (const authorization of authorizations) {
        const challenge = authorization.challenges.find((item) => item.type === "dns-01");
        if (!challenge) {
          throw new Error(`no dns-01 challenge offered for ${authorization.identifier.value}`);
        }

        const keyAuthorization = await client.getChallengeKeyAuthorization(challenge);
        const recordName = `_acme-challenge.${authorization.identifier.value}`;
        const record = await this.opts.dnsProvider.createTxtRecord(recordName, keyAuthorization);
        cleanups.push(() => this.opts.dnsProvider.deleteTxtRecord(recordName, record.id));

        if (this.opts.challengePropagationDelayMs) {
          await sleep(this.opts.challengePropagationDelayMs);
        }

        await client.completeChallenge(challenge);
        await client.waitForValidStatus(challenge);
      }

      const finalized = await client.finalizeOrder(order, csrPem);
      await client.waitForValidStatus(finalized);
      const certChainPem = await client.getCertificate(finalized);

      return { certChainPem, notAfter: extractNotAfter(certChainPem) };
    } finally {
      for (const cleanup of cleanups) {
        await cleanup().catch(() => {});
      }
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function extractNotAfter(certChainPem: string): string {
  const leafEnd = certChainPem.indexOf("-----END CERTIFICATE-----");
  const leafPem =
    leafEnd === -1
      ? certChainPem
      : certChainPem.slice(0, leafEnd + "-----END CERTIFICATE-----".length);
  const cert = new X509Certificate(leafPem);
  return new Date(cert.validTo).toISOString();
}
