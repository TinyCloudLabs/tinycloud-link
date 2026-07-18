import assert from "node:assert/strict";
import test from "node:test";
import { DnsO1AcmeIssuer } from "./acme.js";
import { InMemoryDnsProvider } from "./dns/memory.js";
import { createTestCsr } from "./test-support/csr.js";
import { FakeAcmeClient } from "./test-support/fake-acme-client.js";

test("issues a certificate via DNS-01 using a fake acme-client and in-memory DNS provider", async () => {
  const dnsProvider = new InMemoryDnsProvider();
  const fakeClient = new FakeAcmeClient();
  const issuer = new DnsO1AcmeIssuer({
    directoryUrl: "https://fake-acme.test/directory",
    accountKeyPem: "fake-account-key",
    email: "ops@tinycloud.xyz",
    dnsProvider,
    clientFactory: () => fakeClient,
  });

  const domain = "mynode.local.tinycloud.link";
  const csr = createTestCsr(domain);

  const result = await issuer.issueCertificate({ csrPem: csr, domain });

  assert.match(result.certChainPem, /BEGIN CERTIFICATE/);
  assert.equal(Number.isNaN(Date.parse(result.notAfter)), false);
  assert.equal(fakeClient.completedChallenges.length, 1);
  assert.equal(fakeClient.completedChallenges[0].type, "dns-01");

  // Challenge TXT record must be published under _acme-challenge.<domain> and
  // cleaned up again once the order is finalized.
  assert.equal(dnsProvider.txtRecords.size, 0);
});

test("cleans up the DNS-01 TXT record even if the ACME order fails", async () => {
  const dnsProvider = new InMemoryDnsProvider();
  const fakeClient = new FakeAcmeClient();
  fakeClient.finalizeOrder = async () => {
    throw new Error("simulated CA rejection");
  };
  const issuer = new DnsO1AcmeIssuer({
    directoryUrl: "https://fake-acme.test/directory",
    accountKeyPem: "fake-account-key",
    email: "ops@tinycloud.xyz",
    dnsProvider,
    clientFactory: () => fakeClient,
  });

  const domain = "failingnode.local.tinycloud.link";
  const csr = createTestCsr(domain);

  await assert.rejects(() => issuer.issueCertificate({ csrPem: csr, domain }));
  assert.equal(dnsProvider.txtRecords.size, 0);
});
