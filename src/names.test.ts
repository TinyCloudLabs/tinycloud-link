import assert from "node:assert/strict";
import test from "node:test";
import {
  NameError,
  assertCsrMatchesDomain,
  canonicalCertRequestPayload,
  canonicalClaimPayload,
  canonicalDeletePayload,
  fqdnForName,
  validateCertRequest,
  validateNameClaim,
  validateNameDelete,
  verifyCertRequest,
  verifyNameClaim,
  verifyNameDelete,
} from "./names.js";
import { createTestCsr } from "./test-support/csr.js";
import { didKeySigner, pkhSigner } from "./test-support/signing.js";

test("validates and verifies a did:key name claim", async () => {
  const signer = didKeySigner(7);
  const unsigned = {
    version: 1 as const,
    action: "claim" as const,
    name: "mynode",
    subject: signer.subject,
    lanIps: ["192.168.1.20"],
    sequence: 1,
  };
  const signature = await signer.sign(canonicalClaimPayload(unsigned));
  const record = { ...unsigned, signature };

  assert.deepEqual(validateNameClaim(record), record);
  assert.equal(await verifyNameClaim(record), true);
});

test("validates and verifies a did:pkh name claim", async () => {
  const signer = pkhSigner(
    "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  );
  const unsigned = {
    version: 1 as const,
    action: "claim" as const,
    name: "living-room",
    subject: signer.subject,
    lanIps: ["10.0.0.5", "fd00::5"],
    sequence: 1,
  };
  const signature = await signer.sign(canonicalClaimPayload(unsigned));
  const record = { ...unsigned, signature };

  assert.deepEqual(validateNameClaim(record), record);
  assert.equal(await verifyNameClaim(record), true);
});

test("rejects a tampered claim signature", async () => {
  const signer = didKeySigner(9);
  const unsigned = {
    version: 1 as const,
    action: "claim" as const,
    name: "tamperednode",
    subject: signer.subject,
    lanIps: ["10.0.0.9"],
    sequence: 1,
  };
  const signature = await signer.sign(canonicalClaimPayload(unsigned));
  const record = { ...unsigned, lanIps: ["10.0.0.99"], signature };

  assert.equal(await verifyNameClaim(record), false);
});

test("canonical claim payload excludes signature and preserves field order", () => {
  assert.equal(
    canonicalClaimPayload({
      version: 1,
      action: "claim",
      name: "office",
      subject: "did:key:z6MkiFake",
      lanIps: ["192.168.0.10"],
      sequence: 4,
    }),
    '{"version":1,"action":"claim","name":"office","subject":"did:key:z6MkiFake","lanIps":["192.168.0.10"],"sequence":4}'
  );
});

test("canonical delete payload excludes signature and preserves field order", () => {
  assert.equal(
    canonicalDeletePayload({
      version: 1,
      action: "delete",
      name: "office",
      subject: "did:key:z6MkiFake",
      sequence: 5,
    }),
    '{"version":1,"action":"delete","name":"office","subject":"did:key:z6MkiFake","sequence":5}'
  );
});

test("rejects names shorter than 3 characters", () => {
  assert.throws(
    () =>
      validateNameClaim({
        version: 1,
        action: "claim",
        name: "ab",
        subject: "did:key:z6MkiFake",
        lanIps: ["10.0.0.1"],
        sequence: 1,
        signature: "sig",
      }),
    NameError
  );
});

test("rejects names longer than 32 characters", () => {
  assert.throws(
    () =>
      validateNameClaim({
        version: 1,
        action: "claim",
        name: "a".repeat(33),
        subject: "did:key:z6MkiFake",
        lanIps: ["10.0.0.1"],
        sequence: 1,
        signature: "sig",
      }),
    NameError
  );
});

test("rejects names with invalid dns characters", () => {
  assert.throws(
    () =>
      validateNameClaim({
        version: 1,
        action: "claim",
        name: "-leading-hyphen",
        subject: "did:key:z6MkiFake",
        lanIps: ["10.0.0.1"],
        sequence: 1,
        signature: "sig",
      }),
    NameError
  );
  assert.throws(
    () =>
      validateNameClaim({
        version: 1,
        action: "claim",
        name: "has_underscore",
        subject: "did:key:z6MkiFake",
        lanIps: ["10.0.0.1"],
        sequence: 1,
        signature: "sig",
      }),
    NameError
  );
});

test("rejects reserved names", () => {
  for (const reserved of ["api", "www", "admin", "acme"]) {
    assert.throws(
      () =>
        validateNameClaim({
          version: 1,
          action: "claim",
          name: reserved,
          subject: "did:key:z6MkiFake",
          lanIps: ["10.0.0.1"],
          sequence: 1,
          signature: "sig",
        }),
      /reserved/
    );
  }
});

test("rejects public IP addresses in lanIps", () => {
  assert.throws(
    () =>
      validateNameClaim({
        version: 1,
        action: "claim",
        name: "mynode",
        subject: "did:key:z6MkiFake",
        lanIps: ["8.8.8.8"],
        sequence: 1,
        signature: "sig",
      }),
    /not a private-range/
  );
});

test("rejects an empty lanIps array", () => {
  assert.throws(
    () =>
      validateNameClaim({
        version: 1,
        action: "claim",
        name: "mynode",
        subject: "did:key:z6MkiFake",
        lanIps: [],
        sequence: 1,
        signature: "sig",
      }),
    /non-empty array/
  );
});

test("validates and verifies a name delete record", async () => {
  const signer = didKeySigner(11);
  const unsigned = {
    version: 1 as const,
    action: "delete" as const,
    name: "gone-node",
    subject: signer.subject,
    sequence: 2,
  };
  const signature = await signer.sign(canonicalDeletePayload(unsigned));
  const record = { ...unsigned, signature };

  assert.deepEqual(validateNameDelete(record), record);
  assert.equal(await verifyNameDelete(record), true);
});

test("validates and verifies a cert request record", async () => {
  const signer = didKeySigner(13);
  const domain = fqdnForName("certnode");
  const csr = createTestCsr(domain);
  const unsigned = {
    version: 1 as const,
    action: "cert" as const,
    name: "certnode",
    subject: signer.subject,
    csr,
    sequence: 2,
  };
  const signature = await signer.sign(canonicalCertRequestPayload(unsigned));
  const record = { ...unsigned, signature };

  assert.deepEqual(validateCertRequest(record), record);
  assert.equal(await verifyCertRequest(record), true);
});

test("csr domain check accepts an exact CN/SAN match", () => {
  const domain = fqdnForName("mynode");
  const csr = createTestCsr(domain);
  assert.doesNotThrow(() => assertCsrMatchesDomain(csr, domain));
});

test("csr domain check rejects a mismatched domain", () => {
  const domain = fqdnForName("mynode");
  const csr = createTestCsr(domain);
  assert.throws(() => assertCsrMatchesDomain(csr, fqdnForName("othernode")), NameError);
});

test("csr domain check rejects a csr with extra SAN entries", () => {
  const domain = fqdnForName("mynode");
  const csr = createTestCsr(domain, [domain, "evil.example.com"]);
  assert.throws(() => assertCsrMatchesDomain(csr, domain), NameError);
});
