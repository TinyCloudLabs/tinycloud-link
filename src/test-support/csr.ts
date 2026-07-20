import { webcrypto } from "node:crypto";
import forge from "node-forge";
import * as x509 from "@peculiar/x509";

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

/** A SAN entry: a bare string becomes a dNSName; an object passes through to forge as-is. */
export type TestAltName = string | { type: number; value?: string; ip?: string };

/** Builds a real PKCS#10 CSR PEM for tests, without shelling out to openssl. */
export function createTestCsr(commonName: string, altNames: TestAltName[] = [commonName]): string {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = keys.publicKey;
  csr.setSubject([{ name: "commonName", value: commonName }]);
  csr.setAttributes([
    {
      name: "extensionRequest",
      extensions: [
        {
          name: "subjectAltName",
          altNames: altNames.map((entry) =>
            typeof entry === "string" ? { type: 2, value: entry } : entry
          ),
        },
      ],
    },
  ]);
  csr.sign(keys.privateKey, forge.md.sha256.create());
  return forge.pki.certificationRequestToPem(csr);
}

/**
 * Builds a real PKCS#10 CSR PEM with an ECDSA P-256 key for tests. node-forge
 * cannot generate (or even parse) EC CSRs, so this uses @peculiar/x509 +
 * Node's WebCrypto directly -- the same library production code now uses to
 * validate CSRs (see assertCsrMatchesDomain in ../names.ts).
 */
export async function createTestEcCsr(
  commonName: string,
  altNames: string[] = [commonName]
): Promise<string> {
  const keys = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: `CN=${commonName}`,
    keys,
    signingAlgorithm: { name: "ECDSA", hash: "SHA-256" },
    extensions: [
      new x509.SubjectAlternativeNameExtension(
        altNames.map((value) => ({ type: "dns" as const, value }))
      ),
    ],
  });
  return csr.toString("pem");
}
