import forge from "node-forge";

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
