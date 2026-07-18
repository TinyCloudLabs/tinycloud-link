import forge from "node-forge";

/** Builds a real PKCS#10 CSR PEM for tests, without shelling out to openssl. */
export function createTestCsr(commonName: string, altNames: string[] = [commonName]): string {
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
          altNames: altNames.map((value) => ({ type: 2, value })),
        },
      ],
    },
  ]);
  csr.sign(keys.privateKey, forge.md.sha256.create());
  return forge.pki.certificationRequestToPem(csr);
}
