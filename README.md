# tinycloud-link

The `tinycloud.link` name + certificate control plane. This is the Tier 2 piece of "Plex-style local HTTPS" for TinyCloud nodes: a local node running on someone's home network gets a real public DNS name that resolves to its LAN IP, and a real Let's Encrypt certificate for that name -- so any device on the LAN (phone, tablet, laptop, nothing installed) can open `https://<name>.local.tinycloud.link` and get a green padlock while every byte of traffic stays on the LAN. No VPN, no self-signed cert warning, no port forwarding.

This works because DNS and TLS validation are two different trust problems and only one of them needs a public network. `local.tinycloud.link` is a normal public DNS zone -- any DNS resolver on the planet can look up `mynode.local.tinycloud.link` and get back a private-range IP like `192.168.1.42`, because DNS answers are just data and nothing stops an A record from pointing at RFC1918 space. Certificate issuance is where the ACME protocol usually assumes a publicly reachable server, which a LAN node is not. ACME's DNS-01 challenge sidesteps that: instead of proving control of the domain by serving a file over HTTP, the requester proves control by publishing a TXT record under `_acme-challenge.<name>.local.tinycloud.link`. This service is the only thing with write access to that DNS zone, so it's the only thing that can complete a DNS-01 challenge on a node's behalf -- which is exactly the point of centralizing it here instead of asking every home node to hold DNS provider credentials.

The security model is deliberately narrow. tinycloud-link never sees a node's private key: the node generates its own keypair locally, builds a CSR, and sends only the CSR (a public-key artifact) to this service. The service completes the ACME order using its own DNS-write credentials and hands back the signed certificate chain; the node then serves TLS locally using a key that has never left the device. First-come-first-served claim-by-signature means a name belongs to whichever DID first claims it and can prove it on every subsequent write via a monotonically increasing sequence number (replay protection, same pattern as `@tinycloud-registry/location-registry`). The one thing this design cannot hide is the *existence* of a name: every certificate this service issues is published to public Certificate Transparency logs by the CA, so `mynode.local.tinycloud.link` having a valid cert is discoverable by anyone watching CT logs, even though its IP is meaningless outside the LAN it belongs to. See "Security notes" below.

## Node-side flow

```
                     tinycloud-link (this service)
                     owns DNS for *.local.tinycloud.link
                     brokers ACME orders, never touches node keys
                              |
   1. claim name              |
   node --PUT /v1/names/mynode-->  validates name, checks private-range IPs,
   {name, subject, lanIps,    |    verifies signature, upserts A/AAAA record
    sequence, signature}      |    mynode.local.tinycloud.link -> 192.168.1.42
                              |
   2. generate local keypair  |
      + build CSR for         |
      mynode.local.tinycloud.link
      (private key stays on   |
       the node, always)      |
                              |
   3. request cert            |
   node --POST /v1/certs/mynode-->  verifies name ownership + signature,
   {csr, subject, sequence,   |    opens ACME order, completes DNS-01 by
    signature}                |    publishing _acme-challenge TXT record,
                              |    finalizes order with the node's CSR
                              |
   4. cert chain returned     |
   <---- {certChainPem, ------|
          notAfter}           |
                              |
   5. node serves HTTPS on its LAN IP using the returned cert + its own
      private key. Any device on the LAN visiting
      https://mynode.local.tinycloud.link gets a browser-trusted cert.
```

## API (all under `/v1`, JSON)

Every write is a signed record: `subject` is the node's `did:pkh` (EIP-191 / `personal_sign`) or `did:key` (Ed25519, base58btc) DID, `signature` covers a canonical JSON payload (fixed key order, signature field excluded), and `sequence` must strictly increase per name to prevent replay. The DID verification code is ported from [`@tinycloud-registry/location-registry`](https://github.com/TinyCloudLabs/registry/blob/main/packages/location-registry/src/records.ts)'s `records.ts` (`src/crypto-verify.ts`, credited in comments).

```
GET    /health
GET    /attestation

GET    /v1/names/:name
PUT    /v1/names/:name
DELETE /v1/names/:name

POST   /v1/certs/:name
```

### `PUT /v1/names/:name`

Claims or updates a name. First-come-first-served: any subject can claim an unclaimed name, but only the current owner can update it (a claim attempt from a different subject once a name is owned returns `409`).

```json
{
  "version": 1,
  "action": "claim",
  "name": "mynode",
  "subject": "did:key:z6Mk...",
  "lanIps": ["192.168.1.42"],
  "sequence": 1,
  "signature": "..."
}
```

- `name`: 3-32 char dns-safe label, lowercase letters/digits/hyphens, not on the reserved list (`www`, `api`, `admin`, `acme`, ...).
- `lanIps`: 1-8 addresses, **private-range only** (RFC1918, link-local, loopback, ULA) -- public IPs are rejected. This namespace exists for LAN addresses.
- On success, upserts A/AAAA records for `<name>.local.tinycloud.link` via the DNS provider and returns `201` (created) or `200` (updated).

### `DELETE /v1/names/:name`

Signed the same way (`action: "delete"`, no `lanIps`). Releases the name and removes its DNS records. Requires the current owner's signature.

### `GET /v1/names/:name`

Public, unsigned. Returns `{ name, subject, lanIps, updatedAt }` or `404`.

### `POST /v1/certs/:name`

```json
{
  "version": 1,
  "action": "cert",
  "name": "mynode",
  "subject": "did:key:z6Mk...",
  "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
  "sequence": 2,
  "signature": "..."
}
```

- Verifies the requester owns `name` and the signature is valid.
- The CSR's CN and every SAN entry must be **exactly** `<name>.local.tinycloud.link` -- no wildcards, no extra names. The CSR's key may be RSA or ECDSA (P-256); both are validated identically (`src/names.ts`'s `assertCsrMatchesDomain` parses with `@peculiar/x509`, not node-forge, specifically so ECDSA node keys aren't rejected).
- Rate-limited to 5 issuances/day per name to protect Let's Encrypt's rate limits.
- **Sequence is bumped before the ACME round trip, not after.** Once the request passes ownership/signature/CSR checks, the handler immediately persists the new `sequence` on the name record and only then calls the ACME issuer. This is deliberate: an ACME DNS-01 order is slow (DNS propagation + CA validation, seconds to tens of seconds) and not idempotent to retry blindly, so the sequence bump has to happen *before* it, not after it succeeds. That way a replayed or concurrent request carrying the same (now-stale) sequence number is rejected with `409` immediately instead of racing a second ACME order for the same name while the first is still in flight. The tradeoff: if the ACME call itself fails after the bump (rate limit, DNS-01 timeout, CA outage), the sequence has still moved forward and the node must retry with a strictly higher sequence, not the same one -- there is no "undo" of the bump on failure.
- Opens an ACME order against `ACME_DIRECTORY` (Let's Encrypt staging by default), completes it via DNS-01 through the configured `DnsProvider`, finalizes with the node's CSR, and returns `{ certChainPem, notAfter }`.
- The private key backing the CSR is generated and held by the node. It is never transmitted to or stored by this service.

## DNS provider

`src/dns/provider.ts` defines the `DnsProvider` interface (`upsertAddressRecords`, `deleteAddressRecords`, `createTxtRecord`, `deleteTxtRecord`). `src/dns/cloudflare.ts` is the production implementation against the Cloudflare API (zone id + token from env). `src/dns/memory.ts` is an in-memory fake used by tests -- no test ever makes a live DNS or ACME call.

## ACME

`src/acme.ts`'s `DnsO1AcmeIssuer` drives `acme-client` through account creation, order creation, DNS-01 challenge completion (via the injected `DnsProvider`), finalization with the node-supplied CSR, and certificate retrieval. The ACME account private key is generated once and persisted in `acme_account` (Postgres) so the same account is reused across restarts. Tests inject a fake implementing the same minimal `AcmeClientLike` interface (`src/test-support/fake-acme-client.ts`) instead of hitting a real ACME directory.

## Storage

Postgres, following the same client approach as `location-registry`'s `postgres.ts` (plain `pg.Pool`, optimistic sequence-guarded upserts). Tables: `names`, `acme_account`, `cert_issuances` (rate-limit tracking). Migrations are kept for manual inspection/provisioning; the service also creates these tables on startup:

```bash
psql "$DATABASE_URL" -f migrations/001_names.sql
psql "$DATABASE_URL" -f migrations/002_acme_account.sql
psql "$DATABASE_URL" -f migrations/003_cert_issuances.sql
```

## Development

```bash
npm install
npm run typecheck
npm test
npm run build
DATABASE_URL=postgres://... CLOUDFLARE_API_TOKEN=... CLOUDFLARE_ZONE_ID=... ACME_EMAIL=... npm run dev
```

Copy `.env.example` to `.env` and fill in real values for local development against a real Postgres instance. Tests never require any of these -- they run entirely against in-memory fakes.

## Container

```bash
docker build --platform linux/amd64 -t tinycloud/tinycloud-link .
docker run -p 3000:3000 --env-file .env tinycloud/tinycloud-link
```

## Deploy to Phala

`docker-compose.phala.yml` is the production template: it runs the API, Postgres, and `dstack-ingress` for a public HTTPS front door at `api.tinycloud.link` (the control-plane API's own hostname -- distinct from the `*.local.tinycloud.link` zone it manages for nodes).

1. `phala auth login` (interactive; requires a human with a Phala Cloud account -- **not done for this build**).
2. Push this repo's image via the `Docker Image` GitHub Actions workflow (builds on `main`, publishes `ghcr.io/tinycloudlabs/tinycloud-link:main`).
3. In the Phala Cloud Docker Compose editor, paste `docker-compose.phala.yml` and set these encrypted secrets:
   - `POSTGRES_PASSWORD`
   - `CLOUDFLARE_API_TOKEN` (**not provisioned for this build** -- needs a Cloudflare API token scoped to the `tinycloud.link` zone)
   - `CLOUDFLARE_ZONE_ID` (**not provisioned** -- needs the `tinycloud.link` zone to exist in Cloudflare and its zone id)
   - `ACME_EMAIL`
   - `CERTBOT_EMAIL` (used by `dstack-ingress` for the API's own front-door cert)
   - `DSTACK_GATEWAY_DOMAIN`
4. Point `api.tinycloud.link` at the deployment's dstack gateway (human DNS step, same pattern as `registry.tinycloud.xyz`).
5. Verify:
   ```bash
   curl https://api.tinycloud.link/health
   curl https://api.tinycloud.link/attestation
   ```

This build does not attempt any live ACME or DNS calls, and does not deploy to Phala -- both require credentials/auth that only a human on the team holds (see the two blockers above).

## Security notes

- **Private keys never leave the node.** The node generates its TLS keypair and CSR locally; only the CSR (a public artifact) is sent to this service. tinycloud-link never possesses, stores, or transmits a node's private key.
- **Certificate Transparency discloses names.** Every certificate Let's Encrypt issues is logged publicly (CT logs, e.g. crt.sh). Anyone can enumerate every name ever claimed under `*.local.tinycloud.link` this way. The private LAN IP behind each name is not disclosed by CT logs, but the name itself, and the fact that someone runs a node there, is public information. Users should not choose names that leak identity they don't want correlated.
- **The TEE holds only DNS + ACME credentials**, not node data or node keys. A compromise of this service's TEE would let an attacker redirect `*.local.tinycloud.link` names or mis-issue certificates for them -- it would not expose any node's private key, data, or LAN traffic content, since none of that ever transits or is stored here.
- **Sequence numbers prevent replay** of captured claim/delete/cert-request payloads; a name's owner is whoever holds the private key for the DID that claimed it first (first-come-first-served) and every write must be signed by that same key with a strictly increasing sequence number.
