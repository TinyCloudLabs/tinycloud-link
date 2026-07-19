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

WS     /v1/tunnel/:name    (see "Remote reachability: the tunnel relay" below)
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

## Remote reachability: the tunnel relay

`*.local.tinycloud.link` only works on the node's own LAN. The tunnel relay (TC-85) adds a second, **remote** namespace for the same names: `https://<name>.tinycloud.link` (the apex zone, no `.local.`) is reachable from anywhere on the internet and is served by this process relaying each HTTPS request down a WebSocket the node itself opened. The node never needs an inbound port, a public IP, or NAT configuration -- it dials **out** to the relay and keeps that one socket alive.

There is one name registry with two surfaces: a name claimed via `PUT /v1/names/:name` gets LAN A/AAAA records (`<name>.local.tinycloud.link`) *and* the right to open a tunnel for `<name>.tinycloud.link`. Same owner, same signing key, same sequence counter.

**Sequence coordination is per-name, not per-operation**: `claim`/`delete` (`PUT`/`DELETE /v1/names/:name`), `cert` (`POST /v1/certs/:name`), and `tunnel` (the WS auth frame) all read and bump the *same* `sequence` column on the name's row in `names`. There is exactly one counter per name, shared across every action type -- a node must treat it as a single source of truth (e.g. keep one in-memory counter per name and increment it before every signed write, regardless of which endpoint), not maintain a separate counter per action. Reusing a sequence across two different action types for the same name is exactly as stale/rejected as reusing it for the same action twice.

### Lifecycle

```
   node                                      relay (this service)
    |                                             |
    |  1. WebSocket connect                       |
    |----- wss://api.tinycloud.link/v1/tunnel/<name> ---->|
    |                                             |
    |  2. auth frame (first WS message, JSON)     |
    |-------------------------------------------->|  verifies: name is claimed,
    |     {version, action:"tunnel", name,        |  subject owns it, sequence >
    |      subject, sequence, signature}          |  stored, signature valid;
    |                                             |  then persists the new sequence
    |  3. ack frame                               |
    |<--------------------------------------------|  {"type":"ack"}  tunnel is live
    |                                             |
    |  ... for each HTTPS request to              |
    |      https://<name>.tinycloud.link ...      |
    |                                             |
    |  4. request + requestBody frames            |
    |<--------------------------------------------|
    |  5. response + responseBody frames          |
    |-------------------------------------------->|
    |                                             |
    |  (relay pings every 30s; the node's WS      |
    |   stack must answer pongs or the socket     |
    |   is terminated as dead)                    |
```

- **Auth** (`src/names.ts` `TunnelAuthRecord`, enforced in `src/tunnel/upgrade.ts`): the first WS message must be a JSON record signed exactly like every other write -- canonical payload `{"version":1,"action":"tunnel","name":...,"subject":...,"sequence":...}` (fixed key order, `signature` field excluded from the signed bytes), same did:pkh (EIP-191) / did:key (Ed25519, base64url signature) schemes, `sequence` strictly greater than the name record's stored sequence. On success the stored sequence is bumped (same bump-before-side-effect pattern as the cert flow) and the relay sends `{"type":"ack"}`. The node has 5 seconds from socket open to deliver the auth frame.
- **Close codes on rejection** (RFC 6455 private-use range): `4400` malformed auth frame or frame `name` != URL name, `4401` invalid signature, `4403` subject does not own the name, `4404` name not claimed, `4408` auth timeout, `4409` stale sequence, `4410` superseded by a newer connection for the same name.
- **One socket per name, newest wins** (`src/tunnel/registry.ts`): a second authenticated connection for the same name evicts the first (close `4410`) rather than being rejected -- a node reconnecting after a network blip must be able to take over from its own half-dead previous socket. (Each reconnect needs a fresh auth frame with a higher sequence.)
- **Keep-alive**: the relay pings every 30s and terminates the socket if the previous ping got no pong. Standard WS libraries answer pings automatically; a Rust client must confirm its library does (tungstenite does).
- **Connection-attempt limits** (`src/tunnel/upgrade.ts`, checked in the raw HTTP `upgrade` handler, before the WS handshake and before any Postgres read): at most 30 upgrade attempts per remote IP per minute, at most 10 upgrade attempts per tunnel name per minute (bounds reconnect/eviction churn on one name), and a global cap of 1000 concurrently registered tunnels (env-tunable via `TUNNEL_MAX_CONCURRENT`, see below). An attempt over any of these limits gets the raw TCP socket destroyed -- no WS handshake, no close code, nothing for the node to parse.

### Frame protocol

Defined in `src/tunnel/protocol.ts` -- that file is the source of truth for the Rust node client. Every frame is one JSON **text** message (binary WS messages are never used); body bytes travel base64-encoded inside the JSON. After the ack, the frames are:

| frame | direction | fields |
|---|---|---|
| `request` | relay → node | `id` (UUID string), `method`, `path` (path + query, always starts with `/`), `headers` (ordered `[name, value]` pairs; `Host` and hop-by-hop headers stripped) |
| `requestBody` | relay → node | `id`, `chunk` (base64, may be `""`), `done` (bool) |
| `response` | node → relay | `id`, `status` (int), `headers` (ordered `[name, value]` pairs) |
| `responseBody` | node → relay | `id`, `chunk` (base64, may be `""`), `done` (bool) |
| `error` | either direction | `message`, optional `id` (fails just that request without closing the socket) |

Rules a node client must follow:

- Requests are multiplexed: frames for different `id`s interleave freely on the one socket. Echo the request's `id` on every frame you send for it. A frame carrying an `id` the relay/node doesn't recognize (e.g. arriving after that request already failed or timed out) is silently ignored, never treated as a protocol error.
- **Headers are ordered `[name, value]` pairs, not an object** -- so a header repeated on the wire (most importantly `Set-Cookie`, but any header) survives as multiple array entries instead of colliding on one object key. A client must be able to both emit and parse duplicate entries for the same header name.
- The relay sends `request` first, then one or more `requestBody` frames ending with `done: true`; the node replies with exactly one `response` frame, then one or more `responseBody` frames ending with `done: true`. An empty body is still exactly one frame: `{"...Body","id":...,"chunk":"","done":true}`.
- **Size limits**: no single WS frame may exceed `MAX_FRAME_PAYLOAD_BYTES` (1MB) -- the relay's `WebSocketServer` is configured with this as `maxPayload` and will close a connection that sends a larger one (WS close code `1009`). A body larger than `BODY_CHUNK_BYTES` (256KB, chosen to stay well under 1MB once base64-inflated) must be split across multiple body frames; only the last carries `done: true`. The relay itself follows this when sending `requestBody` frames and expects a node to do the same for `responseBody`. Independent of frame size, the full reassembled body (request or response) is capped at `DEFAULT_MAX_BODY_BYTES` (25MB, overridable via the `TUNNEL_MAX_BODY_BYTES` env var, see below): a request over the cap gets `413` directly from the relay before it ever reaches the tunnel; a response over the cap is aborted with `502` to the HTTP caller and an `{"type":"error","id":...}` frame is sent back to the node so it knows to stop sending.
- If the node cannot serve a request it sends `{"type":"error","id":...,"message":...}`; the relay answers the HTTP caller with `502`. The relay applies a 30s per-request timeout (caller gets `504`).
- HTTP callers with no live tunnel for their Host get `502` directly from the relay.

### Ingress and TLS for tunnels

TLS for `https://<name>.tinycloud.link` terminates **at the relay's front door, with one wildcard certificate** -- not with per-name certificates, and not inside this Node process.

The constraint that forces this: on Phala, this service runs behind `dstack-ingress` (see `docker-compose.phala.yml`), an HAProxy-based L4 TCP proxy that terminates TLS itself using its own certbot/DNS-01 machinery and forwards the decrypted stream to `TARGET_ENDPOINT`. Everything arriving on the CVM's public `:443` goes through it. From inside the CVM there is no per-SNI certificate hook: this repo's process never sees the TLS handshake, and `dstack-ingress` serves the certificates *it* obtained at bootstrap, not ones handed to it at runtime by another container. So the "extend the ACME issuer to obtain a cert for each `<name>.tinycloud.link` on tunnel registration" design is a dead end in this deployment model -- this process could *obtain* those certs (it already has the DNS-01 machinery), but nothing here could ever *serve* them. Design honesty: we don't ship per-name relay certs.

What ships instead:

- `dstack-ingress` runs with `DOMAIN=*.tinycloud.link` -- it supports wildcard domains natively (wildcard DNS-01 order, `issuewild` CAA). One certificate covers `api.tinycloud.link` and every tunnel name.
- DNS needs one wildcard record: `*.tinycloud.link` → the same dstack gateway target `api.tinycloud.link` already points at (human step, same as the original `api` wiring). Tunnels create **no** per-name DNS records; the per-name records this service writes remain what they always were -- LAN A/AAAA under `*.local.tinycloud.link`.
- Behind the ingress, this process routes by `Host` header (`src/tunnel/host-router.ts`): `API_HOSTNAME` (default `api.tinycloud.link`) gets the normal `/v1` API; any other single-label `<name>.tinycloud.link` host is looked up in the tunnel registry and proxied.
- **Open verification item**: dstack-ingress documents that wildcard `DOMAIN` requires dstack-gateway wildcard TXT resolution support ([dstack#545](https://github.com/Dstack-TEE/dstack/pull/545)). Whether the production gateway has it can't be verified from this repo. If it doesn't, the wildcard ACME order fails at ingress bootstrap; the fallback is `DOMAIN=api.tinycloud.link` (control-plane API keeps working exactly as today, tunnels stay dark) until the gateway supports it. Must be checked on a staging CVM before the tunnel-enabled image is deployed.

Trade-offs accepted: all tunnel names share one certificate (one CT-log entry for `*.tinycloud.link` rather than a per-name entry -- strictly *less* name disclosure than the LAN cert flow, which CT-logs every name); and tunnel TLS terminates in the ingress container rather than end-to-end at the node, meaning plaintext HTTP crosses the CVM-internal hop between ingress and this process -- the same boundary the control-plane API traffic has always crossed.

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
4. Point `api.tinycloud.link` at the deployment's dstack gateway (human DNS step, same pattern as `registry.tinycloud.xyz`). For tunnels (TC-85), also point the wildcard `*.tinycloud.link` at the same gateway target and confirm the gateway supports wildcard TXT resolution for the ingress's wildcard cert order -- see "Ingress and TLS for tunnels" above.
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
