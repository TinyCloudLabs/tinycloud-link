import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const dir = new URL(".", import.meta.url).pathname;
const backupScript = join(dir, "link-backup.sh");
const restoreScript = join(dir, "link-restore-drill.sh");
const migrations = ["001_names.sql", "002_acme_account.sql", "003_cert_issuances.sql"];

test("compose sidecar never carries a private key and requires every backup input", () => {
  const compose = readFileSync(join(dir, "../docker-compose.phala.yml"), "utf8");
  const sidecar = compose.slice(compose.indexOf("  postgres-backup:"), compose.indexOf("\nvolumes:"));
  assert.match(sidecar, /image: \$\{LINK_BACKUP_IMAGE:\?set /);
  assert.match(sidecar, /init: true/);
  assert.match(sidecar, /tmpfs:\n\s+- \/tmp:size=\d+m,mode=1700/);
  assert.match(sidecar, /PGUSER=tinycloud_link/);
  assert.match(sidecar, /PGDATABASE=tinycloud_link/);
  assert.doesNotMatch(compose, /AGE-SECRET-KEY-1[A-Z0-9]{20,}|AGE_IDENTITY/);
  for (const name of [
    "LINK_BACKUP_R2_ENDPOINT",
    "LINK_BACKUP_R2_BUCKET",
    "LINK_BACKUP_R2_ACCESS_KEY_ID",
    "LINK_BACKUP_R2_SECRET_ACCESS_KEY",
    "LINK_BACKUP_AGE_RECIPIENT",
  ]) {
    assert.match(sidecar, new RegExp(`- ${name}=\\$\\{${name}:\\?set `));
  }
});

function run(command, args, env) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    child.stdout.on("data", (chunk) => (out += chunk));
    child.stderr.on("data", (chunk) => (err += chunk));
    child.on("close", (status) => resolve({ status, out, err }));
  });
}

const tools = ["age", "age-keygen", "pg_dump", "pg_restore", "psql", "createdb", "dropdb", "curl"];
const missing = tools.filter((tool) => spawnSync("sh", ["-c", `command -v ${tool}`]).status !== 0);
const dbReady = missing.length === 0 && spawnSync("psql", ["-d", "postgres", "-Atqc", "select 1"]).status === 0;
// On CI a missing tool or database is a failure, never a silent skip that leaves the job green.
const skip = dbReady || process.env.CI ? false : `needs ${missing.join(", ") || "a reachable Postgres via PG* env"}`;

function mockR2(snapshot) {
  const objects = new Map();
  const seen = [];
  let failUploads = false;
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const url = new URL(req.url, "http://mock");
      seen.push({ method: req.method, path: url.pathname, authorization: req.headers.authorization, sha: req.headers["x-amz-content-sha256"], ifNoneMatch: req.headers["if-none-match"], files: snapshot?.() });
      if (req.method === "PUT") {
        if (failUploads) return res.writeHead(500).end();
        objects.set(url.pathname, Buffer.concat(chunks));
        return res.writeHead(200).end();
      }
      if (req.method === "GET" && url.searchParams.get("list-type") === "2") {
        const prefix = `/test-bucket/${url.searchParams.get("prefix")}`;
        const keys = [...objects.keys()].filter((key) => key.startsWith(prefix)).map((key) => key.slice("/test-bucket/".length));
        return res.writeHead(200).end(`<ListBucketResult>${keys.map((key) => `<Contents><Key>${key}</Key></Contents>`).join("")}</ListBucketResult>`);
      }
      if (req.method === "GET" && objects.has(url.pathname)) return res.writeHead(200).end(objects.get(url.pathname));
      res.writeHead(404).end();
    });
  });
  return {
    objects,
    seen,
    failUploads: (value) => (failUploads = value),
    listen: () => new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${server.address().port}`))),
    close: () => server.close(),
  };
}

test("backup uploads an age-encrypted dump that the restore drill restores", { skip }, async () => {
  const work = mkdtempSync(join(tmpdir(), "link-backup-test-"));
  const suffix = `${process.pid}_${Date.now()}`;
  const source = `link_backup_src_${suffix}`;
  const target = `link_backup_dst_${suffix}`;
  // Called while a PUT is in flight: what exists in the sidecar's tmpfs at the moment of upload.
  const r2 = mockR2(() => {
    try {
      return readdirSync(join(work, "tmpfs"), { recursive: true });
    } catch {
      return [];
    }
  });
  const endpoint = await r2.listen();
  try {
    assert.equal((await run("createdb", [source])).status, 0);
    assert.equal((await run("createdb", [target])).status, 0);
    for (const file of migrations) {
      const migrate = await run("psql", ["-d", source, "-v", "ON_ERROR_STOP=1", "-f", join(dir, "../migrations", file)]);
      assert.equal(migrate.status, 0, migrate.err);
    }
    const secretMarker = "did:key:z6MkPlaintextMarkerNeverInTheClear";
    const pemMarker = "PlaintextAcmeAccountKeyMarkerNeverInTheClear";
    const seed = await run("psql", [
      "-d", source, "-v", "ON_ERROR_STOP=1", "-c",
      `insert into names (name, subject, lan_ips, sequence, updated_at) select 'n' || g, '${secretMarker}' || g, '["192.168.0.1"]'::jsonb, g, now() from generate_series(1,7) g;
       insert into acme_account (account_key_pem) values ('${pemMarker}');
       insert into cert_issuances (name) select 'n' || g from generate_series(1,3) g`,
    ]);
    assert.equal(seed.status, 0, seed.err);

    const keygen = await run("age-keygen", ["-o", join(work, "identity.txt")]);
    assert.equal(keygen.status, 0, keygen.err);
    const recipient = /[Pp]ublic key: (age1\S+)/.exec(keygen.err + keygen.out)?.[1];
    assert.ok(recipient, "age-keygen must print a public recipient");

    // The plaintext dump may only ever live under TMPDIR (the compose tmpfs); it must not survive a run.
    const scratch = join(work, "tmpfs");
    mkdirSync(scratch);
    // A curl shim records its argument list, then runs the real curl.
    const realCurl = spawnSync("sh", ["-c", "command -v curl"]).stdout.toString().trim();
    const shimDir = join(work, "bin");
    const argvLog = join(work, "curl-argv");
    mkdirSync(shimDir);
    writeFileSync(join(shimDir, "curl"), `#!/bin/sh\nprintf '%s\\n' "$@" >> '${argvLog}'\nexec '${realCurl}' "$@"\n`);
    chmodSync(join(shimDir, "curl"), 0o755);

    const base = {
      PGDATABASE: source,
      PGUSER: process.env.PGUSER ?? process.env.USER ?? "postgres",
      PGHOST: process.env.PGHOST ?? "127.0.0.1",
      PGPASSWORD: process.env.PGPASSWORD ?? "unused",
      LINK_BACKUP_R2_ENDPOINT: endpoint,
      LINK_BACKUP_R2_BUCKET: "test-bucket",
      LINK_BACKUP_R2_ACCESS_KEY_ID: "test-key-id",
      LINK_BACKUP_R2_SECRET_ACCESS_KEY: "test-secret-value",
      LINK_BACKUP_AGE_RECIPIENT: recipient,
      BACKUP_ONCE: "1",
      TMPDIR: scratch,
      PATH: `${shimDir}:${process.env.PATH}`,
    };

    // Misconfiguration is rejected before anything is dumped or uploaded.
    const identityText = readFileSync(join(work, "identity.txt"), "utf8");
    const privateKey = /AGE-SECRET-KEY-\S+/.exec(identityText)[0];
    const refusedPrivate = await run("sh", [backupScript], { ...base, LINK_BACKUP_AGE_RECIPIENT: privateKey });
    assert.notEqual(refusedPrivate.status, 0);
    assert.match(refusedPrivate.err, /PRIVATE key/);
    assert.ok(!(refusedPrivate.err + refusedPrivate.out).includes(privateKey), "the refused private key must not be echoed");
    const refusedMissing = await run("sh", [backupScript], { ...base, LINK_BACKUP_R2_BUCKET: "" });
    assert.notEqual(refusedMissing.status, 0);
    assert.equal(r2.objects.size, 0);

    // An upload failure is a failure, not a silent success, and leaves no plaintext or ciphertext behind.
    r2.failUploads(true);
    assert.notEqual((await run("sh", [backupScript], base)).status, 0);
    r2.failUploads(false);
    assert.equal(r2.objects.size, 0);
    assert.deepEqual(readdirSync(scratch), []);

    // A pg_dump failure uploads nothing. In the retry loop (`if backup_once`, where `set -e` is off) it
    // must be reported and retried, and TERM must exit promptly with the tmpfs cleaned.
    const loop = spawn("sh", [backupScript], {
      env: { ...process.env, ...base, BACKUP_ONCE: "", PGDATABASE: "link_backup_does_not_exist", BACKUP_RETRY_SECONDS: "600" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let loopErr = "";
    loop.stderr.on("data", (chunk) => (loopErr += chunk));
    const loopEnd = new Promise((resolve) => loop.on("close", (code) => resolve(code)));
    for (let waited = 0; !loopErr.includes("backup: FAILED") && waited < 100; waited++) await new Promise((resolve) => setTimeout(resolve, 100));
    assert.match(loopErr, /backup: FAILED; retrying in 600s/);
    loop.kill("SIGTERM");
    assert.equal(await loopEnd, 143);
    assert.equal(r2.objects.size, 0);
    assert.deepEqual(readdirSync(scratch), []);

    const backup = await run("sh", [backupScript], base);
    assert.equal(backup.status, 0, backup.err);
    assert.deepEqual(readdirSync(scratch), []);
    assert.equal(r2.objects.size, 1);
    const [[path, body]] = [...r2.objects];
    assert.match(path, /^\/test-bucket\/tinycloud-link\/link_backup_src_\d+_\d+-\d{8}T\d{6}Z\.dump\.age$/);
    assert.ok(body.subarray(0, 22).toString().startsWith("age-encryption.org/v1"), "object must be an age file");
    assert.ok(!body.includes(secretMarker), "ciphertext must not contain plaintext name data");
    assert.ok(!body.includes(pemMarker), "ciphertext must not contain the plaintext ACME account key");
    const put = r2.seen.find((entry) => entry.method === "PUT");
    assert.match(put.authorization, /^AWS4-HMAC-SHA256 Credential=test-key-id\/\d{8}\/auto\/s3\/aws4_request/);
    assert.equal(put.sha, "UNSIGNED-PAYLOAD");
    assert.equal(put.ifNoneMatch, "*");
    // "Deleted before upload": at the moment of the PUT only the ciphertext is on the tmpfs.
    assert.ok(put.files.some((file) => file.endsWith("dump.age")), "ciphertext must be on the tmpfs during upload");
    assert.ok(!put.files.some((file) => /(^|\/)dump$/.test(file)), "plaintext dump must be gone before upload");
    const argv = readFileSync(argvLog, "utf8");
    assert.match(argv, /--aws-sigv4/);
    assert.ok(!argv.includes("test-secret-value") && !argv.includes("test-key-id"), "R2 credentials must not be passed in curl's argv");

    const drillEnv = {
      AGE_IDENTITY_FILE: join(work, "identity.txt"),
      LINK_BACKUP_R2_ENDPOINT: endpoint,
      LINK_BACKUP_R2_BUCKET: "test-bucket",
      LINK_BACKUP_R2_ACCESS_KEY_ID: "test-key-id",
      LINK_BACKUP_R2_SECRET_ACCESS_KEY: "test-secret-value",
      RESTORE_DATABASE_URL: `postgresql:///${target}?host=${encodeURIComponent(process.env.PGHOST ?? "127.0.0.1")}`,
      RESTORE_EXPECT_MIN_NAMES: "7",
      RESTORE_EXPECT_MIN_ACME_ACCOUNT: "1",
      RESTORE_EXPECT_MIN_CERT_ISSUANCES: "3",
      PATH: `${shimDir}:${process.env.PATH}`,
    };
    const drill = await run("sh", [restoreScript], drillEnv);
    assert.equal(drill.status, 0, drill.err + drill.out);
    assert.match(drill.out, /names rows = 7\b/);
    assert.match(drill.out, /acme_account rows = 1\b/);
    assert.match(drill.out, /cert_issuances rows = 3\b/);
    assert.match(drill.out, /restore-drill: OK/);
    assert.ok(!readFileSync(argvLog, "utf8").includes("test-secret-value"), "the drill must not pass the R2 secret in curl's argv");

    // Wrong private key: decryption must fail loudly, restoring nothing.
    assert.equal((await run("age-keygen", ["-o", join(work, "other.txt")])).status, 0);
    const wrong = await run("sh", [restoreScript], { ...drillEnv, AGE_IDENTITY_FILE: join(work, "other.txt") });
    assert.notEqual(wrong.status, 0);
    assert.match(wrong.err, /decryption failed/);

    // The row-count floor catches a dump that is smaller than production should be.
    const short = await run("sh", [restoreScript], { ...drillEnv, RESTORE_EXPECT_MIN_NAMES: "8" });
    assert.notEqual(short.status, 0);
    assert.match(short.err, /expected at least 8 rows in names/);
  } finally {
    r2.close();
    await run("dropdb", ["--if-exists", source]);
    await run("dropdb", ["--if-exists", target]);
    rmSync(work, { recursive: true, force: true });
  }
});
