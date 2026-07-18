import assert from "node:assert/strict";
import test from "node:test";
import { waitForTxtPropagation } from "./dns/propagation.js";

const RECORD_NAME = "_acme-challenge.example.local.tinycloud.link";
const EXPECTED_VALUE = "expected-value";

/** Deterministic fake clock: sleep() advances the clock instead of waiting in real time. */
function fakeClock() {
  let time = 0;
  return {
    now: () => time,
    sleep: async (ms: number) => {
      time += ms;
    },
  };
}

test("resolves on the first poll when the public resolver already shows the value", async () => {
  const clock = fakeClock();
  let publicCalls = 0;
  let authoritativeFactoryCalls = 0;

  await waitForTxtPropagation(RECORD_NAME, EXPECTED_VALUE, {
    publicResolver: {
      resolveTxt: async () => {
        publicCalls += 1;
        return [[EXPECTED_VALUE]];
      },
    },
    authoritativeResolverFactory: async () => {
      authoritativeFactoryCalls += 1;
      return { resolveTxt: async () => [] };
    },
    initialDelayMs: 10000,
    pollIntervalMs: 2000,
    timeoutMs: 120000,
    now: clock.now,
    sleep: clock.sleep,
  });

  assert.equal(publicCalls, 1);
  assert.equal(
    authoritativeFactoryCalls,
    0,
    "authoritative resolver should not be needed once the public resolver already shows the value"
  );
});

test("resolves once the authoritative servers have shown the value for the full grace period", async () => {
  const clock = fakeClock();
  let authoritativeCalls = 0;

  await waitForTxtPropagation(RECORD_NAME, EXPECTED_VALUE, {
    publicResolver: { resolveTxt: async () => [] },
    authoritativeResolverFactory: async () => ({
      resolveTxt: async () => {
        authoritativeCalls += 1;
        return [[EXPECTED_VALUE]];
      },
    }),
    initialDelayMs: 10000,
    pollIntervalMs: 2000,
    authoritativeGraceMs: 6000,
    timeoutMs: 120000,
    now: clock.now,
    sleep: clock.sleep,
  });

  // authoritativeGraceMs (6s) / pollIntervalMs (2s) means the value must be observed across
  // several successive polls (not just once) before we're willing to proceed on it alone.
  assert.equal(authoritativeCalls, 4);
});

test("times out with a clear error when the value never becomes visible anywhere", async () => {
  const clock = fakeClock();

  await assert.rejects(
    () =>
      waitForTxtPropagation(RECORD_NAME, EXPECTED_VALUE, {
        publicResolver: { resolveTxt: async () => [] },
        authoritativeResolverFactory: async () => ({ resolveTxt: async () => [] }),
        initialDelayMs: 1000,
        pollIntervalMs: 1000,
        timeoutMs: 5000,
        now: clock.now,
        sleep: clock.sleep,
      }),
    new RegExp(`timed out after 5000ms waiting for ${RECORD_NAME.replace(/\./g, "\\.")}`)
  );
});

test("treats a resolver query that never returns as not-visible, instead of hanging the whole flow", async () => {
  const clock = fakeClock();
  const hungResolver = {
    // Never resolves; only the per-query timeout can move this along.
    resolveTxt: () => new Promise<string[][]>(() => {}),
  };

  await assert.rejects(
    () =>
      waitForTxtPropagation(RECORD_NAME, EXPECTED_VALUE, {
        publicResolver: hungResolver,
        authoritativeResolverFactory: async () => ({ resolveTxt: async () => [] }),
        initialDelayMs: 0,
        pollIntervalMs: 10,
        timeoutMs: 50,
        queryTimeoutMs: 20,
        now: clock.now,
        sleep: clock.sleep,
      }),
    /timed out/
  );
});
