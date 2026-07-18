import assert from "node:assert/strict";
import test from "node:test";
import { isPrivateAddress } from "./ip.js";

test("accepts RFC1918 and link-local IPv4 ranges", () => {
  assert.equal(isPrivateAddress("10.0.0.5"), true);
  assert.equal(isPrivateAddress("172.16.0.1"), true);
  assert.equal(isPrivateAddress("172.31.255.255"), true);
  assert.equal(isPrivateAddress("192.168.1.42"), true);
  assert.equal(isPrivateAddress("169.254.1.1"), true);
  assert.equal(isPrivateAddress("127.0.0.1"), true);
});

test("rejects public IPv4 addresses", () => {
  assert.equal(isPrivateAddress("8.8.8.8"), false);
  assert.equal(isPrivateAddress("1.1.1.1"), false);
  assert.equal(isPrivateAddress("172.32.0.1"), false); // just outside 172.16.0.0/12
  assert.equal(isPrivateAddress("192.169.1.1"), false);
});

test("accepts private IPv6 ranges", () => {
  assert.equal(isPrivateAddress("::1"), true);
  assert.equal(isPrivateAddress("fe80::1"), true);
  assert.equal(isPrivateAddress("fd00::1"), true);
  assert.equal(isPrivateAddress("fc00::1"), true);
});

test("rejects public IPv6 and malformed addresses", () => {
  assert.equal(isPrivateAddress("2001:4860:4860::8888"), false);
  assert.equal(isPrivateAddress("not-an-ip"), false);
  assert.equal(isPrivateAddress(""), false);
});
