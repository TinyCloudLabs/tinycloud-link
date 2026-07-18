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

test("accepts expanded IPv6 spellings of private addresses", () => {
  assert.equal(isPrivateAddress("0:0:0:0:0:0:0:1"), true); // expanded loopback
  assert.equal(isPrivateAddress("fe80:0:0:0:0:0:0:1"), true);
  assert.equal(isPrivateAddress("fd00:0000:0000:0000:0000:0000:0000:0001"), true);
});

test("classifies IPv4-mapped IPv6 by the embedded IPv4", () => {
  assert.equal(isPrivateAddress("::ffff:192.168.1.1"), true);
  assert.equal(isPrivateAddress("::ffff:10.0.0.5"), true);
  assert.equal(isPrivateAddress("::ffff:8.8.8.8"), false);
});

test("classifies NAT64-embedded IPv6 by the embedded IPv4", () => {
  assert.equal(isPrivateAddress("64:ff9b::192.168.1.1"), true);
  assert.equal(isPrivateAddress("64:ff9b::c0a8:101"), true); // 192.168.1.1 in hex groups
  assert.equal(isPrivateAddress("64:ff9b::8.8.8.8"), false);
});

test("classifies 6to4 IPv6 by the embedded IPv4", () => {
  assert.equal(isPrivateAddress("2002:c0a8:101::1"), true); // embeds 192.168.1.1
  assert.equal(isPrivateAddress("2002:808:808::1"), false); // embeds 8.8.8.8
});

test("fails closed on ambiguous IPv6 forms", () => {
  assert.equal(isPrivateAddress("::"), false); // unspecified
  assert.equal(isPrivateAddress("::ffff:0:8.8.8.8"), false); // not the mapped /96
});
