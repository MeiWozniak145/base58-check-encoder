/**
 * Tests for Base58Check encode/decode.
 *
 * Run with: node --test
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { encode, decode, defaultAlphabets } from "../src/index.js";

// Known answer for the canonical Bitcoin vector: payload 0x00 + 20 bytes
// of all-0x01 produces "16Jswqk47s9PUcyCc88MMVwzgvHPvtEpf" under the Bitcoin
// alphabet with a 4-byte checksum.
const knownPayload = new Uint8Array([
  0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
]);
const knownEncoded = "16Jswqk47s9PUcyCc88MMVwzgvHPvtEpf";

test("encode produces the canonical Bitcoin known-answer for an all-0x01 payload", () => {
  assert.equal(encode(knownPayload), knownEncoded);
});

test("decode inverts encode for the known Bitcoin vector", () => {
  const out = decode(knownEncoded);
  assert.deepEqual(out, knownPayload);
});

test("decode rejects a single corrupted character", () => {
  // Flip the last character; this should alter the checksum.
  const bad = knownEncoded.slice(0, -1) + "7";
  assert.throws(() => decode(bad), /checksum mismatch/);
});

test("decode rejects characters outside the alphabet", () => {
  // '0' is intentionally not in the Bitcoin alphabet.
  assert.throws(() => decode("0"), /not in alphabet/);
});

test("decode rejects an empty string", () => {
  assert.throws(() => decode(""), /empty/);
});

test("encode and decode round-trip arbitrary non-zero payloads", () => {
  const payloads = [
    new Uint8Array([42, 255, 0, 17, 99]),
    new Uint8Array([1]),
    new Uint8Array([0, 0, 0, 1, 2, 3]),
    new Uint8Array(new Array(40).fill(0xab)),
  ];
  for (const p of payloads) {
    const enc = encode(p);
    const dec = decode(enc);
    assert.deepEqual(dec, p, `round-trip failed for payload ${JSON.stringify(Array.from(p))}`);
  }
});

test("leading zero bytes encode to the alphabet's first character", () => {
  // Bitcoin: leading zero -> '1'.
  const payload = new Uint8Array([0, 1, 2, 3]);
  const enc = encode(payload);
  assert.equal(enc[0], "1");
  assert.deepEqual(decode(enc), payload);
});

test("the Ripple alphabet is a permutation of the Bitcoin alphabet", () => {
  const b = Array.from(defaultAlphabets.bitcoin).sort().join("");
  const r = Array.from(defaultAlphabets.ripple).sort().join("");
  assert.equal(b, r);
});

test("Ripple alphabet encodes the leading-zero byte as its own first character", () => {
  const payload = new Uint8Array([0, 1, 2, 3]);
  const enc = encode(payload, { alphabet: defaultAlphabets.ripple });
  assert.equal(enc[0], "r");
  const dec = decode(enc, { alphabet: defaultAlphabets.ripple });
  assert.deepEqual(dec, payload);
});

test("cross-alphabet decode fails the checksum", () => {
  // A string encoded with the Bitcoin alphabet will not validate under Ripple.
  const enc = encode(new Uint8Array([1, 2, 3, 4]), { alphabet: defaultAlphabets.bitcoin });
  assert.throws(
    () => decode(enc, { alphabet: defaultAlphabets.ripple }),
    /not in alphabet|checksum mismatch/,
  );
});

test("a non-58-character alphabet is rejected", () => {
  const short = "123456789";
  assert.throws(() => encode(new Uint8Array([1]), { alphabet: short }), /58-character/);
  assert.throws(() => decode("1", { alphabet: short }), /58-character/);
});

test("encode rejects a non-Uint8Array payload", () => {
  assert.throws(() => encode([1, 2, 3]), /must be a Uint8Array/);
  assert.throws(() => encode("hello"), /must be a Uint8Array/);
});

test("encode and decode reject an invalid checksum byte count", () => {
  const p = new Uint8Array([1, 2, 3]);
  assert.throws(() => encode(p, { checksumBytes: 0 }), /must be an integer/);
  assert.throws(() => encode(p, { checksumBytes: 1.5 }), /must be an integer/);
  assert.throws(() => encode(p, { checksumBytes: 100 }), /must be an integer/);
  assert.throws(() => decode(encode(p), { checksumBytes: 0 }), /must be an integer/);
});

test("a custom 1-byte checksum round-trips", () => {
  const p = new Uint8Array([10, 20, 30]);
  const enc = encode(p, { checksumBytes: 1 });
  const dec = decode(enc, { checksumBytes: 1 });
  assert.deepEqual(dec, p);
});

test("decoding with the wrong checksum byte count fails", () => {
  const p = new Uint8Array([1, 2, 3, 4]);
  const enc = encode(p, { checksumBytes: 4 });
  assert.throws(() => decode(enc, { checksumBytes: 1 }), /checksum mismatch|shorter than/);
});

test("empty payload round-trips to first-characters-only", () => {
  const empty = new Uint8Array(0);
  const enc = encode(empty);
  // payload=0 bytes, checksum=4 bytes of SHA256d(""). Decode should recover
  // an empty payload.
  assert.equal(decode(enc).length, 0);
});

test("a very long payload round-trips", () => {
  const long = new Uint8Array(200);
  for (let i = 0; i < long.length; i += 1) long[i] = (i * 7 + 3) & 0xff;
  const enc = encode(long);
  const dec = decode(enc);
  assert.deepEqual(dec, long);
});
