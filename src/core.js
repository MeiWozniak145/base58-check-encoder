/**
 * Base58Check encode/decode with a pluggable checksum size and alphabet.
 *
 * Base58 itself is a positional numeral system that avoids the visually
 * ambiguous characters 0, O, I, and l, which makes copied strings easier
 * to verify by eye. "Base58Check" appends a checksum (here, the leading
 * bytes of SHA-256(SHA-256(payload))) so that a single transposed or
 * dropped character is detected rather than silently accepted.
 *
 * The standard variants shipped here differ in two places:
 *
 *   - Bitcoin (and most currencies) use a 4-byte checksum and the
 *     "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
 *     alphabet. A leading zero byte in the payload encodes to a leading
 *     '1' character.
 *   - Ripple uses a 4-byte checksum and its own alphabet
 *     "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz",
 *     which is a permutation of the same 58 characters. Because the
 *     numeric value of each character is defined by its position in the
 *     alphabet, Ripple's leading-zero byte still encodes to the first
 *     character of its alphabet ('r'), not to Bitcoin's '1'.
 *
 * We use Node's built-in crypto module for SHA-256. This keeps the project
 * free of third-party dependencies, which matters for auditability and for
 * running inside sandboxes that have no package registry access.
 */

import { createHash } from "node:crypto";

/**
 * The two alphabets this library ships. Callers may construct their own by
 * passing any 58-character string to encode/decode.
 */
export const defaultAlphabets = Object.freeze({
  /** Bitcoin / most currencies. */
  bitcoin: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
  /** Ripple / XRP. */
  ripple: "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz",
});

const DEFAULT_CHECKSUM_BYTES = 4;

/**
 * Double-SHA-256, returning only as many leading bytes as the caller needs.
 *
 * Reusing SHA-256 rather than SHA-256d would change the checksum and break
 * compatibility with every existing Base58Check string, so the double hash is
 * mandatory for the standard variants. We expose checksumBytes so a caller who
 * genuinely wants a different algorithm can substitute it.
 */
function checksumBytes(payload, checksumBytes) {
  const first = createHash("sha256").update(payload).digest();
  const second = createHash("sha256").update(first).digest();
  return second.subarray(0, checksumBytes);
}

function buildLookup(alphabet) {
  const map = new Map();
  for (let i = 0; i < alphabet.length; i += 1) {
    const ch = alphabet[i];
    if (map.has(ch)) {
      throw new Error(`Duplicate character in alphabet: ${ch}`);
    }
    map.set(ch, i);
  }
  return map;
}

/**
 * Encode a payload as Base58Check.
 *
 * @param {Uint8Array} payload Raw bytes to encode.
 * @param {object} [options]
 * @param {string} [options.alphabet]  58-character alphabet. Defaults to Bitcoin.
 * @param {number} [options.checksumBytes] Number of checksum bytes to append. Defaults to 4.
 * @returns {string} Base58Check-encoded string.
 */
export function encode(payload, options = {}) {
  if (!(payload instanceof Uint8Array)) {
    throw new TypeError("payload must be a Uint8Array");
  }
  const alphabet = options.alphabet ?? defaultAlphabets.bitcoin;
  if (typeof alphabet !== "string" || alphabet.length !== 58) {
    throw new Error("alphabet must be a 58-character string");
  }
  const checksumBytesCount = options.checksumBytes ?? DEFAULT_CHECKSUM_BYTES;
  if (!Number.isInteger(checksumBytesCount) || checksumBytesCount <= 0 || checksumBytesCount > 32) {
    throw new Error("checksumBytes must be an integer in [1, 32]");
  }

  // Compute the combined buffer = payload || checksum, then run the base58
  // conversion on the whole thing. Doing the conversion on the combined
  // buffer (rather than encoding payload and checksum separately) is what
  // makes the leading-zero rule fall out correctly: a zero byte at the
  // start of the payload maps to the first alphabet character.
  const checksum = checksumBytes(payload, checksumBytesCount);
  const combined = new Uint8Array(payload.length + checksum.length);
  combined.set(payload, 0);
  combined.set(checksum, payload.length);

  // Count leading zero bytes. Each one maps to the first character of the
  // alphabet ("1" for Bitcoin, "r" for Ripple).
  let leadingZeros = 0;
  for (let i = 0; i < combined.length; i += 1) {
    if (combined[i] === 0) leadingZeros += 1;
    else break;
  }

  // Convert the non-zero portion as a big-endian base-58 number.
  const digits = [];
  for (let i = leadingZeros; i < combined.length; i += 1) {
    let carry = combined[i];
    for (let j = 0; j < digits.length; j += 1) {
      carry += digits[j] * 256;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  let out = "";
  for (let i = 0; i < leadingZeros; i += 1) out += alphabet[0];
  for (let i = digits.length - 1; i >= 0; i -= 1) out += alphabet[digits[i]];
  return out;
}

/**
 * Decode a Base58Check string, verifying the checksum.
 *
 * @param {string} encoded The Base58Check string.
 * @param {object} [options]
 * @param {string} [options.alphabet]  58-character alphabet. Defaults to Bitcoin.
 * @param {number} [options.checksumBytes] Number of checksum bytes expected at the end. Defaults to 4.
 * @returns {Uint8Array} The original payload, without the checksum.
 * @throws {Error} If the string contains characters outside the alphabet or the checksum does not validate.
 */
export function decode(encoded, options = {}) {
  if (typeof encoded !== "string") {
    throw new TypeError("encoded must be a string");
  }
  const alphabet = options.alphabet ?? defaultAlphabets.bitcoin;
  if (typeof alphabet !== "string" || alphabet.length !== 58) {
    throw new Error("alphabet must be a 58-character string");
  }
  const checksumBytesCount = options.checksumBytes ?? DEFAULT_CHECKSUM_BYTES;
  if (!Number.isInteger(checksumBytesCount) || checksumBytesCount <= 0 || checksumBytesCount > 32) {
    throw new Error("checksumBytes must be an integer in [1, 32]");
  }
  if (encoded.length === 0) {
    throw new Error("encoded string is empty");
  }

  const lookup = buildLookup(alphabet);

  // Count leading instances of the alphabet's first character — the decode
  // counterpart of the leading-zero-byte rule in encode().
  const firstChar = alphabet[0];
  let leadingFirst = 0;
  for (let i = 0; i < encoded.length; i += 1) {
    if (encoded[i] === firstChar) leadingFirst += 1;
    else break;
  }

  // Interpret the remaining characters as a base-58 number, least significant
  // digit first. We mutate `bytes` in place; length only grows.
  const bytes = [];
  for (let i = leadingFirst; i < encoded.length; i += 1) {
    const ch = encoded[i];
    const value = lookup.get(ch);
    if (value === undefined) {
      throw new Error(`Character not in alphabet: ${ch}`);
    }
    let carry = value;
    for (let j = 0; j < bytes.length; j += 1) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  // bytes is little-endian and excludes the leading-zero bytes; prepend them.
  const combined = new Uint8Array(leadingFirst + bytes.length);
  // The first `leadingFirst` entries are already 0 (default Uint8Array value).
  for (let i = 0; i < bytes.length; i += 1) {
    combined[leadingFirst + i] = bytes[bytes.length - 1 - i];
  }

  if (combined.length < checksumBytesCount) {
    throw new Error("decoded data is shorter than the checksum");
  }

  const payload = combined.subarray(0, combined.length - checksumBytesCount);
  const expectedChecksum = combined.subarray(combined.length - checksumBytesCount);
  const actualChecksum = checksumBytes(payload, checksumBytesCount);

  // Constant-time-ish comparison. We do not branch on the bytes so that a
  // timing observer cannot learn how many bytes matched before a mismatch.
  // (For this library's threat model this is belt-and-braces; we include it
  // anyway because it is cheap and avoids a known foot-gun.)
  let diff = 0;
  for (let i = 0; i < checksumBytesCount; i += 1) {
    diff |= expectedChecksum[i] ^ actualChecksum[i];
  }
  if (diff !== 0) {
    throw new Error("checksum mismatch");
  }

  return payload;
}
