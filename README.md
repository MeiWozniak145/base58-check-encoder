# Base58 Check Encoder

Encode and decode Base58Check strings in pure JavaScript (ESM), with a pluggable checksum size and alphabet. Ships with the Bitcoin and Ripple alphabets. Zero third-party dependencies; SHA-256 comes from Node's built-in `crypto`.

```js
import { encode, decode, defaultAlphabets } from "./src/index.js";

const payload = new Uint8Array([0x00, 0x01, 0x02, 0x03]);
const encoded = encode(payload);                       // Bitcoin alphabet, 4-byte checksum
const back = decode(encoded);                         // Uint8Array([0x00, 0x01, 0x02, 0x03])

// Ripple alphabet: same algorithm, different character ordering.
const xrp = encode(payload, { alphabet: defaultAlphabets.ripple });
const xrpBack = decode(xrp, { alphabet: defaultAlphabets.ripple });
```

## Why this exists

The library exists to give a single, small, auditable implementation of Base58Check that is not tied to a specific blockchain SDK. The trade-off is that it only implements the double-SHA-256 checksum used by Bitcoin and Ripple; if your system uses a different checksum algorithm, this is not the right library. The `checksumBytes` option lets you change how many checksum bytes are appended, but not how they are computed.

## Exported names

- `encode(payload: Uint8Array, options?: { alphabet?: string; checksumBytes?: number }): string`
- `decode(encoded: string, options?: { alphabet?: string; checksumBytes?: number }): Uint8Array`
- `defaultAlphabets` — a frozen object with `bitcoin` and `ripple` 58-character alphabet strings.

The default alphabet is Bitcoin's; the default checksum length is 4 bytes.

## Awkward edge

A leading zero byte in the payload is encoded as the first character of the chosen alphabet. For Bitcoin that is `1`; for Ripple it is `r`. If you encode with one alphabet and decode with the other, you will almost certainly get a checksum-mismatch error rather than a clean recovery. Always pass the same `alphabet` to both sides.

Run the tests with `node --test`.

## Design notes

The window stores values eagerly rather than keeping running aggregates. Running
sums drift with floating point over long streams, and recomputing from a small
buffer is cheap enough that the drift is not worth the speed.

