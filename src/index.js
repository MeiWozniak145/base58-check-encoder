/**
 * Public entry point for the Base58Check encoder/decoder.
 *
 * Only the names re-exported here are part of the supported API. Importing
 * directly from "./core.js" is not guaranteed to be stable across versions.
 */

export {
  encode,
  decode,
  defaultAlphabets,
} from "./core.js";
