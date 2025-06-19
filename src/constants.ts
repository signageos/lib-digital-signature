"use strict";

export const constants = {
  BASE64: "base64",
  COLON: ":",
  CONTENT_DIGEST_SHA256: "sha-256=:",
  CONTENT_DIGEST_SHA512: "sha-512=:",
  CONTENT_DIGEST_MD5: "md5=:",
  HEADERS: {
    APPLICATION_JSON: "application/json",
    CONTENT_DIGEST: "content-digest",
    SIGNATURE_INPUT: "signature-input",
    SIGNATURE: "signature",
  },
  HTTP_STATUS_CODE: {
    NO_CONTENT: 204,
    OK: 200,
    BAD_REQUEST: 400,
    INTERNAL_SERVER_ERROR: 500,
  },
  KEY_PATTERN_END: /\n-----END PUBLIC KEY-----/,
  KEY_PATTERN_START: /-----BEGIN PUBLIC KEY-----\n/,
  KEY_END: "\n-----END PUBLIC KEY-----",
  KEY_START: "-----BEGIN PUBLIC KEY-----\n",
  SHA_256: "sha256",
  SHA_512: "sha512",
  MD5: "md5",
  SIGNATURE_PREFIX: "sig1=:",
  UTF8: "utf8",
} as const;
