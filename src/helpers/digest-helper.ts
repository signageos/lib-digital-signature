"use strict";

import crypto from "crypto";
import { constants } from "../constants";

/**
 * Keys are in the format of algorithm used to calculate the digest (crypto package).
 * Values are in the format of content-digest header cipher.
 */
const cryptoAlgoToDashed = {
  [constants.SHA_256]: "sha-256",
  [constants.SHA_512]: "sha-512",
  [constants.MD5]: "md5",
};

/**
 * Keys are in the format of content-digest header cipher.
 * Values are in the format of algorithm used to calculate the digest (crypto package).
 */
const dashedToCryptoAlgo = {
  "sha-256": constants.SHA_256,
  "sha-512": constants.SHA_512,
  md5: constants.MD5,
};

export type CryptoAlgorithm = keyof typeof cryptoAlgoToDashed;
export type DashedAlgorithm = keyof typeof dashedToCryptoAlgo;

function isValidCryptoAlgo(cipher: string): cipher is CryptoAlgorithm {
  return cipher in cryptoAlgoToDashed;
}

function isValidDashedAlgo(cipher: string): cipher is DashedAlgorithm {
  return cipher in dashedToCryptoAlgo;
}

/**
 * Generates the 'Content-Digest' header value for the input payload.
 *
 * @param {Buffer} payload The request payload.
 * @param {string} cipher The algorithm used to calculate the digest.
 * @returns {string} contentDigest The 'Content-Digest' header value.
 */
function generateDigestHeader(
  payload: Buffer,
  cipher: CryptoAlgorithm,
): string {
  let contentDigest: string = "";

  if (!isValidCryptoAlgo(cipher)) {
    throw new Error("Invalid cipher " + cipher);
  }

  // Validate the input payload
  if (!payload) {
    return contentDigest;
  }

  // Calculate the digest
  const hash = crypto
    .createHash(cipher)
    .update(payload)
    .digest(constants.BASE64);

  const algo = cryptoAlgoToDashed[cipher];

  contentDigest = algo + "=" + constants.COLON + hash + constants.COLON;
  return contentDigest;
}

/**
 * Validates the 'Content-Digest' header value.
 *
 * @param {string} contentDigestHeader The Content-Digest header value.
 * @param {Buffer} body The HTTP request body.
 * @throws {Error} If the Content-Digest header value is invalid.
 */
function validateDigestHeader(contentDigestHeader: string, body: Buffer): void {
  if (!contentDigestHeader) {
    throw new Error("Content-Digest header missing");
  }

  // Validate
  const contentDigestPattern = new RegExp("(.+)=:(.+):");
  const contentDigestParts = contentDigestPattern.exec(contentDigestHeader);
  if (!contentDigestParts || contentDigestParts.length == 0) {
    throw new Error("Content-digest header invalid");
  }
  const cipher: string = contentDigestParts[1];

  if (!isValidDashedAlgo(cipher)) {
    throw new Error("Invalid cipher " + cipher);
  }

  const algorithm = dashedToCryptoAlgo[cipher];
  const newDigest: string = generateDigestHeader(body, algorithm);

  if (newDigest !== contentDigestHeader) {
    throw new Error(
      "Content-Digest value is invalid. Expected body digest is: " + newDigest,
    );
  }
}

export { generateDigestHeader, validateDigestHeader };
