"use strict";

import crypto from "crypto";
import { constants } from "../constants";
import { decryptJWE, encryptJWE } from "./jwe-helper";
import {
  generateBase,
  calculateBase,
  getUnixTimestamp,
} from "./signature-base-helper";
import { Config } from "..";
import { readKey, sanitizeKey } from "./common";

// Helper function to get the signature key header name
const getSignatureKeyHeader = (config: Config): string =>
  config.signatureKeyHeader;

/**
 * Generates the signature key header (config.signatureKeyHeader) value for the input payload.
 *
 * @param {Config} config The input config.
 * @returns <Promise<string> The signature key value.
 */
async function generateSignatureKey(config: Config): Promise<string> {
  const jwe: string = await encryptJWE(config);
  return jwe;
}

/**
 * Generates the Signature-Input header value for the input payload.
 *
 * @param {any} headers The HTTP headers.
 * @param {Config} config The input config.
 * @returns {string} the 'Signature-Input' header value.
 */
function generateSignatureInput(headers: any, config: Config): string {
  const unixTimestamp = getUnixTimestamp();
  let signatureInput: string = `sig1=(`;

  config.signatureParams.forEach((param) => {
    if (
      param === constants.HEADERS.CONTENT_DIGEST &&
      !headers[constants.HEADERS.CONTENT_DIGEST]
    ) {
      return;
    }

    signatureInput += `"${param}" `;
  });

  signatureInput = signatureInput.trim() + `);created=${unixTimestamp}`;

  return signatureInput;
}

/**
 * Generates the 'Signature' header.
 *
 * @param {any} headers The HTTP headers.
 * @param {Config} config The input config.
 * @returns {string} the signature header value.
 */
function generateSignature(headers: any, config: Config): string {
  const baseString = generateBase(headers, config);
  const privateKey = readKey(config.privateKey);

  // If algorithm is undefined, then it is dependent upon the private key type.
  const signatureBuffer: any = crypto.sign(
    undefined,
    Buffer.from(baseString),
    privateKey,
  );

  let signature: string = signatureBuffer.toString(constants.BASE64);

  return constants.SIGNATURE_PREFIX + signature + constants.COLON;
}

/**
 * Validates the input signature key (header value).
 *
 * @param {string} signatureKey the signature key header value.
 * @param {Config} config The input config.
 * @returns Promise<string> the public key (pkey) value from JWT claims set.
 * @throws {Error} if the header generation fails.
 */
function validateSignatureKey(
  signatureKey: string,
  config: Config,
): Promise<string | undefined> {
  const signatureKeyHeader = getSignatureKeyHeader(config);
  try {
    return decryptJWE(signatureKey, config);
  } catch (e) {
    throw new Error(
      `Error parsing JWE from ${signatureKeyHeader} header: ${e.message}`,
    );
  }
}

/**
 * Validates the signature header value.
 *
 * @param {any} headers The HTTP headers.
 * @param {Config} config The input config.
 * @returns Promise<boolean> True upon successful signature validation.
 * @throws Error if the Signature value is invalid.
 */
async function validateSignatureHeader(
  headers: any,
  config: Config,
): Promise<boolean> {
  const signatureKeyHeader = getSignatureKeyHeader(config);
  const signature = headers[constants.HEADERS.SIGNATURE] as string;
  const signatureKey: string = headers[signatureKeyHeader] as string;

  if (!signatureKey) {
    throw new Error(`${signatureKeyHeader} header missing`);
  }

  if (!signature) {
    throw new Error(`${constants.HEADERS.SIGNATURE} header missing`);
  }

  // Validate signature pattern
  const signaturePattern = new RegExp(".+=:(.+):");
  const signatureParts = signaturePattern.exec(signature);
  if (!signatureParts || signatureParts.length < 2) {
    throw new Error("Signature header invalid");
  }

  // Base64 decode
  const signatureBuffer: Buffer = Buffer.from(
    signatureParts[1],
    constants.BASE64,
  );

  // Verify JWT
  const publicKey: any = await validateSignatureKey(signatureKey, config);
  if (config.publicKey) {
    const expectedPublicKey = sanitizeKey(readKey(config.publicKey));
    const sanitizedPublicKey = sanitizeKey(publicKey);
    if (expectedPublicKey !== sanitizedPublicKey) {
      throw new Error("Public key mismatch");
    }
  }

  const baseString: string = calculateBase(headers, config);

  // If algorithm is undefined, then it is dependent upon the public key type.
  const verificationResponse: boolean = crypto.verify(
    undefined,
    Buffer.from(baseString),
    publicKey,
    signatureBuffer,
  );

  return verificationResponse;
}

export {
  generateSignature,
  generateSignatureInput,
  generateSignatureKey,
  validateSignatureKey,
  validateSignatureHeader,
  getSignatureKeyHeader,
};
