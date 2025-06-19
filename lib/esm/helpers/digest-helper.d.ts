/// <reference types="node" />
/**
 * Keys are in the format of algorithm used to calculate the digest (crypto package).
 * Values are in the format of content-digest header cipher.
 */
declare const cryptoAlgoToDashed: {
    sha256: string;
    sha512: string;
    md5: string;
};
/**
 * Keys are in the format of content-digest header cipher.
 * Values are in the format of algorithm used to calculate the digest (crypto package).
 */
declare const dashedToCryptoAlgo: {
    "sha-256": "sha256";
    "sha-512": "sha512";
    md5: "md5";
};
export type CryptoAlgorithm = keyof typeof cryptoAlgoToDashed;
export type DashedAlgorithm = keyof typeof dashedToCryptoAlgo;
/**
 * Generates the 'Content-Digest' header value for the input payload.
 *
 * @param {Buffer} payload The request payload.
 * @param {string} cipher The algorithm used to calculate the digest.
 * @returns {string} contentDigest The 'Content-Digest' header value.
 */
declare function generateDigestHeader(payload: Buffer, cipher: CryptoAlgorithm): string;
/**
 * Validates the 'Content-Digest' header value.
 *
 * @param {string} contentDigestHeader The Content-Digest header value.
 * @param {Buffer} body The HTTP request body.
 * @throws {Error} If the Content-Digest header value is invalid.
 */
declare function validateDigestHeader(contentDigestHeader: string, body: Buffer): void;
export { generateDigestHeader, validateDigestHeader };
