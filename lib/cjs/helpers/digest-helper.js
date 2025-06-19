"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateDigestHeader = exports.generateDigestHeader = void 0;
const crypto_1 = __importDefault(require("crypto"));
const constants_1 = require("../constants");
/**
 * Keys are in the format of algorithm used to calculate the digest (crypto package).
 * Values are in the format of content-digest header cipher.
 */
const cryptoAlgoToDashed = {
    [constants_1.constants.SHA_256]: "sha-256",
    [constants_1.constants.SHA_512]: "sha-512",
    [constants_1.constants.MD5]: "md5",
};
/**
 * Keys are in the format of content-digest header cipher.
 * Values are in the format of algorithm used to calculate the digest (crypto package).
 */
const dashedToCryptoAlgo = {
    "sha-256": constants_1.constants.SHA_256,
    "sha-512": constants_1.constants.SHA_512,
    md5: constants_1.constants.MD5,
};
function isValidCryptoAlgo(cipher) {
    return cipher in cryptoAlgoToDashed;
}
function isValidDashedAlgo(cipher) {
    return cipher in dashedToCryptoAlgo;
}
/**
 * Generates the 'Content-Digest' header value for the input payload.
 *
 * @param {Buffer} payload The request payload.
 * @param {string} cipher The algorithm used to calculate the digest.
 * @returns {string} contentDigest The 'Content-Digest' header value.
 */
function generateDigestHeader(payload, cipher) {
    let contentDigest = "";
    if (!isValidCryptoAlgo(cipher)) {
        throw new Error("Invalid cipher " + cipher);
    }
    // Validate the input payload
    if (!payload) {
        return contentDigest;
    }
    // Calculate the digest
    const hash = crypto_1.default
        .createHash(cipher)
        .update(payload)
        .digest(constants_1.constants.BASE64);
    const algo = cryptoAlgoToDashed[cipher];
    contentDigest = algo + "=" + constants_1.constants.COLON + hash + constants_1.constants.COLON;
    return contentDigest;
}
exports.generateDigestHeader = generateDigestHeader;
/**
 * Validates the 'Content-Digest' header value.
 *
 * @param {string} contentDigestHeader The Content-Digest header value.
 * @param {Buffer} body The HTTP request body.
 * @throws {Error} If the Content-Digest header value is invalid.
 */
function validateDigestHeader(contentDigestHeader, body) {
    if (!contentDigestHeader) {
        throw new Error("Content-Digest header missing");
    }
    // Validate
    const contentDigestPattern = new RegExp("(.+)=:(.+):");
    const contentDigestParts = contentDigestPattern.exec(contentDigestHeader);
    if (!contentDigestParts || contentDigestParts.length == 0) {
        throw new Error("Content-digest header invalid");
    }
    const cipher = contentDigestParts[1];
    if (!isValidDashedAlgo(cipher)) {
        throw new Error("Invalid cipher " + cipher);
    }
    const algorithm = dashedToCryptoAlgo[cipher];
    const newDigest = generateDigestHeader(body, algorithm);
    if (newDigest !== contentDigestHeader) {
        throw new Error("Content-Digest value is invalid. Expected body digest is: " + newDigest);
    }
}
exports.validateDigestHeader = validateDigestHeader;
