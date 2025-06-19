"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.encryptJWE = exports.decryptJWE = void 0;
const jose_1 = require("jose");
const constants_1 = require("../constants");
const common_1 = require("./common");
const signature_base_helper_1 = require("./signature-base-helper");
/**
 * Decrypts the input JWE string and returns the 'pkey' value from claims set.
 *
 * @param {string} jweString The JWE string.
 * @param {Config} config The input config.
 * @returns Promise<string> If the JWE decryption is successful, else returns Promise<undefined>.
 */
async function decryptJWE(jweString, config) {
    const masterKey = (0, common_1.readKey)(config.masterKey);
    const masterKeyBuffer = Buffer.from(masterKey, constants_1.constants.BASE64);
    const jwtDecryptResult = await (0, jose_1.jwtDecrypt)(jweString, masterKeyBuffer);
    if (jwtDecryptResult["payload"] && jwtDecryptResult["payload"]["pkey"]) {
        const pKey = jwtDecryptResult["payload"]["pkey"];
        return constants_1.constants.KEY_START + pKey + constants_1.constants.KEY_END;
    }
}
exports.decryptJWE = decryptJWE;
/**
 * Generates JWE string.
 *
 * @param {Config} config The input config.
 * @returns {Promise<string>} jwe The JWE as string.
 */
async function encryptJWE(config) {
    const masterKey = (0, common_1.readKey)(config.masterKey);
    let publicKey = (0, common_1.readKey)(config.publicKey);
    publicKey = formatPublicKey(publicKey);
    const unixTimestamp = (0, signature_base_helper_1.getUnixTimestamp)();
    const masterKeyBuffer = Buffer.from(masterKey, constants_1.constants.BASE64);
    const jwe = await new jose_1.EncryptJWT(config.jwtPayload)
        .setProtectedHeader(config.jweHeaderParams)
        .setIssuedAt(unixTimestamp)
        .setNotBefore(unixTimestamp)
        .setExpirationTime(`${config.jwtExpiration}y`)
        .encrypt(masterKeyBuffer);
    return jwe;
}
exports.encryptJWE = encryptJWE;
/**
 * Removes beginning and end markers from the input public key.
 *
 * @param {string} key The public key.
 * @throws {Error} if the key format is invalid.
 */
function formatPublicKey(key) {
    try {
        const updatedKey = key.replace(constants_1.constants.KEY_PATTERN_START, "");
        return updatedKey.replace(constants_1.constants.KEY_PATTERN_END, "");
    }
    catch (exception) {
        throw new Error(`Invalid public key format`);
    }
}
