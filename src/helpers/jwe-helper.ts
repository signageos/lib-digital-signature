import { CompactJWEHeaderParameters, EncryptJWT, jwtDecrypt, JWTPayload } from 'jose';
import type { Config } from '../types/Config.js';
import { constants } from '../constants.js';
import { readKey } from './common.js';
import { getUnixTimestamp } from './signature-base-helper.js';

/**
 * Decrypts the input JWE string and returns the 'pkey' value from claims set.
 *
 * @param {string} jweString The JWE string.
 * @param {Config} config The input config.
 * @returns Promise<string> If the JWE decryption is successful, else returns Promise<undefined>.
 */
export async function decryptJWE(jweString: string, config: Config): Promise<string | undefined> {
	const masterKey: string = readKey(config.masterKey);

	const masterKeyBuffer: Buffer = Buffer.from(masterKey, constants.BASE64);
	const jwtDecryptResult: any = await jwtDecrypt(jweString, masterKeyBuffer);

	if (jwtDecryptResult.payload?.pkey) {
		const pKey = jwtDecryptResult.payload.pkey;
		return constants.KEY_START + pKey + constants.KEY_END;
	}
}

/**
 * Generates JWE string.
 *
 * @param {Config} config The input config.
 * @returns {Promise<string>} jwe The JWE as string.
 */
export async function encryptJWE(config: Config): Promise<string> {
	const masterKey: string = readKey(config.masterKey);

	const unixTimestamp = getUnixTimestamp();
	const masterKeyBuffer: Buffer = Buffer.from(masterKey, constants.BASE64);

	const jwe = await new EncryptJWT(config.jwtPayload as JWTPayload)
		.setProtectedHeader(config.jweHeaderParams as CompactJWEHeaderParameters)
		.setIssuedAt(unixTimestamp)
		.setNotBefore(unixTimestamp)
		.setExpirationTime(`${config.jwtExpiration}y`)
		.encrypt(masterKeyBuffer);

	return jwe;
}
