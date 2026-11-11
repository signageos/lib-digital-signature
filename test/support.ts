import crypto from 'crypto';
import type { Config } from '../src/index';
import type { SignatureComponents } from '../src/types/SignatureComponents';

export const MASTER_KEY_PATH = './examples/keys/masterkey.key';
export const SIGNATURE_KEY_HEADER = 'x-sos-signature-key';
// The fixture JWEs are valid from these instants; jose checks iat/nbf/exp against `new Date()`.
export const ED25519_FIXTURE_TIME = 1663459378000;
export const RSA_FIXTURE_TIME = 1664063650000;

export function createConfig(overrides: Partial<Config> = {}): Config {
	return {
		digestAlgorithm: 'sha256',
		jwe: '',
		jwtExpiration: 3,
		jweHeaderParams: { alg: 'A256GCMKW', enc: 'A256GCM', zip: 'DEF' },
		jwtPayload: {},
		masterKey: MASTER_KEY_PATH,
		privateKey: '',
		publicKey: '',
		signatureComponents: createComponents(),
		signatureParams: [],
		signatureKeyHeader: SIGNATURE_KEY_HEADER,
		...overrides,
	};
}

export function createComponents(overrides: Partial<SignatureComponents> = {}): SignatureComponents {
	return {
		authority: 'localhost:8080',
		method: 'POST',
		path: '/test',
		requestTarget: 'post /test',
		scheme: 'https',
		targetUri: 'https://localhost:8080/test',
		...overrides,
	};
}

/** The base64 body of an SPKI PEM, which is what the JWE `pkey` claim carries. */
export function toPkeyClaim(publicKeyPem: string): string {
	return crypto
		.createPublicKey(publicKeyPem)
		.export({ type: 'spki', format: 'pem' })
		.toString()
		.replace(/-----(BEGIN|END) PUBLIC KEY-----|\s/g, '');
}

/** Inverts the first byte of a `label=:base64:` signature, keeping the header well-formed. */
export function tamperSignature(signature: string): string {
	const match = /^(.+=:)(.+)(:)$/.exec(signature);
	if (!match?.[2]) {
		throw new Error(`Not a signature header: ${signature}`);
	}
	const bytes = Buffer.from(match[2], 'base64');
	bytes[0] = 255 - (bytes[0] ?? 0);
	return `${match[1]}${bytes.toString('base64')}${match[3]}`;
}
