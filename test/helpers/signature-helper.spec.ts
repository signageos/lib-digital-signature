import crypto from 'crypto';
import should from 'should';
import sinon from 'sinon';
import { encryptJWE } from '../../src/helpers/jwe-helper';
import {
	generateSignature,
	generateSignatureInput,
	getSignatureKeyHeader,
	validateSignatureHeader,
	validateSignatureKey,
} from '../../src/helpers/signature-helper';
import fixtures from '../fixtures.json';
import { B26, PROXY_RSA, TEST_KEY_ED25519_PRIVATE, TEST_KEY_ED25519_PUBLIC, TEST_KEY_RSA_PUBLIC } from '../rfc/rfc9421';
import { createComponents, createConfig, ED25519_FIXTURE_TIME, SIGNATURE_KEY_HEADER, tamperSignature, toPkeyClaim } from '../support';

// fixtures.json's ED25519 JWE carries the RFC 9421 test-key-ed25519 public key.
const ED25519_JWE = fixtures.ED25519_SIGN.jwe;

describe('helpers/signature-helper', function () {
	let clock: sinon.SinonFakeTimers;

	beforeEach(function () {
		clock = sinon.useFakeTimers({ now: ED25519_FIXTURE_TIME, toFake: ['Date'] });
	});

	afterEach(function () {
		clock.restore();
	});

	describe('validateSignatureHeader', function () {
		const b26Config = createConfig({
			publicKey: TEST_KEY_ED25519_PUBLIC,
			signatureComponents: createComponents(B26.components),
		});
		const b26Headers = { ...B26.headers, [SIGNATURE_KEY_HEADER]: ED25519_JWE };

		it('should accept the RFC 9421 B.2.6 ed25519 signature', async function () {
			should(await validateSignatureHeader(b26Headers, b26Config)).be.true();
		});

		it('should accept the RFC 9421 section 4.3 rsa-v1_5-sha256 signature', async function () {
			const config = createConfig({
				jwtPayload: { pkey: toPkeyClaim(TEST_KEY_RSA_PUBLIC) },
				signatureComponents: createComponents(PROXY_RSA.components),
			});
			const headers = { ...PROXY_RSA.headers, [SIGNATURE_KEY_HEADER]: await encryptJWE(config) };

			should(await validateSignatureHeader(headers, config)).be.true();
		});

		it('should skip the public key check when the config has none', async function () {
			should(await validateSignatureHeader(b26Headers, { ...b26Config, publicKey: '' })).be.true();
		});

		it('should reject a tampered signature', async function () {
			const headers = { ...b26Headers, signature: tamperSignature(B26.headers.signature) };
			should(await validateSignatureHeader(headers, b26Config)).be.false();
		});

		it('should reject a signature over different components', async function () {
			const config = { ...b26Config, signatureComponents: createComponents({ ...B26.components, method: 'GET' }) };
			should(await validateSignatureHeader(b26Headers, config)).be.false();
		});

		it('should reject a signature over a different header value', async function () {
			const headers = { ...b26Headers, 'content-length': '19' };
			should(await validateSignatureHeader(headers, b26Config)).be.false();
		});

		it('should reject a signature key carrying another public key', async function () {
			const config = {
				...b26Config,
				publicKey: crypto.createPublicKey(TEST_KEY_RSA_PUBLIC).export({ type: 'spki', format: 'pem' }).toString(),
			};
			await should(validateSignatureHeader(b26Headers, config)).be.rejectedWith('Public key mismatch');
		});

		it('should reject a missing signature key header', async function () {
			await should(validateSignatureHeader(B26.headers, b26Config)).be.rejectedWith(`${SIGNATURE_KEY_HEADER} header missing`);
		});

		it('should reject a missing signature header', async function () {
			const { signature: _signature, ...headers } = b26Headers;
			await should(validateSignatureHeader(headers, b26Config)).be.rejectedWith('signature header missing');
		});

		it('should reject a malformed signature header', async function () {
			await should(validateSignatureHeader({ ...b26Headers, signature: 'sig-b26' }, b26Config)).be.rejectedWith('Signature header invalid');
		});

		it('should reject a signature key encrypted with another master key', async function () {
			const config = { ...b26Config, masterKey: Buffer.alloc(32, 1).toString('base64') };
			await should(validateSignatureHeader(b26Headers, config)).be.rejected();
		});
	});

	describe('validateSignatureKey', function () {
		it('should return the public key the signature key carries', async function () {
			should(await validateSignatureKey(ED25519_JWE, createConfig())).equal(TEST_KEY_ED25519_PUBLIC);
		});
	});

	describe('generateSignatureInput', function () {
		const config = createConfig({ signatureParams: ['content-digest', SIGNATURE_KEY_HEADER, '@method'] });

		it('should cover the Content-Digest header when the message carries one', function () {
			should(generateSignatureInput({ 'content-digest': 'sha-256=:abc=:' }, config)).equal(
				'sig1=("content-digest" "x-sos-signature-key" "@method");created=1663459378',
			);
		});

		it('should leave the Content-Digest header out when the message has none', function () {
			should(generateSignatureInput({}, config)).equal('sig1=("x-sos-signature-key" "@method");created=1663459378');
		});
	});

	describe('generateSignature', function () {
		it('should reproduce the RFC 9421 B.2.6 ed25519 signature from its Signature-Input', function () {
			const config = createConfig({
				privateKey: TEST_KEY_ED25519_PRIVATE,
				signatureComponents: createComponents(B26.components),
				signatureParams: ['@method'],
			});
			const signature = generateSignature(B26.headers, config);
			should(signature.replace(/^sig1=/, 'sig-b26=')).equal(B26.headers.signature);
		});

		it('should sign the created time of the Signature-Input header, not the clock', async function () {
			const config = createConfig({
				jwtPayload: { pkey: toPkeyClaim(TEST_KEY_ED25519_PUBLIC) },
				privateKey: TEST_KEY_ED25519_PRIVATE,
				signatureParams: [SIGNATURE_KEY_HEADER, '@method', '@path'],
			});
			clock.setSystemTime(ED25519_FIXTURE_TIME + 900);
			const headers: Record<string, string> = { [SIGNATURE_KEY_HEADER]: await encryptJWE(config) };
			headers['signature-input'] = generateSignatureInput(headers, config);

			clock.setSystemTime(ED25519_FIXTURE_TIME + 1100);
			headers.signature = generateSignature(headers, config);

			should(await validateSignatureHeader(headers, config)).be.true();
		});

		it('should sign with the configured private key', function () {
			const config = createConfig({ privateKey: TEST_KEY_ED25519_PRIVATE, signatureParams: ['@method', '@path'] });
			const signature = generateSignature({}, config);
			const [, value] = /^sig1=:(.+):$/.exec(signature) ?? [];
			const base = '"@method": POST\n"@path": /test\n"@signature-params": ("@method" "@path");created=1663459378';

			should(crypto.verify(undefined, Buffer.from(base), TEST_KEY_ED25519_PUBLIC, Buffer.from(value ?? '', 'base64'))).be.true();
		});
	});

	describe('getSignatureKeyHeader', function () {
		it('should return the configured header name', function () {
			should(getSignatureKeyHeader(createConfig({ signatureKeyHeader: 'x-custom' }))).equal('x-custom');
		});
	});
});
