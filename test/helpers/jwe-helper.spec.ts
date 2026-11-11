import fs from 'fs';
import { jwtDecrypt } from 'jose';
import should from 'should';
import sinon from 'sinon';
import { decryptJWE, encryptJWE } from '../../src/helpers/jwe-helper';
import { TEST_KEY_ED25519_PUBLIC } from '../rfc/rfc9421';
import { createConfig, MASTER_KEY_PATH, toPkeyClaim } from '../support';

const NOW = 1663459378000;
const YEAR_SECONDS = 365.25 * 24 * 60 * 60;

describe('helpers/jwe-helper', function () {
	let clock: sinon.SinonFakeTimers;
	const config = createConfig({ jwtPayload: { pkey: toPkeyClaim(TEST_KEY_ED25519_PUBLIC) } });

	beforeEach(function () {
		clock = sinon.useFakeTimers({ now: NOW, toFake: ['Date'] });
	});

	afterEach(function () {
		clock.restore();
	});

	it('should round-trip the public key through the JWE', async function () {
		const jwe = await encryptJWE(config);
		should(await decryptJWE(jwe, config)).equal(TEST_KEY_ED25519_PUBLIC);
	});

	it('should issue the token now and let it expire after jwtExpiration years', async function () {
		const { payload, protectedHeader } = await jwtDecrypt(
			await encryptJWE(config),
			Buffer.from(fs.readFileSync(MASTER_KEY_PATH, 'utf8'), 'base64'),
		);

		should(payload.iat).equal(NOW / 1000);
		should(payload.nbf).equal(NOW / 1000);
		should(payload.exp).equal(NOW / 1000 + 3 * YEAR_SECONDS);
		should(protectedHeader).containEql({ alg: 'A256GCMKW', enc: 'A256GCM', zip: 'DEF' });
	});

	it('should reject an expired token', async function () {
		const jwe = await encryptJWE(config);
		clock.setSystemTime(NOW + (3 * YEAR_SECONDS + 1) * 1000);
		await should(decryptJWE(jwe, config)).be.rejectedWith({ code: 'ERR_JWT_EXPIRED' });
	});

	it('should reject a token that is not valid yet', async function () {
		const jwe = await encryptJWE(config);
		clock.setSystemTime(NOW - 1000);
		await should(decryptJWE(jwe, config)).be.rejectedWith({ code: 'ERR_JWT_CLAIM_VALIDATION_FAILED' });
	});

	it('should reject a token encrypted with another master key', async function () {
		const jwe = await encryptJWE(createConfig({ ...config, masterKey: Buffer.alloc(32, 1).toString('base64') }));
		await should(decryptJWE(jwe, config)).be.rejected();
	});

	it('should return nothing for a token without a public key', async function () {
		const jwe = await encryptJWE(createConfig());
		should(await decryptJWE(jwe, config)).be.undefined();
	});
});
