import { Response, Request } from 'express';
import { jwtDecrypt } from 'jose';
import should from 'should';
import sinon from 'sinon';
import { constants } from '../src/constants';
import { readKey } from '../src/helpers/common';
import * as DigitalSignatureSDK from '../src/index';
import fixtures from './fixtures.json';
import { ED25519_FIXTURE_TIME, RSA_FIXTURE_TIME, tamperSignature } from './support';
const testData = fixtures as unknown as Record<keyof typeof fixtures, DigitalSignatureSDK.Config>;

describe('test Signature SDK', function () {
	let clock: sinon.SinonFakeTimers;

	beforeEach(function () {
		clock = sinon.useFakeTimers({ now: ED25519_FIXTURE_TIME, toFake: ['Date'] });
	});

	afterEach(function () {
		clock.restore();
	});

	describe('Content-Digest', function () {
		it('should be able to generate for SHA256 cipher', function () {
			const request: string = '{"hello": "world"}';
			const requestBuffer: Buffer = Buffer.from(request);
			const expected: string = 'sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:';

			const actual = DigitalSignatureSDK.generateDigestHeader(requestBuffer, constants.SHA_256);

			should(actual).equal(expected);
		});

		it('should be able to generate for SHA512 cipher', function () {
			const request: string = '{"hello": "world"}';
			const requestBuffer: Buffer = Buffer.from(request);
			const expected: string = 'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:';

			const actual = DigitalSignatureSDK.generateDigestHeader(requestBuffer, constants.SHA_512);

			should(actual).equal(expected);
		});

		it('should be able to generate for MD5 cipher', function () {
			const request: string = '{"hello": "world"}';
			const requestBuffer: Buffer = Buffer.from(request);
			const expected: string = `md5=:Sd/dVLAcvNLSq16eXua5uQ==:`;

			const actual = DigitalSignatureSDK.generateDigestHeader(requestBuffer, constants.MD5);

			should(actual).equal(expected);
		});
	});

	const testCases = [
		{
			digestAlgorithm: 'sha256',
			digestAlgo: 'sha-256',
			testDigest: 'X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=',
			expectedSignature: 'dzURGVP+qnm4HSWpkJY7xbYUCulHp4yD724NI12CJtUDcp6z3z2YRKvsbH/ypw1u/e4DRE39OPhlzCn0TCWuAg==',
		},
		{
			digestAlgorithm: 'md5',
			digestAlgo: 'md5',
			testDigest: 'Sd/dVLAcvNLSq16eXua5uQ==',
			expectedSignature: 'SQLay/Qy9QqiExbSY9Qtjj37H6T7hlf+Xf9Q8oIk0z+sDYCnQwed8mB9uKq1AXDkJd3AJhtjq6l9HO2ZvgqGAA==',
		},
	] as const;

	testCases.forEach(({ digestAlgorithm, digestAlgo, testDigest, expectedSignature }) =>
		describe(`ED25519 - ${digestAlgorithm}`, function () {
			it("should be able to generate 'signature-input' header when request has payload", function () {
				const config: DigitalSignatureSDK.Config = testData.ED25519;
				const expected: string = `sig1=("content-digest" "x-sos-signature-key" "@method" "@path" "@authority");created=1663459378`;

				const actual = DigitalSignatureSDK.generateSignatureInput({ 'content-digest': 'test' }, config);

				should(actual).equal(expected);
			});

			it("should be able to generate 'signature-input' header when request has no payload", function () {
				const config: DigitalSignatureSDK.Config = testData.ED25519_GET;
				const expected: string = `sig1=("x-sos-signature-key" "@method" "@path" "@authority");created=1663459378`;

				const actual = DigitalSignatureSDK.generateSignatureInput({ 'content-digest': 'test' }, config);

				should(actual).equal(expected);
			});

			it("should be able to generate 'Signature' header", function () {
				const config: DigitalSignatureSDK.Config = testData.ED25519;
				const expected = 'sig1=:' + expectedSignature + ':';

				const actual = DigitalSignatureSDK.generateSignature(
					{
						'content-digest': digestAlgo + '=:' + testDigest + ':',
						'signature-input': 'sig1=("content-digest" "x-sos-signature-key" "@method" "@path" "@authority");created=1663459378',
						'x-sos-signature-key':
							'eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiemlwIjoiREVGIiwiaXYiOiJvSzFwdXJNVHQtci14VUwzIiwidGFnIjoiTjB4WjI4ZklZckFmYkd5UWFrTnpjZyJ9.AYdKU7ObIc7Z764OrlKpwUViK8Rphxl0xMP9v2_o9mI.1DbZiSQNRK6pLeIw.Yzp3IDV8RM_h_lMAnwGpMA4DXbaDdmqAh-65kO9xyDgzHD6s0kY3p-yO6oPR9kEcAbjGXIULeQKWVYzbfHKwXTY09Npj_mNuO5yxgZtWnL55uIgP2HL1So2dKkZRK0eyPa6DEXJT71lPtwZtpIGyq9R5h6s3kGMbqA.m4t_MX4VnlXJGx1X_zZ-KQ',
					},
					config,
				);

				should(actual).equal(expected);
			});

			it("should be able to generate 'Signature' header with given JWE", function () {
				const config: DigitalSignatureSDK.Config = testData.ED25519_SIGN;
				const expected = 'sig1=:' + expectedSignature + ':';

				const actual = DigitalSignatureSDK.generateSignature(
					{
						'content-digest': digestAlgo + '=:' + testDigest + ':',
						'signature-input': 'sig1=("content-digest" "x-sos-signature-key" "@method" "@path" "@authority");created=1663459378',
						'x-sos-signature-key':
							'eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiemlwIjoiREVGIiwiaXYiOiJvSzFwdXJNVHQtci14VUwzIiwidGFnIjoiTjB4WjI4ZklZckFmYkd5UWFrTnpjZyJ9.AYdKU7ObIc7Z764OrlKpwUViK8Rphxl0xMP9v2_o9mI.1DbZiSQNRK6pLeIw.Yzp3IDV8RM_h_lMAnwGpMA4DXbaDdmqAh-65kO9xyDgzHD6s0kY3p-yO6oPR9kEcAbjGXIULeQKWVYzbfHKwXTY09Npj_mNuO5yxgZtWnL55uIgP2HL1So2dKkZRK0eyPa6DEXJT71lPtwZtpIGyq9R5h6s3kGMbqA.m4t_MX4VnlXJGx1X_zZ-KQ',
					},
					config,
				);

				should(actual).equal(expected);
			});

			it("should be able to generate 'x-sos-signature-key' header", async function () {
				const actual = await DigitalSignatureSDK.generateSignatureKey(testData.ED25519);

				const masterKey: string = readKey(testData.ED25519.masterKey);
				const masterKeyBuffer: Buffer = Buffer.from(masterKey, constants.BASE64);
				const jwtDecryptResult: any = await jwtDecrypt(actual, masterKeyBuffer);

				should(jwtDecryptResult.payload.iat).equal(1663459378);
				should(jwtDecryptResult.payload.nbf).equal(1663459378);
				should(jwtDecryptResult.payload.pkey).equal('MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=');
				should(jwtDecryptResult.protectedHeader.alg).equal('A256GCMKW');
				should(jwtDecryptResult.protectedHeader.enc).equal('A256GCM');
				should(jwtDecryptResult.protectedHeader.zip).equal('DEF');
			});

			it('should be able to sign a request', async function () {
				const payload: string = '{"hello": "world"}';
				const payloadBuffer: Buffer = Buffer.from(payload);
				const mockedRequest = {
					method: 'POST',
					headers: {
						host: 'localhost:8080',
						url: '/test',
					},
					body: payloadBuffer,
				} as unknown as Request;

				const mockedResponse = {
					setHeader: sinon.spy(),
				} as unknown as Response;

				await DigitalSignatureSDK.signMessage(mockedRequest, mockedResponse, {
					...testData.ED25519,
					digestAlgorithm,
				});

				const signatureSpy = mockedResponse.setHeader as sinon.SinonSpy;
				sinon.assert.calledWith(signatureSpy, 'content-digest', digestAlgo + '=:' + testDigest + ':');
				sinon.assert.calledWith(
					signatureSpy,
					'signature-input',
					'sig1=("content-digest" "x-sos-signature-key" "@method" "@path" "@authority");created=1663459378',
				);
				sinon.assert.calledWith(signatureSpy, 'signature', sinon.match.string);
				sinon.assert.calledWith(signatureSpy, 'x-sos-signature-key', sinon.match.string);
			});

			it('should be able to validate request signature', async function () {
				const payload: string = '{"hello": "world"}';
				const payloadBuffer: Buffer = Buffer.from(payload);
				const request = {
					method: 'POST',
					headers: {
						host: 'localhost:8080',
						url: '/test',
						'content-type': 'application/json',
						'content-digest': digestAlgo + '=:' + testDigest + ':',
						'signature-input': 'sig1=("content-digest" "x-sos-signature-key" "@method" "@path" "@authority");created=1663459378',
						'x-sos-signature-key':
							'eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiemlwIjoiREVGIiwiaXYiOiJvSzFwdXJNVHQtci14VUwzIiwidGFnIjoiTjB4WjI4ZklZckFmYkd5UWFrTnpjZyJ9.AYdKU7ObIc7Z764OrlKpwUViK8Rphxl0xMP9v2_o9mI.1DbZiSQNRK6pLeIw.Yzp3IDV8RM_h_lMAnwGpMA4DXbaDdmqAh-65kO9xyDgzHD6s0kY3p-yO6oPR9kEcAbjGXIULeQKWVYzbfHKwXTY09Npj_mNuO5yxgZtWnL55uIgP2HL1So2dKkZRK0eyPa6DEXJT71lPtwZtpIGyq9R5h6s3kGMbqA.m4t_MX4VnlXJGx1X_zZ-KQ',
						signature: 'sig1=:' + expectedSignature + ':',
					},
					body: payloadBuffer,
				} as unknown as Request;

				const actual: boolean = await DigitalSignatureSDK.validateSignature(request, { ...testData.ED25519, digestAlgorithm });

				should(actual).be.true();
			});

			it('should generate a valid signature', async function () {
				const payload: string = '{"hello": "world"}';
				const payloadBuffer: Buffer = Buffer.from(payload);
				const config: DigitalSignatureSDK.Config = {
					...testData.ED25519,
					digestAlgorithm,
				};
				const contentDigest = DigitalSignatureSDK.generateDigestHeader(payloadBuffer, config.digestAlgorithm);
				const signatureInput = DigitalSignatureSDK.generateSignatureInput(
					{
						'content-digest': contentDigest,
					},
					config,
				);
				const signatureKey = await DigitalSignatureSDK.generateSignatureKey(config);
				const signature = DigitalSignatureSDK.generateSignature(
					{
						'content-digest': contentDigest,
						'signature-input': signatureInput,
						'x-sos-signature-key': signatureKey,
					},
					config,
				);

				const request = {
					method: 'POST',
					headers: {
						host: 'localhost:8080',
						url: '/test',
						'content-type': 'application/json',
						'content-digest': contentDigest,
						'signature-input': signatureInput,
						'x-sos-signature-key': signatureKey,
						signature: signature,
					},
					body: payloadBuffer,
				} as unknown as Request;

				const actual: boolean = await DigitalSignatureSDK.validateSignature(request, testData.ED25519);

				should(actual).be.true();
			});

			it('should generate a valid signature for GET requests', async function () {
				const config: DigitalSignatureSDK.Config = testData.ED25519_GET;

				const signatureInput = DigitalSignatureSDK.generateSignatureInput(
					{
						'content-digest': 'test',
					},
					config,
				);
				const signatureKey = await DigitalSignatureSDK.generateSignatureKey(config);
				const signature = DigitalSignatureSDK.generateSignature(
					{
						'signature-input': signatureInput,
						'x-sos-signature-key': signatureKey,
					},
					config,
				);

				const request = {
					method: 'GET',
					headers: {
						host: 'localhost:8080',
						url: '/test',
						'content-type': 'application/json',
						'signature-input': signatureInput,
						'x-sos-signature-key': signatureKey,
						signature: signature,
					},
				} as unknown as Request;

				const actual: boolean = await DigitalSignatureSDK.validateSignature(request, testData.ED25519_GET);

				should(actual).be.true();
			});

			it('should work when keys are provided in the config', async function () {
				const payload: string = '{"hello": "world"}';
				const payloadBuffer: Buffer = Buffer.from(payload);
				const config: DigitalSignatureSDK.Config = {
					...testData.ED25519_CONFIG_KEYS,
					digestAlgorithm: 'sha256',
				};
				const contentDigest = DigitalSignatureSDK.generateDigestHeader(payloadBuffer, config.digestAlgorithm);
				const signatureInput = DigitalSignatureSDK.generateSignatureInput(
					{
						'content-digest': contentDigest,
					},
					config,
				);
				const signatureKey = await DigitalSignatureSDK.generateSignatureKey(config);
				const signature = DigitalSignatureSDK.generateSignature(
					{
						'content-digest': contentDigest,
						'signature-input': signatureInput,
						'x-sos-signature-key': signatureKey,
					},
					config,
				);

				const request = {
					method: 'POST',
					headers: {
						host: 'localhost:8080',
						url: '/test',
						'content-type': 'application/json',
						'content-digest': contentDigest,
						'signature-input': signatureInput,
						'x-sos-signature-key': signatureKey,
						signature: signature,
					},
					body: payloadBuffer,
				} as unknown as Request;

				const actual: boolean = await DigitalSignatureSDK.validateSignature(request, testData.ED25519_CONFIG_KEYS);

				should(actual).be.true();
			});
		}),
	);

	describe('RSA', function () {
		beforeEach(function () {
			clock.setSystemTime(RSA_FIXTURE_TIME);
		});

		it('should be able to validate request signature', async function () {
			const payload: string = '{"hello": "world"}';
			const payloadBuffer: Buffer = Buffer.from(payload);
			const request = {
				method: 'POST',
				headers: {
					host: 'localhost:8080',
					url: '/test',
					'content-type': 'application/json',
					'content-digest': 'sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:',
					'signature-input': 'sig1=("content-digest" "x-sos-signature-key" "@method" "@path" "@authority");created=1664063650',
					'x-sos-signature-key':
						'eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiemlwIjoiREVGIiwiaXYiOiIwUVRybDVMOWQwdE9BMXhRIiwidGFnIjoiei1mOEJWUjB4TW5KSGtvNE9CYVNkQSJ9.NypbYr7pgnS_mYUwCodu-pXqdFSlojCuwGO0EoWLthg.WuMvyt-cyYBdKB_Z.-4tx5mS8orriIwTGE7dURY80lEo2GchrTlyX3OcN70dbd9WAlJHMP6eyUuDtr5wlk2xLjCQfC-rsuGbWCtaFkM2uuSPNds1DGjHA8-boO_IccyxFMYL_kOKPuFFoqML3q3PDgvUzdS9z96JLyalEwY6wotzAye7suuhl0TS9gOEatCwnKi9Cpq7XJMX9Fh5vuw1oiic_yYqIQI540LnjCq9i-nxEzZ4LExH2Mp4TQaCd4_uZkCjfr0iUuk2OoFbNvhxo2bwFbL4uStpMs1cBRx51O9-CLemzsULGl6U5-YeY2Lf7qBPLqYYHb3ih9pgfEcOVUaX7xZEl8_vp_nqcuu-2mpkcmjKqE7xTdbXzhGGvdlrP5OJudkSxT_fk9eisjI-Kyn2mInLcsOG5xQxNVktkwTLnyPSIQqWuJ87mfwnLh8vkeiOy7SQArBunl133S28SGG_O2rudumvIvqA0b-nuOTU-BA2kEa6ADg5X2wq8rg.AT1DhPD8FGYgT-uScKj9QQ',
					signature:
						'sig1=:TDZuPWqYCy/nMXTVMwahE8bqW5F7Fqv/oXBbM4+/mdw7jZe8I2ddDWSHCh7FFrxbTey/j4MkyptyNds6Gnxzqz3IanzZF/bamk8iZFK/QiMxZJERUaUt5RNru7fVddmpf+idLye+GCc0btgco3efqVQ16kvnwz2jpWYORGMTtcwKhSp9ysIsoaw3ql8O9FzGIMprAzO9lRyoCiPAN3N+GMt9fxdgQEWsF+zBOwXg9aC8Su4nhXOJ+Dnnbwa1xEZqYFq/vDk51y/pWkZ7o71HDjcWmGTe0JtcxgTWV2UEDo7YhTfPARi7WqVz/41XeEV/0MHKedvlzqDgdNQAeIBLKA==:',
				},
				body: payloadBuffer,
			} as unknown as Request;

			const actual: boolean = await DigitalSignatureSDK.validateSignature(request, testData.RSA);

			should(actual).be.true();
		});

		it('should generate a valid signature', async function () {
			const payload: string = '{"hello": "world"}';
			const payloadBuffer: Buffer = Buffer.from(payload);
			const config: DigitalSignatureSDK.Config = {
				...testData.RSA,
				digestAlgorithm: 'sha256',
			};
			const contentDigest = DigitalSignatureSDK.generateDigestHeader(payloadBuffer, config.digestAlgorithm);
			const signatureInput = DigitalSignatureSDK.generateSignatureInput(
				{
					'content-digest': contentDigest,
				},
				config,
			);
			const signatureKey = await DigitalSignatureSDK.generateSignatureKey(config);
			const signature = DigitalSignatureSDK.generateSignature(
				{
					'content-digest': contentDigest,
					'signature-input': signatureInput,
					'x-sos-signature-key': signatureKey,
				},
				config,
			);

			const request = {
				method: 'POST',
				headers: {
					host: 'localhost:8080',
					url: '/test',
					'content-type': 'application/json',
					'content-digest': contentDigest,
					'signature-input': signatureInput,
					'x-sos-signature-key': signatureKey,
					signature: signature,
				},
				body: payloadBuffer,
			} as unknown as Request;

			const actual: boolean = await DigitalSignatureSDK.validateSignature(request, config);

			should(actual).be.true();
		});

		it('should generate a valid signature for GET requests', async function () {
			const config: DigitalSignatureSDK.Config = testData.RSA_GET;

			const signatureInput = DigitalSignatureSDK.generateSignatureInput({}, config);
			const signatureKey = await DigitalSignatureSDK.generateSignatureKey(config);
			const signature = DigitalSignatureSDK.generateSignature(
				{
					'signature-input': signatureInput,
					'x-sos-signature-key': signatureKey,
				},
				config,
			);

			const request = {
				method: 'GET',
				headers: {
					host: 'localhost:8080',
					url: '/test',
					'content-type': 'application/json',
					'signature-input': signatureInput,
					'x-sos-signature-key': signatureKey,
					signature: signature,
				},
			} as unknown as Request;

			const actual: boolean = await DigitalSignatureSDK.validateSignature(request, config);

			should(actual).be.true();
		});
	});
	describe('validateSignature', function () {
		const config = { ...testData.ED25519, digestAlgorithm: 'sha256' } as const;
		let consoleError: sinon.SinonStub;

		beforeEach(function () {
			consoleError = sinon.stub(console, 'error');
		});

		afterEach(function () {
			consoleError.restore();
		});

		async function signPostRequest(body: Buffer): Promise<Request> {
			const headers: Record<string, string> = {};
			const response = { setHeader: (name: string, value: string) => (headers[name] = value) } as unknown as Response;
			await DigitalSignatureSDK.signMessage({ method: 'POST', headers: {}, body } as unknown as Request, response, config);
			return { method: 'POST', headers, body } as unknown as Request;
		}

		it('should accept a request signMessage signed', async function () {
			const request = await signPostRequest(Buffer.from('{"hello": "world"}'));
			should(await DigitalSignatureSDK.validateSignature(request, config)).be.true();
		});

		it('should reject a tampered signature', async function () {
			const request = await signPostRequest(Buffer.from('{"hello": "world"}'));
			request.headers.signature = tamperSignature(request.headers.signature as string);
			should(await DigitalSignatureSDK.validateSignature(request, config)).be.false();
		});

		it('should reject a body that does not match its Content-Digest', async function () {
			const request = await signPostRequest(Buffer.from('{"hello": "world"}'));
			request.body = Buffer.from('{"hello": "World"}');
			should(await DigitalSignatureSDK.validateSignature(request, config)).be.false();
			sinon.assert.calledWithMatch(consoleError, sinon.match.has('message', sinon.match(/^Content-Digest value is invalid/)));
		});

		it('should reject a request with a body but no Content-Digest', async function () {
			const request = await signPostRequest(Buffer.from('{"hello": "world"}'));
			delete request.headers['content-digest'];
			should(await DigitalSignatureSDK.validateSignature(request, config)).be.false();
		});

		it('should reject a request without a signature', async function () {
			const request = { method: 'GET', headers: {} } as unknown as Request;
			should(await DigitalSignatureSDK.validateSignature(request, config)).be.false();
			sinon.assert.calledWithMatch(consoleError, sinon.match.has('message', 'Signature header is missing'));
		});

		it('should reject a missing request', async function () {
			should(await DigitalSignatureSDK.validateSignature(undefined as unknown as Request, config)).be.false();
		});
	});

	describe('signMessage', function () {
		async function signAndValidate(request: Request, config: DigitalSignatureSDK.Config, onSignatureInput?: () => void): Promise<boolean> {
			const headers: Record<string, string> = {};
			const response = {
				setHeader: (name: string, value: string) => {
					headers[name] = value;
					if (name === 'signature-input') {
						onSignatureInput?.();
					}
				},
			} as unknown as Response;
			await DigitalSignatureSDK.signMessage(request, response, config);
			return DigitalSignatureSDK.validateSignature({ ...request, headers } as unknown as Request, config);
		}

		it('should sign a request without a body when the config covers content-digest', async function () {
			const request = { method: 'POST', headers: {} } as unknown as Request;
			should(await signAndValidate(request, { ...testData.ED25519, digestAlgorithm: 'sha256' })).be.true();
		});

		it('should sign the created time it sends when signing crosses a second boundary', async function () {
			clock.setSystemTime(ED25519_FIXTURE_TIME + 900);
			const request = { method: 'POST', headers: {}, body: Buffer.from('{"hello": "world"}') } as unknown as Request;
			const config = { ...testData.ED25519, digestAlgorithm: 'sha256' } as const;
			should(await signAndValidate(request, config, () => clock.tick(200))).be.true();
		});

		it('should not add a Content-Digest for a request without a body', async function () {
			const setHeader = sinon.spy();
			await DigitalSignatureSDK.signMessage(
				{ method: 'GET', headers: {} } as unknown as Request,
				{ setHeader } as unknown as Response,
				testData.ED25519_GET,
			);
			sinon.assert.neverCalledWith(setHeader, 'content-digest');
			sinon.assert.calledWith(
				setHeader,
				'signature-input',
				'sig1=("x-sos-signature-key" "@method" "@path" "@authority");created=1663459378',
			);
		});

		it('should use the JWE from the config instead of generating one', async function () {
			const setHeader = sinon.spy();
			await DigitalSignatureSDK.signMessage(
				{ method: 'POST', headers: {}, body: Buffer.from('{}') } as unknown as Request,
				{ setHeader } as unknown as Response,
				{ ...testData.ED25519_SIGN, digestAlgorithm: 'sha256' },
			);
			sinon.assert.calledWith(setHeader, 'x-sos-signature-key', testData.ED25519_SIGN.jwe);
		});

		it('should fail when the message cannot be signed', async function () {
			await should(
				DigitalSignatureSDK.signMessage(
					{ method: 'GET', headers: {} } as unknown as Request,
					{ setHeader: sinon.spy() } as unknown as Response,
					{ ...testData.ED25519_GET, privateKey: 'not a key' },
				),
			).be.rejected();
		});
	});
});
