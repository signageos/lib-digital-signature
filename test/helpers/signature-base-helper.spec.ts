import should from 'should';
import sinon from 'sinon';
import { calculateBase, generateBase, getUnixTimestamp } from '../../src/helpers/signature-base-helper';
import { generateSignatureInput } from '../../src/helpers/signature-helper';
import { B26, PROXY_RSA } from '../rfc/rfc9421';
import { createComponents, createConfig } from '../support';

describe('helpers/signature-base-helper', function () {
	let clock: sinon.SinonFakeTimers;

	beforeEach(function () {
		clock = sinon.useFakeTimers({ now: 1663459378000, toFake: ['Date'] });
	});

	afterEach(function () {
		clock.restore();
	});

	describe('calculateBase', function () {
		it('should build the RFC 9421 B.2.6 signature base', function () {
			const config = createConfig({ signatureComponents: createComponents(B26.components) });
			should(calculateBase(B26.headers, config)).equal(B26.signatureBase);
		});

		it('should build the RFC 9421 section 4.3 proxy signature base', function () {
			const config = createConfig({ signatureComponents: createComponents(PROXY_RSA.components) });
			should(calculateBase(PROXY_RSA.headers, config)).equal(
				[
					'"@method": POST',
					'"@authority": origin.host.internal.example',
					'"@path": /foo',
					`"content-digest": ${PROXY_RSA.headers['content-digest']}`,
					'"content-type": application/json',
					'"content-length": 18',
					'"forwarded": for=192.0.2.123;host=example.com;proto=https',
					'"@signature-params": ("@method" "@authority" "@path" "content-digest" "content-type" "content-length" "forwarded");created=1618884480;keyid="test-key-rsa";alg="rsa-v1_5-sha256";expires=1618884540',
				].join('\n'),
			);
		});

		it('should cover the remaining derived components', function () {
			const headers = { 'signature-input': 'sig1=("@target-uri" "@scheme" "@request-target");created=1' };
			should(calculateBase(headers, createConfig())).equal(
				[
					'"@target-uri": https://localhost:8080/test',
					'"@scheme": https',
					'"@request-target": post /test',
					'"@signature-params": ("@target-uri" "@scheme" "@request-target");created=1',
				].join('\n'),
			);
		});

		it('should reject a missing Signature-Input header', function () {
			should(() => calculateBase({}, createConfig())).throw('Error calculating base: Signature-Input header missing');
		});

		it('should reject a malformed Signature-Input header', function () {
			should(() => calculateBase({ 'signature-input': 'sig1=("@method")' }, createConfig())).throw(
				/^Error calculating base: Invalid Signature-Input/,
			);
		});

		it('should reject an unknown derived component', function () {
			should(() => calculateBase({ 'signature-input': 'sig1=("@query");created=1' }, createConfig())).throw(
				'Error calculating base: Unknown pseudo header @query',
			);
		});

		it('should reject a covered header the message does not carry', function () {
			should(() => calculateBase({ 'signature-input': 'sig1=("date");created=1' }, createConfig())).throw(
				'Error calculating base: Header date not included in message',
			);
		});
	});

	describe('generateBase', function () {
		it('should build the same base the verifier rebuilds from the generated Signature-Input', function () {
			const config = createConfig({ signatureParams: ['content-digest', 'x-sos-signature-key', '@method', '@path', '@authority'] });
			const headers: Record<string, string> = { 'content-digest': 'sha-256=:abc=:', 'x-sos-signature-key': 'jwe' };
			headers['signature-input'] = generateSignatureInput(headers, config);

			should(generateBase(headers, config)).equal(calculateBase(headers, config));
		});

		it('should cover every derived component', function () {
			const config = createConfig({ signatureParams: ['@method', '@authority', '@target-uri', '@path', '@scheme', '@request-target'] });
			should(generateBase({}, config)).equal(
				[
					'"@method": POST',
					'"@authority": localhost:8080',
					'"@target-uri": https://localhost:8080/test',
					'"@path": /test',
					'"@scheme": https',
					'"@request-target": post /test',
					'"@signature-params": ("@method" "@authority" "@target-uri" "@path" "@scheme" "@request-target");created=1663459378',
				].join('\n'),
			);
		});

		it('should reject an unknown derived component', function () {
			should(() => generateBase({}, createConfig({ signatureParams: ['@query'] }))).throw(
				'Error calculating signature base: Unknown pseudo header @query',
			);
		});

		it('should reject a covered header the message does not carry', function () {
			should(() => generateBase({}, createConfig({ signatureParams: ['date'] }))).throw(
				'Error calculating signature base: Header date not included in message',
			);
		});
	});

	describe('getUnixTimestamp', function () {
		it('should return whole seconds', function () {
			clock.setSystemTime(1663459378999);
			should(getUnixTimestamp()).equal(1663459378);
		});
	});
});
