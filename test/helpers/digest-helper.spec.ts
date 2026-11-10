import should from 'should';
import { generateDigestHeader, validateDigestHeader } from '../../src/helpers/digest-helper';

const BODY = Buffer.from('{"hello": "world"}');

describe('helpers/digest-helper', function () {
	describe('generateDigestHeader', function () {
		it('should match the RFC 9530 sha-256 example (Figure 12)', function () {
			should(generateDigestHeader(Buffer.from('{"hello": "world"}\n'), 'sha256')).equal(
				'sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:',
			);
		});

		it('should match the RFC 9421 test-request sha-512 digest', function () {
			should(generateDigestHeader(BODY, 'sha512')).equal(
				'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:',
			);
		});

		it('should generate an md5 digest', function () {
			should(generateDigestHeader(BODY, 'md5')).equal('md5=:Sd/dVLAcvNLSq16eXua5uQ==:');
		});

		it('should return an empty value without a payload', function () {
			should(generateDigestHeader(undefined as unknown as Buffer, 'sha256')).equal('');
		});

		it('should reject an unknown algorithm', function () {
			should(() => generateDigestHeader(BODY, 'sha1' as 'sha256')).throw('Invalid cipher sha1');
		});
	});

	describe('validateDigestHeader', function () {
		it('should accept a digest of the body', function () {
			should(() =>
				validateDigestHeader('sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:', BODY),
			).not.throw();
			should(() => validateDigestHeader('sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:', BODY)).not.throw();
		});

		it('should reject a digest of a different body', function () {
			should(() => validateDigestHeader('sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:', Buffer.from('{"hello": "World"}'))).throw(
				/^Content-Digest value is invalid/,
			);
		});

		it('should reject a missing header', function () {
			should(() => validateDigestHeader('', BODY)).throw('Content-Digest header missing');
		});

		it('should reject a malformed header', function () {
			should(() => validateDigestHeader('sha-256 X48E9q', BODY)).throw('Content-digest header invalid');
		});

		it('should reject an unknown algorithm', function () {
			should(() => validateDigestHeader('sha-1=:abc=:', BODY)).throw('Invalid cipher sha-1');
		});
	});
});
