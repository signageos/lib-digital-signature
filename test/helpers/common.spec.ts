import should from 'should';
import { needsContentDigestValidation, readKey, sanitizeKey } from '../../src/helpers/common';

describe('helpers/common', function () {
	describe('needsContentDigestValidation', function () {
		it('should require a digest for a non-empty body', function () {
			should(needsContentDigestValidation('{}')).be.true();
			should(needsContentDigestValidation(Buffer.from('x') as unknown as string)).be.true();
		});

		it('should not require a digest for a missing or empty body', function () {
			should(needsContentDigestValidation(undefined as unknown as string)).be.false();
			should(needsContentDigestValidation(null as unknown as string)).be.false();
			should(needsContentDigestValidation('')).be.false();
			should(needsContentDigestValidation(Buffer.alloc(0) as unknown as string)).be.false();
		});
	});

	describe('readKey', function () {
		it('should read the key from a file path', function () {
			should(readKey('./examples/keys/ed25519/publickey.pem')).startWith('-----BEGIN PUBLIC KEY-----');
		});

		it('should return a value that is not a file path as is', function () {
			should(readKey('uSA8lSm4fWRrDs8JvjS/Y6D5Ohp3mIKC4AhN/nBaGxs=')).equal('uSA8lSm4fWRrDs8JvjS/Y6D5Ohp3mIKC4AhN/nBaGxs=');
		});
	});

	describe('sanitizeKey', function () {
		it('should trim the key and drop line breaks', function () {
			should(sanitizeKey('  -----BEGIN-----\r\nabc\ndef\n-----END-----\n ')).equal('-----BEGIN-----abcdef-----END-----');
		});
	});
});
