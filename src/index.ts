import { constants } from './constants.js';
import { Request, Response } from 'express';
import { generateDigestHeader, validateDigestHeader } from './helpers/digest-helper.js';
import { needsContentDigestValidation } from './helpers/common.js';
import {
	generateSignature,
	generateSignatureInput,
	generateSignatureKey,
	validateSignatureHeader,
	getSignatureKeyHeader,
} from './helpers/signature-helper.js';
import type { Config } from './types/Config.js';

/**
 * Generate signature headers and add it to the response.
 *
 * @param {Request} request The request object.
 * @param {Response} response The response object
 * @param {Config} config The input config.
 */
async function signMessage(request: Request, response: Response, config: Config): Promise<void> {
	try {
		const generatedHeaders: any = {};
		const signatureKeyHeader = getSignatureKeyHeader(config); // Get the header name

		if (needsContentDigestValidation(request.body)) {
			const contentDigest = generateDigestHeader(request.body, config.digestAlgorithm);

			response.setHeader(constants.HEADERS.CONTENT_DIGEST, contentDigest);
			generatedHeaders[constants.HEADERS.CONTENT_DIGEST] = contentDigest;
		}

		const signatureInput = generateSignatureInput(generatedHeaders, config);
		response.setHeader(constants.HEADERS.SIGNATURE_INPUT, signatureInput);
		generatedHeaders[constants.HEADERS.SIGNATURE_INPUT] = signatureInput;

		// If JWE is not provided in the config, we generate it.
		let signatureKey: string = config.jwe;
		if (!signatureKey) {
			signatureKey = await generateSignatureKey(config);
		}

		response.setHeader(signatureKeyHeader, signatureKey); // Use the dynamic header name
		generatedHeaders[signatureKeyHeader] = signatureKey; // Use the dynamic header name

		const signature = generateSignature(generatedHeaders, config);
		response.setHeader(constants.HEADERS.SIGNATURE, signature);
	} catch (e) {
		throw new Error(String(e), { cause: e });
	}
}

/**
 * Verifies the signature header for the given request
 *
 * @param {Request} request The request object.
 * @param {Config} config The input config.
 * @returns Promise<boolean> True upon successful signature validation.
 * */
async function validateSignature(request: Request, config: Config): Promise<boolean> {
	let response: boolean;

	try {
		//Validate
		if (!request?.headers[constants.HEADERS.SIGNATURE]) {
			throw new Error('Signature header is missing');
		}

		// Validate digest header, if needed.
		if (needsContentDigestValidation(request.body)) {
			const header = request.headers[constants.HEADERS.CONTENT_DIGEST] as string;
			validateDigestHeader(header, request.body);
		}

		// Verify signature
		const isSignatureValid: boolean = await validateSignatureHeader(request.headers, config);

		response = isSignatureValid;
	} catch (e) {
		console.error(e);
		response = false;
	}

	return response;
}

export {
	generateDigestHeader,
	generateSignature,
	generateSignatureInput,
	generateSignatureKey,
	signMessage,
	validateDigestHeader,
	validateSignature,
	validateSignatureHeader,
};
export type { Config };
