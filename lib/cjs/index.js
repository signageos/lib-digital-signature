'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateSignatureHeader = exports.validateSignature = exports.validateDigestHeader = exports.signMessage = exports.generateSignatureKey = exports.generateSignatureInput = exports.generateSignature = exports.generateDigestHeader = void 0;
const constants_1 = require("./constants");
const digest_helper_1 = require("./helpers/digest-helper");
Object.defineProperty(exports, "generateDigestHeader", { enumerable: true, get: function () { return digest_helper_1.generateDigestHeader; } });
Object.defineProperty(exports, "validateDigestHeader", { enumerable: true, get: function () { return digest_helper_1.validateDigestHeader; } });
const common_1 = require("./helpers/common");
const signature_helper_1 = require("./helpers/signature-helper");
Object.defineProperty(exports, "generateSignature", { enumerable: true, get: function () { return signature_helper_1.generateSignature; } });
Object.defineProperty(exports, "generateSignatureInput", { enumerable: true, get: function () { return signature_helper_1.generateSignatureInput; } });
Object.defineProperty(exports, "generateSignatureKey", { enumerable: true, get: function () { return signature_helper_1.generateSignatureKey; } });
Object.defineProperty(exports, "validateSignatureHeader", { enumerable: true, get: function () { return signature_helper_1.validateSignatureHeader; } });
/**
 * Generate signature headers and add it to the response.
 *
 * @param {Request} request The request object.
 * @param {Response} response The response object
 * @param {Config} config The input config.
 */
async function signMessage(request, response, config) {
    try {
        const generatedHeaders = {};
        const signatureKeyHeader = (0, signature_helper_1.getSignatureKeyHeader)(config); // Get the header name
        if ((0, common_1.needsContentDigestValidation)(request.body)) {
            const contentDigest = (0, digest_helper_1.generateDigestHeader)(request.body, config.digestAlgorithm);
            response.setHeader(constants_1.constants.HEADERS.CONTENT_DIGEST, contentDigest);
            generatedHeaders[constants_1.constants.HEADERS.CONTENT_DIGEST] = contentDigest;
        }
        const signatureInput = (0, signature_helper_1.generateSignatureInput)(generatedHeaders, config);
        response.setHeader(constants_1.constants.HEADERS.SIGNATURE_INPUT, signatureInput);
        // If JWE is not provided in the config, we generate it.
        let signatureKey = config.jwe;
        if (!signatureKey) {
            signatureKey = await (0, signature_helper_1.generateSignatureKey)(config);
        }
        response.setHeader(signatureKeyHeader, signatureKey); // Use the dynamic header name
        generatedHeaders[signatureKeyHeader] = signatureKey; // Use the dynamic header name
        const signature = (0, signature_helper_1.generateSignature)(generatedHeaders, config);
        response.setHeader(constants_1.constants.HEADERS.SIGNATURE, signature);
    }
    catch (e) {
        throw new Error(e);
    }
}
exports.signMessage = signMessage;
;
/**
 * Verifies the signature header for the given request
 *
 * @param {Request} request The request object.
 * @param {Config} config The input config.
 * @returns Promise<boolean> True upon successful signature validation.
 * */
async function validateSignature(request, config) {
    let response;
    try {
        //Validate
        if (!request || !request.headers[constants_1.constants.HEADERS.SIGNATURE]) {
            throw new Error("Signature header is missing");
        }
        // Validate digest header, if needed.
        if ((0, common_1.needsContentDigestValidation)(request.body)) {
            const header = request.headers[constants_1.constants.HEADERS.CONTENT_DIGEST];
            (0, digest_helper_1.validateDigestHeader)(header, request.body);
        }
        // Verify signature
        const isSignatureValid = await (0, signature_helper_1.validateSignatureHeader)(request.headers, config);
        response = isSignatureValid;
    }
    catch (e) {
        // eslint-disable-next-line no-console
        console.error(e);
        response = e.message;
    }
    return response;
}
exports.validateSignature = validateSignature;
;
