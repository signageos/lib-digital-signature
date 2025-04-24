<a href="https://www.npmjs.com/package/@signageos/digital-signature">
    <img src="https://img.shields.io/npm/v/@signageos/digital-signature.svg" alt="NPM Version"/>
</a>

# Digital Signature SDK

> **Note:** This repository is a fork. The upstream repository can be found at [eBay/digital-signature-nodejs-sdk](https://github.com/eBay/digital-signature-nodejs-sdk).

HTTP message signatures provide a mechanism for end-to-end authenticity and integrity for components of an HTTP message.

This NodeJS SDK is designed to simplify the process of generating digital signature headers and also provides a method to validate the digital signature headers.

## Table of contents

* [Digital Signatures for Public API Calls](#digital-signatures-for-public-api-calls)
* [Features](#features)
* [Usage](#usage)
* [Logging](#logging)
* [License](#license)

## Digital Signatures for Public API Calls

To ensure the authenticity and integrity of HTTP calls there can be added extra layer that sign responses
and clients can verify the signature. This is especially important for system with high security requirements
and potential security breaches can highly impact the system.

This SDK is generic and the signature scheme is compliant with these IETF standards.

* [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html)
* [RFC 9530 Digest Fields](https://www.rfc-editor.org/rfc/rfc9530.html)

## Features

This SDK is intended to generate required message signature headers, as per the above IETF standards, and also provides a way to verfiy signature headers. There is also an example NodeJS service included with the SDK.

This SDK incorporates

* Generation of the following HTTP message signature headers:
  * **Content-Digest**: This header includes a SHA-256 digest over the HTTP payload (as specified in [RFC 9530 Digest Fields](https://www.rfc-editor.org/rfc/rfc9530.html)), if any. It is not required to be sent for APIs that do not include a request payload (e.g. GET requests). `generateDigestHeader` method is used to generate the digest header.
  * **Signature-Input**: This header indicates which headers and pseudo-headers are included, as well as the order in which they are used when calculating the signature. It is created as specified in [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html). `generateSignatureInput` method is used to generate the signature input header.
  * **Signature**: The value of the Signature header is created as described in [Section 3.1, Creating a Signature, of RFC9421](https://www.rfc-editor.org/rfc/rfc9421.html#name-creating-a-signature). It uses the Private Key value generated using OpenSSL (ED25519 or RSA). `generateSignature` method is used to generate the signature header.
  * **${config.signatureKeyHeader}**: This header includes the JWE that is created using the builtin function `generateSignatureKey` i.e. `x-sos-signature-key`
* `signMessage` method to sign the incoming request object
* `validateSignature` method to validate the signature of the incoming request object
* There are individual methods as well to generate and validate the headers:
  * `generateDigestHeader`
  * `generateSignature`
  * `generateSignatureInput`
  * `generateSignatureKey`
  * `validateDigestHeader`
  * `validateSignatureHeader`

## Usage

**Prerequisites**

```
NodeJS: v16 or higher
NPM: v7 or higher
```

### Install

Using npm:

```shell
npm install @signageos/digital-signature
```

Using yarn:

```shell
yarn add @signageos/digital-signature
```

### Configure

In order to run the example application (signing-only) the [example-config.json](./examples/example-config.json) needs to be updated.

```json
{
  "digestAlgorithm": "<Algorithm used for generating content digest>",
  "jwe": "<JWE generated using OpenSSL>",
  "privateKey": "<Private key generated using OpenSSL>",
  "signatureComponents": "<Signature components for generating the base string>",
  "signatureParams": "<List of signature params>"
}

```

For both signing and signature validation, use [example-config-full.json](examples/example-config-full.json). 

```json
{
  "digestAlgorithm": "<Algorithm used for generating content digest>",
  "jweHeaderParams": "<The JWE header params>",
  "jwtExpiration": "<The JWT expiration in years>",
  "jwtPayload": "<The JWT  payload params>",
  "masterKey": "<The symmetric key used for JWE encryption and decryption>",
  "privateKey": "<Private key generated using OpenSSL>",
  "publicKey": "<Public key generated using OpenSSL>",
  "signatureComponents": "<Signature components for generating the base string>",
  "signatureParams": "<List of signature params>"
}

```

### Publish NPM package

```bash
# Update package.json version property to describe your changes
npm publish --access=public
```

### Parameters

| Name | Type | Description |
| :------ | :------ | :------ |
| `digestAlgorithm` | string | The algorithm for generating the Content-Digest header. Supported values are `sha256`, `sha512` and `md5` |
| `jwe` | string | The JWE generated using the builtin function `generateSignatureKey` i.e. `x-sos-signature-key`. Other `jwe*` are not needed when this is provided. |
| `jweHeaderParams` | JSON object | The JWE header params. This is required only if a JWE is not provided in the config. |
| `jwtExpiration` | number | The JWT expiration in years. This is required only if a JWE is not provided in the config. |
| `jwtPayload` | JSON object | The JWT payload params. This is required only if a JWE is not provided in the config. |
| `masterKey` | string | The symmetric key. This is required only if a JWE is not provided in the config. |
| `privateKey` | string | The privateKey generated using OpenSSL (ED25519 or RSA) |
| `publicKey` | string | The publicKey generated using OpenSSL (ED25519 or RSA) |
| `signatureComponents` | JSON object | The signature components that are a part of the `signatureParams`. These are used to generate the base string which is used to generate the signature header|
| `signatureParams` | Array | The list of headers that indicates which headers and pseudo-headers are included, as well as the order in which they are used when calculating the signature|

Note: You can refer to [example.js](examples/example.ts) for an example of how to setup an express server and use the SDK.

### Running the example

Using npm:

```shell
npm start
```

Using yarn:

```shell
yarn start
```

* Signing Configuration Sample (JWE is provided in the config): [example-config.json](examples/example-config.json).
* Full Configuration Sample (generates JWE): [example-config-full.json](examples/example-config-full.json).

### JWE generation

```bash
openssl genpkey -algorithm ED25519 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem
openssl rand -base64 32 > master.key
```

```js
const publicKeyPem = await fs.readFile('public.pem', { encoding: 'utf-8' });
const publicKey = publicKeyPem.replace(/-----BEGIN PUBLIC KEY-----/g, '').replace(/-----END PUBLIC KEY-----/g, '').trim();
const signatureConfig = {
	jweHeaderParams: {
		alg: 'A256GCMKW',
		enc: 'A256GCM',
		zip: 'DEF',
	},
	jwtExpiration: 100, // in years
	jwtPayload: {
		pkey: publicKey,
	},
	masterKey: 'master.key',
	publicKey: 'public.pem',
};
const jwe = await generateSignatureKey(signatureConfig);
console.log('JWE:', jwe);
```

### Note for Production deployment

```
For production, please host with HTTPS enabled.
```

## Logging

Uses standard console logging.

## License
See the [LICENSE](LICENSE) file for license rights.
