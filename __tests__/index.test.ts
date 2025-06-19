"use strict";

import { Response, Request } from "express";
import { jwtDecrypt } from "jose";
import { constants } from "../src/constants";
import { readKey } from "../src/helpers/common";
import * as DigitalSignatureSDK from "../src/index";

const testData = require("./test.json");

describe("test Signature SDK", () => {
  beforeAll(() => {
    Date.now = jest.fn(() => 1663459378000);
  });

  describe("Content-Digest", () => {
    test("should be able to generate for SHA256 cipher", () => {
      const request: string = '{"hello": "world"}';
      const requestBuffer: Buffer = Buffer.from(request);
      const expected: string =
        "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:";

      const actual = DigitalSignatureSDK.generateDigestHeader(
        requestBuffer,
        constants.SHA_256,
      );

      expect(actual).toBe(expected);
    });

    test("should be able to generate for SHA512 cipher", () => {
      const request: string = '{"hello": "world"}';
      const requestBuffer: Buffer = Buffer.from(request);
      const expected: string =
        "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:";

      const actual = DigitalSignatureSDK.generateDigestHeader(
        requestBuffer,
        constants.SHA_512,
      );

      expect(actual).toBe(expected);
    });

    test("should be able to generate for MD5 cipher", () => {
      const request: string = '{"hello": "world"}';
      const requestBuffer: Buffer = Buffer.from(request);
      const expected: string = `md5=:Sd/dVLAcvNLSq16eXua5uQ==:`;

      const actual = DigitalSignatureSDK.generateDigestHeader(
        requestBuffer,
        constants.MD5,
      );

      expect(actual).toBe(expected);
    });
  });

  const testCases = [
    {
      digestAlgorithm: "sha256",
      digestAlgo: "sha-256",
      testDigest: "X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=",
      expectedSignature:
        "dzURGVP+qnm4HSWpkJY7xbYUCulHp4yD724NI12CJtUDcp6z3z2YRKvsbH/ypw1u/e4DRE39OPhlzCn0TCWuAg==",
    },
    {
      digestAlgorithm: "md5",
      digestAlgo: "md5",
      testDigest: "Sd/dVLAcvNLSq16eXua5uQ==",
      expectedSignature:
        "SQLay/Qy9QqiExbSY9Qtjj37H6T7hlf+Xf9Q8oIk0z+sDYCnQwed8mB9uKq1AXDkJd3AJhtjq6l9HO2ZvgqGAA==",
    },
  ];

  testCases.forEach(
    ({ digestAlgorithm, digestAlgo, testDigest, expectedSignature }) =>
      describe(`ED25519 - ${digestAlgorithm}`, () => {
        test("should be able to generate 'signature-input' header when request has payload", () => {
          const config: DigitalSignatureSDK.Config = testData.ED25519;
          const expected: string = `sig1=("content-digest" "x-sos-signature-key" "@method" "@path" "@authority");created=1663459378`;

          const actual = DigitalSignatureSDK.generateSignatureInput(
            { "content-digest": "test" },
            config,
          );

          expect(actual).toBe(expected);
        });

        test("should be able to generate 'signature-input' header when request has no payload", () => {
          const config: DigitalSignatureSDK.Config = testData.ED25519_GET;
          const expected: string = `sig1=("x-sos-signature-key" "@method" "@path" "@authority");created=1663459378`;

          const actual = DigitalSignatureSDK.generateSignatureInput(
            { "content-digest": "test" },
            config,
          );

          expect(actual).toBe(expected);
        });

        test("should be able to generate 'Signature' header", () => {
          const config: DigitalSignatureSDK.Config = testData.ED25519;
          const expected = "sig1=:" + expectedSignature + ":";

          const actual = DigitalSignatureSDK.generateSignature(
            {
              "content-digest": digestAlgo + "=:" + testDigest + ":",
              "signature-input":
                'sig1=("content-digest" "x-sos-signature-key" "@method" "@path" "@authority");created=1663459378',
              "x-sos-signature-key":
                "eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiemlwIjoiREVGIiwiaXYiOiJvSzFwdXJNVHQtci14VUwzIiwidGFnIjoiTjB4WjI4ZklZckFmYkd5UWFrTnpjZyJ9.AYdKU7ObIc7Z764OrlKpwUViK8Rphxl0xMP9v2_o9mI.1DbZiSQNRK6pLeIw.Yzp3IDV8RM_h_lMAnwGpMA4DXbaDdmqAh-65kO9xyDgzHD6s0kY3p-yO6oPR9kEcAbjGXIULeQKWVYzbfHKwXTY09Npj_mNuO5yxgZtWnL55uIgP2HL1So2dKkZRK0eyPa6DEXJT71lPtwZtpIGyq9R5h6s3kGMbqA.m4t_MX4VnlXJGx1X_zZ-KQ",
            },
            config,
          );

          expect(actual).toBe(expected);
        });

        test("should be able to generate 'Signature' header with given JWE", () => {
          const config: DigitalSignatureSDK.Config = testData.ED25519_SIGN;
          const expected = "sig1=:" + expectedSignature + ":";

          const actual = DigitalSignatureSDK.generateSignature(
            {
              "content-digest": digestAlgo + "=:" + testDigest + ":",
              "signature-input":
                'sig1=("content-digest" "x-sos-signature-key" "@method" "@path" "@authority");created=1663459378',
              "x-sos-signature-key":
                "eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiemlwIjoiREVGIiwiaXYiOiJvSzFwdXJNVHQtci14VUwzIiwidGFnIjoiTjB4WjI4ZklZckFmYkd5UWFrTnpjZyJ9.AYdKU7ObIc7Z764OrlKpwUViK8Rphxl0xMP9v2_o9mI.1DbZiSQNRK6pLeIw.Yzp3IDV8RM_h_lMAnwGpMA4DXbaDdmqAh-65kO9xyDgzHD6s0kY3p-yO6oPR9kEcAbjGXIULeQKWVYzbfHKwXTY09Npj_mNuO5yxgZtWnL55uIgP2HL1So2dKkZRK0eyPa6DEXJT71lPtwZtpIGyq9R5h6s3kGMbqA.m4t_MX4VnlXJGx1X_zZ-KQ",
            },
            config,
          );

          expect(actual).toBe(expected);
        });

        test("should be able to generate 'x-sos-signature-key' header", async () => {
          const actual = await DigitalSignatureSDK.generateSignatureKey(
            testData.ED25519,
          );

          const masterKey: string = readKey(testData.ED25519.masterKey);
          const masterKeyBuffer: Buffer = Buffer.from(
            masterKey,
            constants.BASE64,
          );
          const jwtDecryptResult: any = await jwtDecrypt(
            actual,
            masterKeyBuffer,
          );

          expect(jwtDecryptResult.payload.iat).toBe(1663459378);
          expect(jwtDecryptResult.payload.nbf).toBe(1663459378);
          expect(jwtDecryptResult.payload.pkey).toBe(
            "MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=",
          );
          expect(jwtDecryptResult.protectedHeader.alg).toBe("A256GCMKW");
          expect(jwtDecryptResult.protectedHeader.enc).toBe("A256GCM");
          expect(jwtDecryptResult.protectedHeader.zip).toBe("DEF");
        });

        test("should be able to sign a request", async () => {
          const payload: string = '{"hello": "world"}';
          const payloadBuffer: Buffer = Buffer.from(payload);
          const mockedRequest = {
            method: "POST",
            headers: {
              host: "localhost:8080",
              url: "/test",
            },
            body: payloadBuffer,
          } as unknown as Request;

          const mockedResponse = {
            setHeader: jest.fn(),
          } as unknown as Response;

          await DigitalSignatureSDK.signMessage(mockedRequest, mockedResponse, {
            ...testData.ED25519,
            digestAlgorithm,
          });

          const signatureSpy = jest.spyOn(mockedResponse, "setHeader");
          expect(signatureSpy).toHaveBeenCalledWith(
            "content-digest",
            digestAlgo + "=:" + testDigest + ":",
          );
          expect(signatureSpy).toHaveBeenCalledWith(
            "signature-input",
            'sig1=("content-digest" "x-sos-signature-key" "@method" "@path" "@authority");created=1663459378',
          );
          expect(signatureSpy).toHaveBeenCalledWith(
            "signature",
            expect.any(String),
          );
          expect(signatureSpy).toHaveBeenCalledWith(
            "x-sos-signature-key",
            expect.any(String),
          );
        });

        test("should be able to validate request signature", async () => {
          const payload: string = '{"hello": "world"}';
          const payloadBuffer: Buffer = Buffer.from(payload);
          const request = {
            method: "POST",
            headers: {
              host: "localhost:8080",
              url: "/test",
              "content-type": "application/json",
              "content-digest": digestAlgo + "=:" + testDigest + ":",
              "signature-input":
                'sig1=("content-digest" "x-sos-signature-key" "@method" "@path" "@authority");created=1663459378',
              "x-sos-signature-key":
                "eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiemlwIjoiREVGIiwiaXYiOiJvSzFwdXJNVHQtci14VUwzIiwidGFnIjoiTjB4WjI4ZklZckFmYkd5UWFrTnpjZyJ9.AYdKU7ObIc7Z764OrlKpwUViK8Rphxl0xMP9v2_o9mI.1DbZiSQNRK6pLeIw.Yzp3IDV8RM_h_lMAnwGpMA4DXbaDdmqAh-65kO9xyDgzHD6s0kY3p-yO6oPR9kEcAbjGXIULeQKWVYzbfHKwXTY09Npj_mNuO5yxgZtWnL55uIgP2HL1So2dKkZRK0eyPa6DEXJT71lPtwZtpIGyq9R5h6s3kGMbqA.m4t_MX4VnlXJGx1X_zZ-KQ",
              signature: "sig1=:" + expectedSignature + ":",
            },
            body: payloadBuffer,
          } as unknown as Request;

          const actual: boolean = await DigitalSignatureSDK.validateSignature(
            request,
            { ...testData.ED25519, digestAlgorithm },
          );

          expect(actual).toBeTruthy();
        });

        test("should generate a valid signature", async () => {
          const payload: string = '{"hello": "world"}';
          const payloadBuffer: Buffer = Buffer.from(payload);
          const config: DigitalSignatureSDK.Config = {
            ...testData.ED25519,
            digestAlgorithm,
          };
          const contentDigest = DigitalSignatureSDK.generateDigestHeader(
            payloadBuffer,
            config.digestAlgorithm,
          );
          const signatureInput = DigitalSignatureSDK.generateSignatureInput(
            {
              "content-digest": contentDigest,
            },
            config,
          );
          const signatureKey =
            await DigitalSignatureSDK.generateSignatureKey(config);
          const signature = DigitalSignatureSDK.generateSignature(
            {
              "content-digest": contentDigest,
              "signature-input": signatureInput,
              "x-sos-signature-key": signatureKey,
            },
            config,
          );

          const request = {
            method: "POST",
            headers: {
              host: "localhost:8080",
              url: "/test",
              "content-type": "application/json",
              "content-digest": contentDigest,
              "signature-input": signatureInput,
              "x-sos-signature-key": signatureKey,
              signature: signature,
            },
            body: payloadBuffer,
          } as unknown as Request;

          const actual: boolean = await DigitalSignatureSDK.validateSignature(
            request,
            testData.ED25519,
          );

          expect(actual).toBeTruthy();
        });

        test("should generate a valid signature for GET requests", async () => {
          const config: DigitalSignatureSDK.Config = testData.ED25519_GET;

          const signatureInput = DigitalSignatureSDK.generateSignatureInput(
            {
              "content-digest": "test",
            },
            config,
          );
          const signatureKey =
            await DigitalSignatureSDK.generateSignatureKey(config);
          const signature = DigitalSignatureSDK.generateSignature(
            {
              "signature-input": signatureInput,
              "x-sos-signature-key": signatureKey,
            },
            config,
          );

          const request = {
            method: "GET",
            headers: {
              host: "localhost:8080",
              url: "/test",
              "content-type": "application/json",
              "signature-input": signatureInput,
              "x-sos-signature-key": signatureKey,
              signature: signature,
            },
          } as unknown as Request;

          const actual: boolean = await DigitalSignatureSDK.validateSignature(
            request,
            testData.ED25519_GET,
          );

          expect(actual).toBeTruthy();
        });

        test("should work when keys are provided in the config", async () => {
          const payload: string = '{"hello": "world"}';
          const payloadBuffer: Buffer = Buffer.from(payload);
          const config: DigitalSignatureSDK.Config = {
            ...testData.ED25519_CONFIG_KEYS,
            digestAlgorithm: "sha256",
          };
          const contentDigest = DigitalSignatureSDK.generateDigestHeader(
            payloadBuffer,
            config.digestAlgorithm,
          );
          const signatureInput = DigitalSignatureSDK.generateSignatureInput(
            {
              "content-digest": contentDigest,
            },
            config,
          );
          const signatureKey =
            await DigitalSignatureSDK.generateSignatureKey(config);
          const signature = DigitalSignatureSDK.generateSignature(
            {
              "content-digest": contentDigest,
              "signature-input": signatureInput,
              "x-sos-signature-key": signatureKey,
            },
            config,
          );

          const request = {
            method: "POST",
            headers: {
              host: "localhost:8080",
              url: "/test",
              "content-type": "application/json",
              "content-digest": contentDigest,
              "signature-input": signatureInput,
              "x-sos-signature-key": signatureKey,
              signature: signature,
            },
            body: payloadBuffer,
          } as unknown as Request;

          const actual: boolean = await DigitalSignatureSDK.validateSignature(
            request,
            testData.ED25519_CONFIG_KEYS,
          );

          expect(actual).toBeTruthy();
        });
      }),
  );

  describe("RSA", () => {
    test("should be able to validate request signature", async () => {
      const payload: string = '{"hello": "world"}';
      const payloadBuffer: Buffer = Buffer.from(payload);
      const request = {
        method: "POST",
        headers: {
          host: "localhost:8080",
          url: "/test",
          "content-type": "application/json",
          "content-digest":
            "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
          "signature-input":
            'sig1=("content-digest" "x-sos-signature-key" "@method" "@path" "@authority");created=1664063650',
          "x-sos-signature-key":
            "eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiemlwIjoiREVGIiwiaXYiOiIwUVRybDVMOWQwdE9BMXhRIiwidGFnIjoiei1mOEJWUjB4TW5KSGtvNE9CYVNkQSJ9.NypbYr7pgnS_mYUwCodu-pXqdFSlojCuwGO0EoWLthg.WuMvyt-cyYBdKB_Z.-4tx5mS8orriIwTGE7dURY80lEo2GchrTlyX3OcN70dbd9WAlJHMP6eyUuDtr5wlk2xLjCQfC-rsuGbWCtaFkM2uuSPNds1DGjHA8-boO_IccyxFMYL_kOKPuFFoqML3q3PDgvUzdS9z96JLyalEwY6wotzAye7suuhl0TS9gOEatCwnKi9Cpq7XJMX9Fh5vuw1oiic_yYqIQI540LnjCq9i-nxEzZ4LExH2Mp4TQaCd4_uZkCjfr0iUuk2OoFbNvhxo2bwFbL4uStpMs1cBRx51O9-CLemzsULGl6U5-YeY2Lf7qBPLqYYHb3ih9pgfEcOVUaX7xZEl8_vp_nqcuu-2mpkcmjKqE7xTdbXzhGGvdlrP5OJudkSxT_fk9eisjI-Kyn2mInLcsOG5xQxNVktkwTLnyPSIQqWuJ87mfwnLh8vkeiOy7SQArBunl133S28SGG_O2rudumvIvqA0b-nuOTU-BA2kEa6ADg5X2wq8rg.AT1DhPD8FGYgT-uScKj9QQ",
          signature:
            "sig1=:TDZuPWqYCy/nMXTVMwahE8bqW5F7Fqv/oXBbM4+/mdw7jZe8I2ddDWSHCh7FFrxbTey/j4MkyptyNds6Gnxzqz3IanzZF/bamk8iZFK/QiMxZJERUaUt5RNru7fVddmpf+idLye+GCc0btgco3efqVQ16kvnwz2jpWYORGMTtcwKhSp9ysIsoaw3ql8O9FzGIMprAzO9lRyoCiPAN3N+GMt9fxdgQEWsF+zBOwXg9aC8Su4nhXOJ+Dnnbwa1xEZqYFq/vDk51y/pWkZ7o71HDjcWmGTe0JtcxgTWV2UEDo7YhTfPARi7WqVz/41XeEV/0MHKedvlzqDgdNQAeIBLKA==:",
        },
        body: payloadBuffer,
      } as unknown as Request;

      const actual: boolean = await DigitalSignatureSDK.validateSignature(
        request,
        testData.RSA,
      );

      expect(actual).toBeTruthy();
    });

    test("should generate a valid signature", async () => {
      const payload: string = '{"hello": "world"}';
      const payloadBuffer: Buffer = Buffer.from(payload);
      const config: DigitalSignatureSDK.Config = {
        ...testData.RSA,
        digestAlgorithm: "sha256",
      };
      const contentDigest = DigitalSignatureSDK.generateDigestHeader(
        payloadBuffer,
        config.digestAlgorithm,
      );
      const signatureInput = DigitalSignatureSDK.generateSignatureInput(
        {
          "content-digest": contentDigest,
        },
        config,
      );
      const signatureKey =
        await DigitalSignatureSDK.generateSignatureKey(config);
      const signature = DigitalSignatureSDK.generateSignature(
        {
          "content-digest": contentDigest,
          "signature-input": signatureInput,
          "x-sos-signature-key": signatureKey,
        },
        config,
      );

      const request = {
        method: "POST",
        headers: {
          host: "localhost:8080",
          url: "/test",
          "content-type": "application/json",
          "content-digest": contentDigest,
          "signature-input": signatureInput,
          "x-sos-signature-key": signatureKey,
          signature: signature,
        },
        body: payloadBuffer,
      } as unknown as Request;

      const actual: boolean = await DigitalSignatureSDK.validateSignature(
        request,
        config,
      );
    });

    test("should generate a valid signature for GET requests", async () => {
      const config: DigitalSignatureSDK.Config = testData.RSA_GET;

      const signatureInput = DigitalSignatureSDK.generateSignatureInput(
        {},
        config,
      );
      const signatureKey =
        await DigitalSignatureSDK.generateSignatureKey(config);
      const signature = DigitalSignatureSDK.generateSignature(
        {
          "signature-input": signatureInput,
          "x-sos-signature-key": signatureKey,
        },
        config,
      );

      const request = {
        method: "GET",
        headers: {
          host: "localhost:8080",
          url: "/test",
          "content-type": "application/json",
          "signature-input": signatureInput,
          "x-sos-signature-key": signatureKey,
          signature: signature,
        },
      } as unknown as Request;

      const actual: boolean = await DigitalSignatureSDK.validateSignature(
        request,
        config,
      );
    });
  });
});
