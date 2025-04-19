import { SignatureComponents } from "./SignatureComponents";
export interface Config {
    digestAlgorithm: string;
    jwe: string;
    jwtExpiration: number;
    jweHeaderParams: object;
    jwtPayload: object;
    masterKey: string;
    privateKey: string;
    publicKey: string;
    signatureComponents: SignatureComponents;
    signatureParams: Array<string>;
    /** The name of the HTTP header used to carry the signature key (JWE). */
    signatureKeyHeader: string;
}
