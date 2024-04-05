// jwt.ts
import { signWithRSA, verifyWithRSA } from "./sign-verify/rsa.ts";
import { signWithHMAC, verifyWithHMAC } from "./sign-verify/hmac.ts";
import { signWithECDSA, verifyWithECDSA } from "./sign-verify/ecdsa.ts";
import { signWithRSAPSS, verifyWithRSAPSS } from "./sign-verify/rsapss.ts";
import type { JWTOptions } from "./utils.ts";

/**
 * Represents supported HMAC algorithms.
 */
const AlgorithmHMAC = ["HMAC"];
/**
 * Represents supported RSA algorithms.
 */
const AlgorithmRSA = ["RSASSA-PKCS1-v1_5"];
/**
 * Represents supported ECDSA algorithms.
 */
const AlgorithmECDSA = ["ECDSA"];
/**
 * Represents supported RSA-PSS algorithms.
 */
const AlgorithmRSAPSS = ["RSA-PSS"];

/**
 * Signs data using the specified algorithm and key.
 *
 * @param {CryptoKey} key - The HMAC key, RSA, or ECDSA private key for signing.
 * @param {string} data - The data to sign.
 * @param {JWTOptions} [options] - Options for customizing signing behavior (optional).
 * @returns {Promise<string>} A promise resolving to the base64url-encoded signature.
 * @throws {Error} If an unsupported algorithm is specified.
 */
export async function sign(
    key: CryptoKey,
    data: string,
    options?: JWTOptions,
) {
    let signature: string;
    const algorithm = key.algorithm.name;

    if (AlgorithmHMAC.includes(algorithm)) {
        signature = await signWithHMAC(key, data);
    } else if (AlgorithmRSA.includes(algorithm)) {
        signature = await signWithRSA(key, data);
    } else if (AlgorithmECDSA.includes(algorithm)) {
        signature = await signWithECDSA(key, data);
    } else if (AlgorithmRSAPSS.includes(algorithm)) {
        signature = await signWithRSAPSS(key, data, options);
    } else {
        throw new Error("Unsupported algorithm");
    }
    return signature;
}

/**
 * Verifies a signature using the specified algorithm and key.
 *
 * @param {CryptoKey} key - The HMAC key, RSA, or ECDSA public key for verification.
 * @param {string} data - The original data.
 * @param {string} signature - The base64url-encoded signature to verify.
 * @param {JWTOptions} [options] - Options for customizing verification behavior (optional).
 * @returns {Promise<boolean>} A promise resolving to `true` if the signature is valid, `false` otherwise.
 * @throws {Error} If an unsupported algorithm is specified.
 */
export async function verify(
    key: CryptoKey,
    data: string,
    signature: string,
    options?: JWTOptions,
) {
    let isValid: boolean;
    const algorithm = key.algorithm.name;
    if (AlgorithmHMAC.includes(algorithm)) {
        isValid = await verifyWithHMAC(key, data, signature);
    } else if (AlgorithmRSA.includes(algorithm)) {
        isValid = await verifyWithRSA(key, data, signature);
    } else if (AlgorithmECDSA.includes(algorithm)) {
        isValid = await verifyWithECDSA(key, data, signature);
    } else if (AlgorithmRSAPSS.includes(algorithm)) {
        isValid = await verifyWithRSAPSS(key, data, signature, options);
    } else {
        throw new Error("Unsupported algorithm");
    }
    return isValid;
}
