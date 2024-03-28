// jwt.ts
import { signWithRSA, verifyWithRSA } from "./signing/rsa.ts";
import type { PrivateKey, PublicKey } from "./signing/rsa.ts";
import { signWithHMAC, verifyWithHMAC } from "./signing/hmac.ts";

/**
 *  Re-exports HMAC key generation, signing, and verification functions from the './algorithms/hmac.ts' module.
 */
export { signWithHMAC, verifyWithHMAC } from "./signing/hmac.ts";

/**
 * Re-exports RSA key generation, signing, and verification functions from the './algorithms/rsa.ts' module.
 */
export { signWithRSA, verifyWithRSA } from "./signing/rsa.ts";

/**
 * Re-exports the PrivateKey and PublicKey interfaces.
 */
export type { PrivateKey, PublicKey };

/**
 * Represents supported HMAC algorithms.
 */
const AlgorithmHMAC = ["HMAC"];
/**
 * Represents supported RSA algorithms.
 */
const AlgorithmRSA = ["RSASSA-PKCS1-v1_5"];

/**
 * Signs data using the specified algorithm and key.
 *
 * @param {string} algorithm - The algorithm to use (e.g., 'HMAC', 'RSASSA-PKCS1-v1_5').
 * @param {CryptoKey | PrivateKey} key -  The HMAC key or RSA private key.
 * @param {string} data - The data to sign.
 * @returns {Promise<string>} A promise resolving to the base64url-encoded signature.
 * @throws {Error} If an unsupported algorithm is specified.
 */
export async function sign(
    algorithm: string,
    key: CryptoKey | PrivateKey,
    data: string,
) {
    let signature: string;
    if (AlgorithmHMAC.includes(algorithm)) {
        signature = await signWithHMAC(key, data);
    } else if (AlgorithmRSA.includes(algorithm)) {
        signature = await signWithRSA(key, data);
    } else {
        throw new Error("Unsupported algorithm");
    }
    return signature;
}

/**
 * Verifies a signature using the specified algorithm and key.
 *
 * @param {string} algorithm - The algorithm to use (e.g., 'HMAC', 'RSASSA-PKCS1-v1_5').
 * @param {CryptoKey | PrivateKey} key -  The HMAC key or RSA public key.
 * @param {string} data - The original data.
 * @param {string} signature - The base64url-encoded signature.
 * @returns {Promise<boolean>} A promise resolving to `true` if the signature is valid, `false` otherwise.
 * @throws {Error} If an unsupported algorithm is specified.
 */
export async function verify(
    algorithm: string,
    key: CryptoKey | PrivateKey,
    data: string,
    signature: string,
) {
    let isValid: boolean;
    if (AlgorithmHMAC.includes(algorithm)) {
        isValid = await verifyWithHMAC(key, data, signature);
    } else if (AlgorithmRSA.includes(algorithm)) {
        isValid = await verifyWithRSA(key, data, signature);
    } else {
        throw new Error("Unsupported algorithm");
    }
    return isValid;
}
