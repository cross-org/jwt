//ecdsa.ts
import { decodeBase64Url, encodeBase64Url, textEncode } from "../../utils/encoding.ts";
import type { JWTOptions } from "../../types/options.ts";

/**
 * Signs data using the RSA-PSS algorithm with a specified key.
 *
 * @param {CryptoKey} key - The RSA private key to use for signing.
 * @param {string} data - The data to sign.
 * @param {JWTOptions} [options] - Options for customizing the RSA-PSS signature (optional).
 * @param {number} [options.saltLength=32] - The length of the salt to use in the RSA-PSS signature.
 * @returns {Promise<string>} A promise resolving to the base64url-encoded RSA-PSS signature.
 */
export async function signWithRSAPSS(key: CryptoKey, data: string, options?: JWTOptions) {
    const algorithm = {
        name: key.algorithm.name,
        saltLength: options?.saltLength || 32,
    };
    const signature = await crypto.subtle.sign(
        algorithm,
        key,
        textEncode(data) as BufferSource,
    );
    return encodeBase64Url(new Uint8Array(signature));
}

/**
 * Verifies an RSA-PSS signature using a specified key.
 *
 * @param {CryptoKey} key - The RSA public key to use for verification.
 * @param {string} data - The original data.
 * @param {string} signature - The base64url-encoded RSA-PSS signature to verify.
 * @param {JWTOptions} [options] - Options for customizing the RSA-PSS verification (optional).
 * @param {number} [options.saltLength=32] - The expected length of the salt used in the RSA-PSS signature.
 * @returns {Promise<boolean>} A promise resolving to `true` if the signature is valid, `false` otherwise.
 */
export async function verifyWithRSAPSS(key: CryptoKey, data: string, signature: string, options?: JWTOptions) {
    const algorithm = {
        name: key.algorithm.name,
        saltLength: options?.saltLength || 32,
    };
    const isValid = await crypto.subtle.verify(
        algorithm,
        key,
        decodeBase64Url(signature),
        textEncode(data) as BufferSource,
    );
    return isValid;
}
