//ecdsa.ts
import { decodeBase64Url, encodeBase64Url, textEncode } from "../../utils/encoding.ts";

/**
 * Signs data using the ECDSA algorithm with a specified key.
 * Supports the P-256 and P-384 curves.
 *
 * @param {CryptoKey} key - The ECDSA private key to use for signing.
 * @param {string} data - The data to sign.
 * @returns {Promise<string>} A promise resolving to the base64url-encoded ECDSA signature.
 */
export async function signWithECDSA(key: CryptoKey, data: string) {
    const hash = (key.algorithm as EcKeyAlgorithm).namedCurve === "P-256" ? "SHA-256" : "SHA-384";
    const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: hash },
        key,
        textEncode(data) as BufferSource,
    );
    return encodeBase64Url(new Uint8Array(signature));
}

/**
 * Verifies an ECDSA signature using a specified key.
 * Supports the P-256 and P-384 curves.
 *
 * @param {CryptoKey} key - The ECDSA public key to use for verification.
 * @param {string} data -  The original data.
 * @param {string} signature - The base64url-encoded ECDSA signature to verify.
 * @returns {Promise<boolean>} A promise resolving to `true` if the signature is valid, `false` otherwise.
 */
export async function verifyWithECDSA(key: CryptoKey, data: string, signature: string) {
    const hash = (key.algorithm as EcKeyAlgorithm).namedCurve === "P-256" ? "SHA-256" : "SHA-384";
    const isValid = await crypto.subtle.verify(
        { name: "ECDSA", hash: hash },
        key,
        decodeBase64Url(signature),
        textEncode(data) as BufferSource,
    );
    return isValid;
}
