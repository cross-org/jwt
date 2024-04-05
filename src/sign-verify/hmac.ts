//hmac.ts
import { decodeBase64Url, encodeBase64Url, textEncode } from "../encoding.ts";

/**
 * Signs data using an HMAC key.
 *
 * @param {CryptoKey} key - The HMAC key.
 * @param {string} data -  The data to be signed.
 * @returns {string} The base64url-encoded signature.
 */
export async function signWithHMAC(key: CryptoKey, data: string) {
    const signature = encodeBase64Url(
        new Uint8Array(
            await crypto.subtle.sign(
                { name: "HMAC" },
                key,
                textEncode(data),
            ),
        ),
    );
    return signature;
}

/**
 * Verifies a signature using an HMAC key.
 *
 * @param {CryptoKey} key - The HMAC key.
 * @param {string} data - The original data.
 * @param {string} signature - The base64url-encoded signature to verify.
 * @returns {Promise<boolean>} A promise resolving to `true` if the signature is valid, `false` otherwise.
 */
export async function verifyWithHMAC(
    key: CryptoKey,
    data: string,
    signature: string,
) {
    const isValid = await crypto.subtle.verify(
        { name: "HMAC" },
        key,
        decodeBase64Url(signature),
        textEncode(data),
    );
    return isValid;
}
