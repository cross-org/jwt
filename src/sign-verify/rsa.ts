//rsa.ts
import { decodeBase64Url, encodeBase64Url, textEncode } from "../encoding.ts";

/**
 * Signs data using an RSA private key (RSASSA-PKCS1-v1_5 algorithm).
 *
 * @param {CryptoKey} privateKey - The RSA private key.
 * @param {string} data -  The data to be signed.
 * @returns {string} The base64url-encoded signature.
 */
export async function signWithRSA(privateKey: CryptoKey, data: string) {
    const signature = encodeBase64Url(
        new Uint8Array(
            await crypto.subtle.sign(
                { name: "RSASSA-PKCS1-v1_5" },
                privateKey,
                textEncode(data) as BufferSource,
            ),
        ),
    );
    return signature;
}

/**
 * Verifies a signature using an RSA public key (RSASSA-PKCS1-v1_5 algorithm).
 *
 * @param {CryptoKey} publicKey - The RSA public key.
 * @param {string} data - The original data.
 * @param {string} signature - The base64url-encoded signature to verify.
 * @returns {Promise<boolean>} A promise resolving to `true` if the signature is valid, `false` otherwise.
 */
export async function verifyWithRSA(
    publicKey: CryptoKey,
    data: string,
    signature: string,
) {
    const isValid = await crypto.subtle.verify(
        { name: "RSASSA-PKCS1-v1_5" },
        publicKey,
        decodeBase64Url(signature),
        textEncode(data) as BufferSource,
    );
    return isValid;
}
