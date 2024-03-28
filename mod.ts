// mod.ts
import { JWTFormatError, JWTValidationError } from "./src/error.ts";
import { decodeBase64Url, encodeBase64Url, textDecode, textEncode } from "./src/encoding.ts";
import { sign, verify } from "./src/jwt.ts";

/**
 * Generates an HMAC key from a provided secret string.
 *
 * @param {string} keyStr - The secret string to use as the key.
 * @returns {Promise<CryptoKey>} A promise resolving to the generated HMAC key.
 * @throws {JWTValidationError} If the secret string is less than 32 bytes long.
 */
export async function generateKey(keyStr: string): Promise<CryptoKey> {
    if (keyStr.length < 32) {
        throw new JWTValidationError(
            "JWT Secret String must be at least 32 bytes long",
        );
    }

    return await crypto.subtle.importKey(
        "raw",
        textEncode(keyStr),
        { name: "HMAC", hash: "SHA-256" }, // Can be adjusted for other HMAC variants
        false,
        ["sign", "verify"],
    );
}

/**
 * Generates an RSA key pair (public and private key).
 *
 * @returns {Promise<CryptoKeyPair>} A promise resolving to the generated RSA key pair.
 */
export async function generateKeyPair(): Promise<CryptoKeyPair> {
    return await crypto.subtle.generateKey(
        {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: "SHA-256",
        },
        true,
        ["sign", "verify"],
    );
}

/**
 * Creates a JWT with the given key and data.
 *
 * @param {CryptoKey} key - The HMAC key or RSA private key for signing.
 * @param {T} data - The data to be included in the JWT payload.
 * @returns {Promise<string>} A promise resolving to the encoded JWT string.
 */
export async function createJWT<T>(
    key: CryptoKey,
    data: T,
): Promise<string> {
    const alg = key.algorithm.name;
    const header = { alg, typ: "JWT" };
    const encodedHeader = encodeBase64Url(textEncode(JSON.stringify(header)));
    const encodedPayload = encodeBase64Url(textEncode(JSON.stringify(data)));

    const signature = await sign(
        alg,
        key,
        `${encodedHeader}.${encodedPayload}`,
    );

    return `${encodedHeader}.${encodedPayload}.${signature}`;
}

/**
 * Parses a JWT, verifies it with the given key, and returns the contained data.
 *
 * @param {CryptoKey} key - The HMAC key or RSA public key for verification.
 * @param {string} jwt - The encoded JWT string.
 * @returns {Promise<Record<string, any>>} A promise resolving to an object representing the decoded JWT payload.
 * @throws {JWTFormatError} If the JWT has an invalid format.
 * @throws {JWTValidationError} If the JWT signature verification fails.
 */
export async function parseJWT(
    key: CryptoKey,
    jwt: string,
    // deno-lint-ignore no-explicit-any
): Promise<Record<string, any>> {
    const jwtParts = jwt.split(".");
    if (jwtParts.length !== 3) {
        throw new JWTFormatError("Invalid JWT format");
    }

    const header = JSON.parse(textDecode(decodeBase64Url(jwtParts[0]))) as { alg: string };
    const unsignedData = `${jwtParts[0]}.${jwtParts[1]}`;
    const signature = jwtParts[2];

    const isValid = await verify(header.alg, key, unsignedData, signature);

    if (!isValid) {
        throw new JWTValidationError("JWT verification failed");
    }
    return JSON.parse(textDecode(decodeBase64Url(jwtParts[1])));
}
