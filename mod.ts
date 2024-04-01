// mod.ts
import { simpleMerge } from "@cross/deepmerge";
import {
    JWTExpiredError,
    JWTFormatError,
    JWTNotYetValidError,
    JWTRequiredClaimMissingError,
    JWTValidationError,
} from "./src/error.ts";
import { decodeBase64Url, encodeBase64Url, textDecode, textEncode } from "./src/encoding.ts";
import { sign, verify } from "./src/jwt.ts";
import type { JWTPayload } from "./src/standardclaims.ts";
export type { JWTPayload } from "./src/standardclaims.ts";

/**
 * Options for customizing the generation of HMAC keys.
 */
export interface KeyOptions {
    /**
     * The hash algorithm to use for the HMAC key.
     * Supported values: "SHA-256", "SHA-384", or "SHA-512".
     */
    hash: "SHA-256" | "SHA-384" | "SHA-512";

    /**
     * If true, allows the generation of keys with lengths considered insecure. Use with caution.
     */
    allowInsecureKeyLengths?: boolean;
}

/**
 * Options for customizing the generation of RSA key pairs.
 */
export interface KeyPairOptions {
    /**
     * The hash algorithm to use for RSA signing and padding operations.
     * Supported values: "SHA-256", "SHA-384", or "SHA-512".
     */
    hash: "SHA-256" | "SHA-384" | "SHA-512";
}

/**
 * Generates an HMAC key from a provided secret string.
 *
 * @param {string} keyStr - The secret string to use as the key.
 * @param {KeyOptions} options - options for controlling key generation
 * @returns {Promise<CryptoKey>} A promise resolving to the generated HMAC key.
 * @throws {JWTValidationError} If the secret string is less than 32 bytes long and insecure lengths are not allowed.
 */
export async function generateKey(keyStr: string, options?: KeyOptions): Promise<CryptoKey> {
    const mergedOptions = simpleMerge({
        hash: "SHA-256",
        allowInsecureKeyLengths: false,
    }, options);
    const encodedKey = textEncode(keyStr);

    if (!mergedOptions?.allowInsecureKeyLengths && encodedKey.byteLength < 32) {
        throw new JWTValidationError("JWT Secret String must be at least 32 bytes long");
    }

    return await crypto.subtle.importKey(
        "raw",
        encodedKey,
        { name: "HMAC", hash: mergedOptions?.hash! },
        false,
        ["sign", "verify"],
    );
}

/**
 * Generates an RSA key pair (public and private key).
 *
 * @param {KeyPairOptions} options - options for controlling key generation
 * @returns {Promise<CryptoKeyPair>} A promise resolving to the generated RSA key pair.
 */
export async function generateKeyPair(options?: KeyPairOptions): Promise<CryptoKeyPair> {
    const mergedOptions = simpleMerge({
        hash: "SHA-256",
    }, options);

    return await crypto.subtle.generateKey(
        {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: mergedOptions?.hash!,
        },
        true,
        ["sign", "verify"],
    );
}

/**
 * Options for customizing JWT creation and parsing behavior.
 */
export interface JWTOptions {
    /**
     * If true, the 'iat' (issued at) claim will not be automatically added to the JWT payload during creation.
     */
    NoIat?: boolean;

    /**
     * If true, the 'exp' (expiration time) claim will be validated during creation and parsing.
     */
    validateExp?: boolean;

    /**
     *  If true, the 'nbf' (not before) claim will be validated during creation and parsing.
     */
    validateNbf?: boolean;

    /**
     * The number of seconds of leeway to allow for clock skew during expiration validation. (Default: 60)
     */
    clockSkewLeewaySeconds?: number;
}

/**
 * A set of default options.
 */
const defaultOptions: JWTOptions = {
    clockSkewLeewaySeconds: 60,
};

/**
 * Creates a JWT with the given key and payload.
 *
 * @param {JWTPayload} payload - The payload to be included in the JWT payload.
 * @param {string} key -  The string to generate an HMAC key from.
 * @param {JWTOptions} options - Options to customize JWT creation behavior.
 * @returns {Promise<string>} A promise resolving to the encoded JWT string.
 */
export async function createJWT(payload: JWTPayload, key: string, options?: JWTOptions): Promise<string>;
/**
 * Creates a JWT with the given key and payload.
 *
 * @param {JWTPayload} payload - The payload to be included in the JWT payload.
 * @param {CryptoKey} key -  The HMAC key or RSA private key for signing.
 * @param {JWTOptions} options - Options to customize JWT creation behavior.
 * @returns {Promise<string>} A promise resolving to the encoded JWT string.
 */
export async function createJWT(payload: JWTPayload, key: CryptoKey, options?: JWTOptions): Promise<string>;

/**
 * Creates a JWT with the given key and payload.
 *
 * @param {JWTPayload} payload - The payload to be included in the JWT payload.
 * @param {CryptoKey | string} key - The HMAC key or RSA private key for signing, or a string to generate a key from.
 * @param {JWTOptions} options - Options to customize JWT creation behavior.
 * @returns {Promise<string>} A promise resolving to the encoded JWT string.
 * @throws {JWTValidationError} If validation is enabled and there are issues with the 'exp' or 'nbf' claims.
 * @throws {JWTRequiredClaimMissingError} If validation is enabled and the 'exp' or 'nbf' claims are missing.
 */
export async function createJWT(
    payload: JWTPayload,
    key: CryptoKey | string,
    options?: JWTOptions,
): Promise<string> {
    options = simpleMerge(defaultOptions, options);

    key = (typeof key === "string") ? await generateKey(key) : key;

    if (!options?.NoIat && !payload.iat) {
        payload.iat = Math.floor(Date.now() / 1000);
    }

    if (options?.validateExp) {
        if (payload.exp) {
            const currentTimestamp = Math.floor(Date.now() / 1000);
            if (payload.exp <= currentTimestamp) {
                throw new JWTValidationError("JWT 'exp' claim cannot be in the past");
            }
        } else {
            throw new JWTRequiredClaimMissingError("exp");
        }
    }

    if (options?.validateNbf) {
        if (payload.nbf) {
            const currentTimestamp = Math.floor(Date.now() / 1000);
            if (currentTimestamp <= payload.nbf) {
                throw new JWTValidationError("JWT 'nbf' claim cannot be in the past");
            }
        } else {
            throw new JWTRequiredClaimMissingError("nbf");
        }
    }

    const alg = key.algorithm.name;
    const header = { alg, typ: "JWT" };
    const encodedHeader = encodeBase64Url(textEncode(JSON.stringify(header)));
    const encodedPayload = encodeBase64Url(textEncode(JSON.stringify(payload)));

    const signature = await sign(
        alg,
        key,
        `${encodedHeader}.${encodedPayload}`,
    );

    return `${encodedHeader}.${encodedPayload}.${signature}`;
}

/**
 * Validates and parses a JWT, verifies it with the given key, and returns the contained payload.
 *
 * @param {string} jwt - The encoded JWT string.
 * @param {string} key - string to generate an HMAC key from.
 * @param {JWTOptions} options - Options to customize JWT parsing behavior.
 * @returns {Promise<JWTPayload>} A promise resolving to an object representing the decoded JWT payload.
 */
export async function validateJWT(jwt: string, key: string, options?: JWTOptions): Promise<JWTPayload>;

/**
 * Validates and parses a JWT, verifies it with the given key, and returns the contained payload.
 *
 * @param {string} jwt - The encoded JWT string.
 * @param {CryptoKey} key - The HMAC key or The RSA public key for verification.
 * @param {JWTOptions} options - Options to customize JWT parsing behavior.
 * @returns {Promise<JWTPayload>} A promise resolving to an object representing the decoded JWT payload.
 */
export async function validateJWT(jwt: string, key: CryptoKey, options?: JWTOptions): Promise<JWTPayload>;

/**
 * Validates and parses a JWT, verifies it with the given key, and returns the contained payload.
 *
 * @param {CryptoKey | string} key - The HMAC key or RSA public key for verification, or a string to generate a key from.
 * @param {string} jwt - The encoded JWT string.
 * @param {JWTOptions} options - Options to customize JWT parsing behavior.
 * @returns {Promise<JWTPayload>} A promise resolving to an object representing the decoded JWT payload.
 * @throws {JWTFormatError} If the JWT has an invalid format.
 * @throws {JWTValidationError} If the JWT signature verification fails.
 * @throws {JWTExpiredError} If the JWT has expired (and expiration validation is enabled).
 * @throws {JWTNotYetValidError} If the JWT is not yet valid based on its 'nbf' claim (and 'nbf' validation is enabled).
 * @throws {JWTRequiredClaimMissingError} If the 'exp' or 'nbf' claims are missing (and validation is enabled).
 */
export async function validateJWT(
    jwt: string,
    key: CryptoKey | string,
    options?: JWTOptions,
): Promise<JWTPayload> {
    options = simpleMerge(defaultOptions, options);

    const jwtParts = jwt.split(".");
    if (jwtParts.length !== 3) {
        throw new JWTFormatError("Invalid JWT format");
    }

    key = (typeof key === "string") ? await generateKey(key) : key;

    const header = JSON.parse(textDecode(decodeBase64Url(jwtParts[0]))) as { alg: string };
    const unsignedData = `${jwtParts[0]}.${jwtParts[1]}`;
    const signature = jwtParts[2];

    const isValid = await verify(header.alg, key, unsignedData, signature);

    if (!isValid) {
        throw new JWTValidationError("JWT verification failed");
    }

    const payload = JSON.parse(textDecode(decodeBase64Url(jwtParts[1])));

    if (options?.validateExp) {
        if (payload.exp) {
            const currentTimestamp = Math.floor(Date.now() / 1000);
            const effectiveExpiry = currentTimestamp - (options?.clockSkewLeewaySeconds || 0);

            if (payload.exp < effectiveExpiry) {
                throw new JWTExpiredError();
            }
        } else {
            throw new JWTRequiredClaimMissingError("exp");
        }
    }

    if (options?.validateNbf) {
        if (payload.nbf) {
            const currentTimestamp = Math.floor(Date.now() / 1000);
            const effectiveNotBefore = currentTimestamp + (options?.clockSkewLeewaySeconds || 0);

            if (payload.nbf > effectiveNotBefore) {
                throw new JWTNotYetValidError();
            }
        } else {
            throw new JWTRequiredClaimMissingError("nbf");
        }
    }

    return payload;
}
