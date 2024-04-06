// mod.ts
import { simpleMerge } from "@cross/deepmerge";
import {
    JWTExpiredError,
    JWTFormatError,
    JWTNotYetValidError,
    JWTRequiredClaimMissingError,
    JWTUnsupportedAlgorithmError,
    JWTValidationError,
} from "./src/error.ts";
import { algorithmMapping, detectAlgorithm } from "./src/utils.ts";
import type { JWTOptions, SupportedGenerateKeyAlgorithms, SupportedGenerateKeyPairAlgorithms } from "./src/utils.ts";
import { decodeBase64Url, encodeBase64Url, textDecode, textEncode } from "./src/encoding.ts";
import { sign, verify } from "./src/jwt.ts";
import type { JWTPayload } from "./src/standardclaims.ts";

export type { JWTPayload };
export type { JWTOptions };
export type { SupportedGenerateKeyAlgorithms, SupportedGenerateKeyPairAlgorithms };

/**
 * Options for key generation
 */
export interface GenerateKeyOptions {
    /**
     * The HMAC algorithm to use for key generation. Defaults to 'HS256'.
     */
    algorithm?: SupportedGenerateKeyAlgorithms;

    /**
     * If true, allows generation of keys with lengths shorter than recommended security guidelines.
     * Use with caution, as shorter keys are less secure.
     */
    allowInsecureKeyLengths?: boolean;
}

/**
 * Generates an HMAC key from a provided secret string.
 *
 * @param {string} keyStr - The secret string to use as the key.
 * @param {SupportedGenerateKeyAlgorithms} algorithm - The HMAC algorithm to use (default: "HS256").
 * @returns {Promise<CryptoKey>} A promise resolving to the generated HMAC key.
 * @throws {JWTUnsupportedAlgorithmError} If the provided algorithm is not supported.
 */
export async function generateKey(
    keyStr: string,
    optionsOrAlgorithm: SupportedGenerateKeyAlgorithms | GenerateKeyOptions = "HS256",
): Promise<CryptoKey> {
    let algorithm: SupportedGenerateKeyAlgorithms = "HS256";
    let allowInsecureKeyLengths: boolean = false;

    if (typeof optionsOrAlgorithm === "object") {
        algorithm = optionsOrAlgorithm.algorithm || algorithm;
        allowInsecureKeyLengths = optionsOrAlgorithm.allowInsecureKeyLengths || allowInsecureKeyLengths;
    } else {
        algorithm = optionsOrAlgorithm;
    }

    const encodedKey = textEncode(keyStr);

    if (!algorithm.startsWith("HS") || !(algorithm in algorithmMapping)) {
        throw new JWTUnsupportedAlgorithmError("Unsupported key algorithm");
    }

    const minimumLength = {
        HS256: 32,
        HS384: 48,
        HS512: 64,
    }[algorithm as SupportedGenerateKeyAlgorithms];

    if (!allowInsecureKeyLengths && encodedKey.byteLength < minimumLength) {
        throw new JWTValidationError(
            `JWT Secret String for ${algorithm} should be at least ${minimumLength} bytes long`,
        );
    }

    const algo = algorithmMapping[algorithm!] as HmacKeyGenParams;
    return await crypto.subtle.importKey(
        "raw",
        encodedKey,
        algo,
        false,
        ["sign", "verify"],
    );
}

/**
 * Options for key pair generation.
 */
export interface GenerateKeyPairOptions {
    /**
     * The algorithm to use for key pair generation. Defaults to 'RS256'.
     */
    algorithm?: SupportedGenerateKeyPairAlgorithms;

    /**
     * The desired length of the RSA modulus in bits. Larger values offer greater security,
     * but impact performance. A common default is 2048.
     */
    modulusLength?: number;
}

/**
 * Generates an RSA or ECDSA key pair (public and private key).
 *
 * @param {SupportedGenerateKeyPairAlgorithms} algorithm - The algorithm to use (default: "RS256").
 * @returns {Promise<CryptoKeyPair>} A promise resolving to the generated key pair.
 * @throws {JWTUnsupportedAlgorithmError} If the provided algorithm is not supported.
 */
export async function generateKeyPair(
    optionsOrAlgorithm: SupportedGenerateKeyPairAlgorithms | GenerateKeyPairOptions = "RS256",
): Promise<CryptoKeyPair> {
    let algorithm: SupportedGenerateKeyPairAlgorithms = "RS256";
    let modulusLength: number = 2048;

    if (typeof optionsOrAlgorithm === "object") {
        algorithm = optionsOrAlgorithm.algorithm || algorithm;
        modulusLength = optionsOrAlgorithm.modulusLength || modulusLength;
    } else {
        algorithm = optionsOrAlgorithm;
    }

    if (
        !(algorithm.startsWith("RS") || algorithm.startsWith("ES") || algorithm.startsWith("PS")) ||
        !(algorithm in algorithmMapping)
    ) {
        throw new JWTUnsupportedAlgorithmError("Unsupported key algorithm");
    }

    if (algorithm.startsWith("RS") || algorithm.startsWith("PS")) {
        const algo = algorithmMapping[algorithm!] as RsaHashedKeyGenParams;
        algo.modulusLength = modulusLength;
        algo.publicExponent = new Uint8Array([0x01, 0x00, 0x01]);
        return await crypto.subtle.generateKey(
            algo,
            true,
            ["sign", "verify"],
        );
    } else if (algorithm.startsWith("ES")) {
        const algo = algorithmMapping[algorithm!] as EcKeyGenParams;
        return await crypto.subtle.generateKey(
            algo,
            true,
            ["sign", "verify"],
        );
    } else {
        throw new JWTUnsupportedAlgorithmError("Unsupported key algorithm");
    }
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
export async function signJWT(payload: JWTPayload, key: string, options?: JWTOptions): Promise<string>;
/**
 * Creates a JWT with the given key and payload.
 *
 * @param {JWTPayload} payload - The payload to be included in the JWT payload.
 * @param {CryptoKey} key -  The HMAC key or RSA private key for signing.
 * @param {JWTOptions} options - Options to customize JWT creation behavior.
 * @returns {Promise<string>} A promise resolving to the encoded JWT string.
 */
export async function signJWT(payload: JWTPayload, key: CryptoKey, options?: JWTOptions): Promise<string>;

/**
 * Creates a signed JWT.
 *
 * @param {JWTPayload} payload - The data to include in the JWT.
 * @param {CryptoKey | string} key - The HMAC key, RSA/ECDSA private key, or a string to generate a key from.
 * @param {JWTOptions} [options] - Options to customize JWT creation (optional).
 * @returns {Promise<string>} A promise resolving to the encoded JWT string.
 * @throws {JWTUnsupportedAlgorithmError} If the key algorithm is not supported.
 * @throws {JWTValidationError} If validation is enabled and there are issues with the 'exp' or 'nbf' claims.
 * @throws {JWTRequiredClaimMissingError} If validation is enabled and the 'exp' or 'nbf' claims are missing.
 */
export async function signJWT(
    payload: JWTPayload,
    key: CryptoKey | string,
    options?: JWTOptions,
): Promise<string> {
    options = simpleMerge(defaultOptions, options);

    key = (typeof key === "string") ? await generateKey(key) : key;
    const keyAlgorithm = detectAlgorithm(key);
    if (!keyAlgorithm || !(keyAlgorithm in algorithmMapping)) {
        throw new JWTUnsupportedAlgorithmError("Unsupported key algorithm");
    }

    if (options?.setIat && !payload.iat) {
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

    const header = { alg: key.algorithm.name, typ: "JWT" };
    const encodedHeader = encodeBase64Url(textEncode(JSON.stringify(header)));
    const encodedPayload = encodeBase64Url(textEncode(JSON.stringify(payload)));

    const signature = await sign(
        key,
        `${encodedHeader}.${encodedPayload}`,
        options,
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
 * Validates and parses a JWT, verifying it with the given key.
 *
 * @param {string} jwt - The encoded JWT string.
 * @param {CryptoKey | string} key - The HMAC key, RSA/ECDSA public key, or a string to generate a key from.
 * @param {JWTOptions} [options] - Options to customize JWT validation (optional).
 * @returns {Promise<JWTPayload>} A promise resolving to the decoded JWT payload.
 * @throws {JWTUnsupportedAlgorithmError} If the key algorithm is not supported.
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

    const keyAlgorithm = detectAlgorithm(key);

    if (!keyAlgorithm || !(keyAlgorithm in algorithmMapping)) {
        throw new JWTUnsupportedAlgorithmError("Unsupported key algorithm");
    }

    const unsignedData = `${jwtParts[0]}.${jwtParts[1]}`;
    const signature = jwtParts[2];

    const isValid = await verify(key, unsignedData, signature, options);

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
