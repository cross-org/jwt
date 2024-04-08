// mod.ts
import { simpleMerge } from "@cross/deepmerge";
import {
    JWTExpiredError,
    JWTFormatError,
    JWTNotYetValidError,
    JWTRequiredClaimMissingError,
    JWTUnsupportedAlgorithmError,
    JWTValidationError,
} from "./error.ts";
import { detectAlgorithm } from "./utils.ts";
import { algorithmMapping, defaultOptions } from "./options.ts";
import type { JWTOptions } from "./options.ts";
import { decodeBase64Url, textDecode } from "./encoding.ts";
import { generateKey } from "./cryptokeys.ts";

import { verifyWithRSA } from "./sign-verify/rsa.ts";
import { verifyWithHMAC } from "./sign-verify/hmac.ts";
import { verifyWithECDSA } from "./sign-verify/ecdsa.ts";
import { verifyWithRSAPSS } from "./sign-verify/rsapss.ts";

import type { JWTPayload } from "./standardclaims.ts";

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
 * Validates and parses a JWT and returns the contained payload, no key verification.
 * See: https://datatracker.ietf.org/doc/html/rfc7519#section-6
 *
 * @param {string} jwt - The encoded JWT string.
 * @param {false} key - False indicates an unsecured jwt.
 * @param {JWTOptions} options - Options to customize JWT parsing behavior.
 * @returns {Promise<JWTPayload>} A promise resolving to an object representing the decoded JWT payload.
 */
export async function validateJWT(jwt: string, key: false, options?: JWTOptions): Promise<JWTPayload>;

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
    key: CryptoKey | string | false,
    options?: JWTOptions,
): Promise<JWTPayload> {
    options = simpleMerge(defaultOptions, options);
    let algorithm: string | null;

    const jwtParts = jwt.split(".");
    if (jwtParts.length !== 3) {
        throw new JWTFormatError("Invalid JWT format");
    }

    if (key === false || (typeof key === "string" && key === "none")) {
        options!.algorithm = "none";
        algorithm = "none";
    } else {
        key = (typeof key === "string") ? await generateKey(key) : key;

        algorithm = detectAlgorithm(key);

        if (!algorithm || !(algorithm in algorithmMapping)) {
            throw new JWTUnsupportedAlgorithmError("Unsupported key algorithm.");
        }
    }
    const unsignedData = `${jwtParts[0]}.${jwtParts[1]}`;
    const signature = jwtParts[2];

    if (algorithm === "none") {
        // Skip signature validation for unsecured JWTs
    } else {
        const isValid = await verify(key as CryptoKey, unsignedData, signature, options);
        if (!isValid) {
            throw new JWTValidationError("JWT verification failed.");
        }
    }

    const payload = JSON.parse(textDecode(decodeBase64Url(jwtParts[1])));

    if (options?.validateExp) {
        if (payload.exp) {
            const currentTimestamp = Math.floor(Date.now() / 1000);
            const effectiveExpiry = payload.exp + (options?.clockSkewLeewaySeconds || 0);

            if (currentTimestamp > effectiveExpiry) {
                throw new JWTExpiredError();
            }
        } else {
            throw new JWTRequiredClaimMissingError("exp");
        }
    }

    if (options?.validateNbf) {
        if (payload.nbf) {
            const currentTimestamp = Math.floor(Date.now() / 1000);
            const effectiveNotBefore = payload.nbf - (options?.clockSkewLeewaySeconds || 0);

            if (currentTimestamp < effectiveNotBefore) {
                throw new JWTNotYetValidError();
            }
        } else {
            throw new JWTRequiredClaimMissingError("nbf");
        }
    }

    return payload;
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
export async function verify(key: CryptoKey, data: string, signature: string, options?: JWTOptions) {
    const algorithm = key.algorithm.name;

    switch (algorithm) {
        case "HMAC":
            return await verifyWithHMAC(key, data, signature);
        case "RSASSA-PKCS1-v1_5":
            return await verifyWithRSA(key, data, signature);
        case "ECDSA":
            return await verifyWithECDSA(key, data, signature);
        case "RSA-PSS":
            return await verifyWithRSAPSS(key, data, signature, options);
        default:
            throw new Error("Unsupported algorithm");
    }
}
