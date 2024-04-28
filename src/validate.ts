// validate.ts
import { simpleMerge } from "@cross/deepmerge";
import {
    JWTAlgorithmMismatchError,
    JWTExpiredError,
    JWTFormatError,
    JWTNotYetValidError,
    JWTParseError,
    JWTRequiredClaimMissingError,
    JWTUnsupportedAlgorithmError,
    JWTValidationError,
} from "./error.ts";
import { detectAlgorithm } from "./utils.ts";
import { algorithmMapping, defaultOptions } from "./options.ts";
import type { JWTOptions } from "./options.ts";
import { decodeBase64Url, textDecode } from "./encoding.ts";
import { generateKey } from "./cryptokeys.ts";
import type { SupportedKeyAlgorithms } from "./cryptokeys.ts";

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

    const jwtParts = validateParts(jwt);

    const { algorithm, key: processedKey } = await processKey(key, options);

    const unsignedData = `${jwtParts[0]}.${jwtParts[1]}`;
    const signature = jwtParts[2];

    if (algorithm === "none") {
        // Skip signature validation for unsecured JWTs
    } else {
        const isValid = await verify(processedKey as CryptoKey, unsignedData, signature, options);
        if (!isValid) {
            throw new JWTValidationError("JWT verification failed.");
        }
    }

    const payload = JSON.parse(textDecode(decodeBase64Url(jwtParts[1])));

    validateClaims(payload, options);

    return payload;
}

function validateParts(jwt: string): string[] {
    const jwtParts = jwt.split(".");
    if (jwtParts.length !== 3) {
        throw new JWTFormatError("Invalid JWT format");
    }

    enum JWTParts {
        Header = 0,
        Payload = 1,
        Signature = 2,
    }

    for (let i = 0; i < jwtParts.length; i++) {
        try {
            switch (i) {
                case JWTParts.Header:
                    decodeBase64Url(jwtParts[i]);
                    break;
                case JWTParts.Payload:
                    decodeBase64Url(jwtParts[i]);
                    break;
            }
        } catch (err) {
            if (err instanceof TypeError) {
                const partName = Object.keys(JWTParts)[i];
                throw new JWTFormatError(`Invalid Base64URL encoding in JWT ${partName}`);
            } else {
                throw err;
            }
        }
    }
    return jwtParts;
}
/**
 * Processes the provided key and options, handling algorithm selection, key generation, and compatibility checks.
 *
 * @param {CryptoKey | string | false} key - The key (or a string to generate one), or 'false' for unsecured JWTs.
 * @param {JWTOptions} [options] - Options for customizing JWT creation.
 * @returns {Promise<{ algorithm: string, key: CryptoKey | false }>} A promise resolving to an object containing the final algorithm and the processed key (which could be 'false' for unsecured JWTs).
 */
async function processKey(
    key: CryptoKey | string | false,
    options?: JWTOptions,
): Promise<{ algorithm: string; key: CryptoKey | false }> {
    let algorithm: string | null;

    if (key === false || (typeof key === "string" && key === "none")) {
        key = false;
        options!.algorithm = "none";
        algorithm = "none";

        return { algorithm, key };
    } else {
        if (typeof key === "string" && options?.algorithm) {
            key = await generateKey(key, options?.algorithm as SupportedKeyAlgorithms);
        } else if (typeof key === "string") {
            key = await generateKey(key);
        }

        const keyAlgorithm = detectAlgorithm(key);
        algorithm = options?.algorithm || keyAlgorithm;

        if (algorithm !== keyAlgorithm) {
            throw new JWTAlgorithmMismatchError(
                `Incompatible algorithm '${algorithm}' for key using '${keyAlgorithm}'. Provide a compatible key or omit the 'algorithm' option.`,
            );
        }

        if (!algorithm || !(algorithm in algorithmMapping)) {
            throw new JWTUnsupportedAlgorithmError("Unsupported key algorithm.");
        }

        return { algorithm, key };
    }
}

/**
 * Validates the 'exp' and 'nbf' claims of a JWT payload (if validation is enabled in options).
 *
 * @param {JWTPayload} payload - The JWT payload to validate.
 * @param {JWTOptions} [options] - Options for JWT creation.
 * @throws {JWTValidationError} If the 'exp' claim expired.
 * @throws {JWTNotYetValidError} If the 'nbf' claim is not yet valid.
 * @throws {JWTRequiredClaimMissingError} If a required claim ('exp' or 'nbf') is missing.
 */
function validateClaims(payload: JWTPayload, options?: JWTOptions): void {
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

/**
 * "unsafely" parse a JWT without cryptokey.
 *
 * @param {string} jwt - The encoded JWT string.
 * @returns {Promise<JWTPayload>} A promise resolving to the decoded JWT payload.
 * @throws {JWTParseError} If the jwt string is not parsable.
 */
export function unsafeParseJWT(jwt: string): Promise<JWTPayload> {
    try {
        const jwtParts = validateParts(jwt);
        const payload = JSON.parse(textDecode(decodeBase64Url(jwtParts[1])));
        return payload;
    } catch (error) {
        throw new JWTParseError(error);
    }
}
