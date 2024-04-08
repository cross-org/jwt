// mod.ts
import { simpleMerge } from "@cross/deepmerge";
import {
    JWTAlgorithmMismatchError,
    JWTRequiredClaimMissingError,
    JWTUnsupportedAlgorithmError,
    JWTValidationError,
} from "./error.ts";
import { detectAlgorithm } from "./utils.ts";
import { algorithmMapping, defaultOptions } from "./options.ts";
import type { JWTOptions } from "./options.ts";
import { encodeBase64Url, textEncode } from "./encoding.ts";
import { generateKey } from "./cryptokeys.ts";

import { signWithRSA } from "./sign-verify/rsa.ts";
import { signWithHMAC } from "./sign-verify/hmac.ts";
import { signWithECDSA } from "./sign-verify/ecdsa.ts";
import { signWithRSAPSS } from "./sign-verify/rsapss.ts";

import type { JWTPayload } from "./standardclaims.ts";

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
 * Creates a JWT with given payload, without key security.
 * See: https://datatracker.ietf.org/doc/html/rfc7519#section-6
 *
 * @param {JWTPayload} payload - The payload to be included in the JWT payload.
 * @param {false} key -  False indicates an unsecured jwt.
 * @param {JWTOptions} options - Options to customize JWT creation behavior.
 * @returns {Promise<string>} A promise resolving to the encoded JWT string.
 */
export async function signJWT(payload: JWTPayload, key: false, options?: JWTOptions): Promise<string>;

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
    key: CryptoKey | string | false,
    options?: JWTOptions,
): Promise<string> {
    options = simpleMerge(defaultOptions, options);
    let algorithm: string | null;
    if (key === false || (typeof key === "string" && key === "none")) {
        options!.algorithm = "none";
        algorithm = "none";
    } else {
        key = (typeof key === "string") ? await generateKey(key) : key;
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
    }
    if (options?.setIat && !payload.iat) {
        payload.iat = Math.floor(Date.now() / 1000);
    }

    if (options?.validateExp) {
        if (payload.exp) {
            const currentTimestamp = Math.floor(Date.now() / 1000);
            if (currentTimestamp >= payload.exp) {
                throw new JWTValidationError("JWT 'exp' claim cannot be in the past.");
            }
        } else {
            throw new JWTRequiredClaimMissingError("exp");
        }
    }

    if (options?.validateNbf) {
        if (payload.nbf) {
            const currentTimestamp = Math.floor(Date.now() / 1000);
            if (currentTimestamp > payload.nbf) {
                throw new JWTValidationError("JWT 'nbf' claim cannot be in the past.");
            }
        } else {
            throw new JWTRequiredClaimMissingError("nbf");
        }
    }

    const header = { alg: algorithm, typ: "JWT" };
    const encodedHeader = encodeBase64Url(textEncode(JSON.stringify(header)));
    const encodedPayload = encodeBase64Url(textEncode(JSON.stringify(payload)));

    const signature = algorithm === "none"
        ? ""
        : await sign(key as CryptoKey, `${encodedHeader}.${encodedPayload}`, options);

    return `${encodedHeader}.${encodedPayload}.${signature}`;
}

/**
 * Signs data using the specified algorithm and key.
 *
 * @param {CryptoKey} key - The HMAC key, RSA, or ECDSA private key for signing.
 * @param {string} data - The data to sign.
 * @param {JWTOptions} [options] - Options for customizing signing behavior (optional).
 * @returns {Promise<string>} A promise resolving to the base64url-encoded signature.
 * @throws {Error} If an unsupported algorithm is specified.
 */
export async function sign(key: CryptoKey, data: string, options?: JWTOptions) {
    const algorithm = key.algorithm.name;

    switch (algorithm) {
        case "HMAC":
            return await signWithHMAC(key, data);
        case "RSASSA-PKCS1-v1_5":
            return await signWithRSA(key, data);
        case "ECDSA":
            return await signWithECDSA(key, data);
        case "RSA-PSS":
            return await signWithRSAPSS(key, data, options);
        default:
            throw new Error("Unsupported algorithm");
    }
}
