// cryptokeys.ts
import { encodeBase64, textEncode } from "./encoding.ts";
import { JWTUnsupportedAlgorithmError, JWTValidationError } from "./error.ts";
import { algorithmMapping } from "./options.ts";
import { writeFile } from "@cross/fs/io";

/**
 * Represents valid algorithm names for key generation using HMAC.
 */
export type SupportedGenerateKeyAlgorithms = "HS256" | "HS384" | "HS512";

/**
 * Represents valid algorithm names for generating key pairs using RSA, ECDSA and RSA-PSS.
 */
export type SupportedGenerateKeyPairAlgorithms =
    | "RS256"
    | "RS384"
    | "RS512"
    | "ES256"
    | "ES384"
    | "PS256"
    | "PS384"
    | "PS512"
    | "none";

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
 * @param {SupportedGenerateKeyAlgorithms | GenerateKeyOptions} optionsOrAlgorithm - The HMAC algorithm to use or GenerateKeyOptions object (default: "HS256").
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

    /**
     * If true, allows generation of key pairs with modulus length shorter than recommended security guidelines.
     * Use with caution, as shorter lengths are less secure.
     */
    allowInsecureModulusLengths?: boolean;
}

/**
 * Generates an RSA or ECDSA key pair (public and private key).
 *
 * @param {SupportedGenerateKeyPairAlgorithms | GenerateKeyPairOptions} optionsOrAlgorithm - The algorithm to use or GenerateKeyPairOptions object (default: "RS256").
 * @returns {Promise<CryptoKeyPair>} A promise resolving to the generated key pair.
 * @throws {JWTUnsupportedAlgorithmError} If the provided algorithm is not supported.
 */
export async function generateKeyPair(
    optionsOrAlgorithm: SupportedGenerateKeyPairAlgorithms | GenerateKeyPairOptions = "RS256",
): Promise<CryptoKeyPair> {
    let algorithm: SupportedGenerateKeyPairAlgorithms = "RS256";
    const recommendedModulusLength: number = 2048;
    let modulusLength: number = recommendedModulusLength;
    let allowInsecureModulusLengths: boolean = false;

    if (typeof optionsOrAlgorithm === "object") {
        algorithm = optionsOrAlgorithm.algorithm || algorithm;
        modulusLength = optionsOrAlgorithm.modulusLength || modulusLength;
        allowInsecureModulusLengths = optionsOrAlgorithm.allowInsecureModulusLengths || allowInsecureModulusLengths;
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
        if (!allowInsecureModulusLengths && modulusLength < recommendedModulusLength) {
            throw new JWTValidationError(
                `Modulus length should be at least ${recommendedModulusLength}.`,
            );
        }

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
 * Represents the options for the `exportKeyFiles` function.
 */
export interface ExportKeyFilesOptions {
    /**
     * The private key to be exported.
     */
    privateKey: CryptoKey;

    /**
     * The file path where the PEM-formatted private key will be written. No file will be written if undefined.
     */
    privateFile?: string;

    /**
     * The public key to be exported.
     */
    publicKey: CryptoKey;

    /**
     * The file path where the PEM-formatted public key will be written. No file will be written if undefined.
     */
    publicFile?: string;
}

/**
 * Exports a key pair to PEM-formatted files.
 *
 * @param {ExportKeyFilesOptions} options - Options for the key export operation.
 * @returns {Promise<ExportedKeyFiles>} A promise that resolves when the files have been written.
 */
export async function exportKeyFiles(
    options: ExportKeyFilesOptions,
): Promise<{ privateKey: string; publicKey: string }> {
    const { privateKey, publicKey, privateFile, publicFile } = options;

    // todo: implement checks for privateKey, publicKey, privateFile, publicFile

    const privateKeyExport = await window.crypto.subtle.exportKey("pkcs8", privateKey);
    const publicKeyExport = await window.crypto.subtle.exportKey("spki", publicKey);

    const privateKeyPem = formatAsPem("PRIVATE KEY", privateKeyExport);
    const publicKeyPem = formatAsPem("PUBLIC KEY", publicKeyExport);

    if (privateFile) {
        await writeFile(privateFile, privateKeyPem);
    }

    if (publicFile) {
        await writeFile(publicFile, publicKeyPem);
    }

    return { privateKey: privateKeyPem, publicKey: publicKeyPem };
}

/**
 * Formats a key as a PEM (Privacy Enhanced Mail) block.
 *
 * @param {string} header - The header type for the PEM block (e.g., "PUBLIC KEY", "RSA PRIVATE KEY").
 * @param {ArrayBuffer} keyData - An ArrayBuffer containing the binary key data.
 * @returns {string} The formatted PEM string.
 */
function formatAsPem(header: string, keyData: ArrayBuffer) {
    const base64Key = encodeBase64(keyData);
    const lines = base64Key.match(/.{1,64}/g) || [];
    return `-----BEGIN ${header}-----\n${lines.join("\n")}\n-----END ${header}-----`;
}
