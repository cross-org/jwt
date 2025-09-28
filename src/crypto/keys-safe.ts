// cryptokeys-safe.ts
import { exportPEMKey, generateKey, generateKeyPair, importPEMKey } from "./keys.ts";
import { err, ok, type Result } from "../types/result.ts";
import type { JWTError } from "../errors/index.ts";
import type {
    ExportPEMKeyOptions,
    GenerateKeyOptions,
    GenerateKeyPairOptions,
    SupportedKeyAlgorithms,
    SupportedKeyPairAlgorithms,
} from "./keys.ts";

/**
 * Safely generates a cryptographic key and returns a Result type instead of throwing.
 * @param keyStr - The key string to use for key generation.
 * @param optionsOrAlgorithm - The algorithm or options for key generation.
 * @returns A Result containing the generated CryptoKey or an error.
 */
export async function generateKeySafe(
    keyStr: string,
    optionsOrAlgorithm: SupportedKeyAlgorithms | GenerateKeyOptions = "HS256",
): Promise<Result<CryptoKey, JWTError>> {
    try {
        const key = await generateKey(keyStr, optionsOrAlgorithm);
        return ok(key);
    } catch (error) {
        return err(error as JWTError);
    }
}

/**
 * Safely generates a cryptographic key pair and returns a Result type instead of throwing.
 * @param optionsOrAlgorithm - The algorithm or options for key pair generation.
 * @returns A Result containing the generated CryptoKeyPair or an error.
 */
export async function generateKeyPairSafe(
    optionsOrAlgorithm: SupportedKeyPairAlgorithms | GenerateKeyPairOptions = "RS256",
): Promise<Result<CryptoKeyPair, JWTError>> {
    try {
        const keyPair = await generateKeyPair(optionsOrAlgorithm);
        return ok(keyPair);
    } catch (error) {
        return err(error as JWTError);
    }
}

/**
 * Safely exports a cryptographic key to PEM format and returns a Result type instead of throwing.
 * @param key - The CryptoKey to export.
 * @param filePathOrOptions - Optional file path or export options.
 * @returns A Result containing the PEM string or an error.
 */
export async function exportPEMKeySafe(
    key: CryptoKey,
    filePathOrOptions?: string | ExportPEMKeyOptions,
): Promise<Result<string, JWTError>> {
    try {
        const pem = filePathOrOptions
            ? typeof filePathOrOptions === "string"
                ? await exportPEMKey(key, filePathOrOptions)
                : await exportPEMKey(key, filePathOrOptions)
            : await exportPEMKey(key);
        return ok(pem);
    } catch (error) {
        return err(error as JWTError);
    }
}

/**
 * Safely imports a cryptographic key from PEM format and returns a Result type instead of throwing.
 * @param pem - The PEM string to import.
 * @param algorithm - The algorithm for the key pair.
 * @returns A Result containing the imported CryptoKey or an error.
 */
export async function importPEMKeySafe(
    pem: string,
    algorithm: SupportedKeyPairAlgorithms,
): Promise<Result<CryptoKey, JWTError>> {
    try {
        const key = await importPEMKey(pem, algorithm);
        return ok(key);
    } catch (error) {
        return err(error as JWTError);
    }
}
