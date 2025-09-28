// cryptokeys-safe.ts
import { exportPEMKey, generateKey, generateKeyPair, importPEMKey } from "./cryptokeys.ts";
import { err, ok, type Result } from "./result.ts";
import type { JWTError } from "./error.ts";
import type {
    ExportPEMKeyOptions,
    GenerateKeyOptions,
    GenerateKeyPairOptions,
    SupportedKeyAlgorithms,
    SupportedKeyPairAlgorithms,
} from "./cryptokeys.ts";

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
