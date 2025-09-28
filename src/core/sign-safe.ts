// sign-safe.ts
import { signJWT } from "./sign.ts";
import { err, ok, type Result } from "../types/result.ts";
import type { JWTPayload } from "../types/claims.ts";
import type { JWTOptions } from "../types/options.ts";
import type { JWTError } from "../errors/index.ts";

/**
 * Safely signs a JWT payload and returns a Result type instead of throwing.
 * @param payload - The JWT payload to sign.
 * @param key - The signing key (CryptoKey, string, or false for unsecured).
 * @param options - Optional JWT signing options.
 * @returns A Result containing the signed JWT string or an error.
 */
export async function signJWTSafe(
    payload: JWTPayload,
    key: CryptoKey | string | false,
    options?: JWTOptions,
): Promise<Result<string, JWTError>> {
    try {
        let jwt: string;
        if (key === false) {
            jwt = await signJWT(payload, false, options);
        } else if (typeof key === "string") {
            jwt = await signJWT(payload, key, options);
        } else {
            jwt = await signJWT(payload, key, options);
        }
        return ok(jwt);
    } catch (error) {
        return err(error as JWTError);
    }
}
