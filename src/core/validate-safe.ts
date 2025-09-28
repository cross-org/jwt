// validate-safe.ts
import { unsafeParseJOSEHeader, unsafeParseJWT, validateJWT } from "./validate.ts";
import { err, ok, type Result } from "../types/result.ts";
import type { JOSEHeader, JWTPayload } from "../types/claims.ts";
import type { JWTOptions } from "../types/options.ts";
import type { JWTError } from "../errors/index.ts";

export async function validateJWTSafe(
    jwt: string,
    key: CryptoKey | string | false,
    options?: JWTOptions,
): Promise<Result<JWTPayload, JWTError>> {
    try {
        let payload: JWTPayload;
        if (key === false) {
            payload = await validateJWT(jwt, false, options);
        } else if (typeof key === "string") {
            payload = await validateJWT(jwt, key, options);
        } else {
            payload = await validateJWT(jwt, key, options);
        }
        return ok(payload);
    } catch (error) {
        return err(error as JWTError);
    }
}

export function unsafeParseJWTSafe(jwt: string): Result<JWTPayload, JWTError> {
    try {
        const payload = unsafeParseJWT(jwt);
        return ok(payload);
    } catch (error) {
        return err(error as JWTError);
    }
}

export function unsafeParseJOSEHeaderSafe(jwt: string): Result<JOSEHeader, JWTError> {
    try {
        const header = unsafeParseJOSEHeader(jwt);
        return ok(header);
    } catch (error) {
        return err(error as JWTError);
    }
}
