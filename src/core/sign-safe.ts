// sign-safe.ts
import { signJWT } from "./sign.ts";
import { err, ok, type Result } from "../types/result.ts";
import type { JWTPayload } from "../types/claims.ts";
import type { JWTOptions } from "../types/options.ts";
import type { JWTError } from "../errors/index.ts";

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
