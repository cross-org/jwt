// mod.ts
export { signJWT } from "./src/sign.ts";
export { unsafeParseJWT, validateJWT } from "./src/validate.ts";
export { exportPEMKey, generateKey, generateKeyPair, importPEMKey } from "./src/cryptokeys.ts";
export type {
    GenerateKeyOptions,
    GenerateKeyPairOptions,
    SupportedKeyAlgorithms,
    SupportedKeyPairAlgorithms,
} from "./src/cryptokeys.ts";
export type { JWTOptions } from "./src/options.ts";
export type { JWTPayload } from "./src/standardclaims.ts";

//Aliases
export { signJWT as createJWT } from "./src/sign.ts";
export { validateJWT as verifyJWT } from "./src/validate.ts";
