// mod.ts
export { signJWT } from "./src/sign.ts";
export { validateJWT } from "./src/validate.ts";
export { exportKeyFiles, generateKey, generateKeyPair } from "./src/cryptokeys.ts";
export type {
    ExportKeyFilesOptions,
    GenerateKeyOptions,
    GenerateKeyPairOptions,
    SupportedGenerateKeyAlgorithms,
    SupportedGenerateKeyPairAlgorithms,
} from "./src/cryptokeys.ts";
export type { JWTOptions } from "./src/options.ts";
export type { JWTPayload } from "./src/standardclaims.ts";

//Aliases
export { signJWT as createJWT } from "./src/sign.ts";
export { validateJWT as verifyJWT } from "./src/validate.ts";
