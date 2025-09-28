// mod.ts

// Main functions (throwing behavior by default)
export { signJWT } from "./src/sign.ts";
export { unsafeParseJOSEHeader, unsafeParseJWT, validateJWT } from "./src/validate.ts";
export { exportPEMKey, generateKey, generateKeyPair, importPEMKey } from "./src/cryptokeys.ts";

// Result type and utilities
export type { Err, Ok, Result } from "./src/result.ts";
export { err, ok, tryCatch, tryCatchSync } from "./src/result.ts";

// Error types
export type { JWTError } from "./src/error.ts";
export {
    JWTAlgorithmMismatchError,
    JWTAmbiguousClaimError,
    JWTExpiredError,
    JWTFormatError,
    JWTNotYetValidError,
    JWTParseError,
    JWTRequiredClaimMissingError,
    JWTRequiredOptionMissingError,
    JWTUnsupportedAlgorithmError,
    JWTValidationError,
} from "./src/error.ts";

// Type exports
export type {
    ExportPEMKeyOptions,
    GenerateKeyOptions,
    GenerateKeyPairOptions,
    SupportedKeyAlgorithms,
    SupportedKeyPairAlgorithms,
} from "./src/cryptokeys.ts";
export type { JWTOptions } from "./src/options.ts";
export type { JOSEHeader, JWTPayload } from "./src/standardclaims.ts";

//Aliases
export { signJWT as createJWT } from "./src/sign.ts";
export { validateJWT as verifyJWT } from "./src/validate.ts";

// Safe error handling variants (always return Result types)
export { signJWTSafe } from "./src/sign-safe.ts";
export { unsafeParseJOSEHeaderSafe, unsafeParseJWTSafe, validateJWTSafe } from "./src/validate-safe.ts";
export { exportPEMKeySafe, generateKeyPairSafe, generateKeySafe, importPEMKeySafe } from "./src/cryptokeys-safe.ts";
