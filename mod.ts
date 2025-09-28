// mod.ts

// Main functions (throwing behavior by default)
export { signJWT } from "./src/core/sign.ts";
export { unsafeParseJOSEHeader, unsafeParseJWT, validateJWT } from "./src/core/validate.ts";
export { exportPEMKey, generateKey, generateKeyPair, importPEMKey } from "./src/crypto/keys.ts";

// Result type and utilities
export type { Err, Ok, Result } from "./src/types/result.ts";
export { err, ok, tryCatch, tryCatchSync } from "./src/types/result.ts";

// Error types
export type { JWTError } from "./src/errors/index.ts";
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
} from "./src/errors/index.ts";

// Type exports
export type {
    ExportPEMKeyOptions,
    GenerateKeyOptions,
    GenerateKeyPairOptions,
    SupportedKeyAlgorithms,
    SupportedKeyPairAlgorithms,
} from "./src/crypto/keys.ts";
export type { JWTOptions } from "./src/types/options.ts";
export type { JOSEHeader, JWTPayload } from "./src/types/claims.ts";

//Aliases
export { signJWT as createJWT } from "./src/core/sign.ts";
export { validateJWT as verifyJWT } from "./src/core/validate.ts";

// Safe error handling variants (always return Result types)
export { signJWTSafe } from "./src/core/sign-safe.ts";
export { unsafeParseJOSEHeaderSafe, unsafeParseJWTSafe, validateJWTSafe } from "./src/core/validate-safe.ts";
export { exportPEMKeySafe, generateKeyPairSafe, generateKeySafe, importPEMKeySafe } from "./src/crypto/keys-safe.ts";
