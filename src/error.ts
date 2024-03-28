// error.ts

/**
 * Represents an error that occurs during JWT validation due to issues such as
 * invalid algorithms.
 */
export class JWTValidationError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "JWTValidationError";
    }
}

/**
 * Represents an error that occurs due to an incorrectly formatted or
 * structurally invalid JWT.
 */
export class JWTFormatError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "JWTFormatError";
    }
}
