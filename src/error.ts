// src/error.ts

/**
 * Represents an error caused by an incorrectly formatted JWT.
 */
export class JWTFormatError extends Error {
    /**
     * @param {string} message - A descriptive message about the formatting issue.
     */
    constructor(message: string) {
        super(message);
        this.name = "JWTFormatError";
    }
}

/**
 * Represents an error caused by an unsupported algorithm
 */
export class JWTUnsupportedAlgorithmError extends Error {
    /**
     * @param {string} message - A descriptive message about the issue.
     */
    constructor(message: string) {
        super(message);
        this.name = "JWTUnsupportedAlgorithmError";
    }
}

/**
 * Represents a general error that occurred during JWT validation.
 */
export class JWTValidationError extends Error {
    /**
     * @param {string} message - A descriptive message about the validation failure.
     */
    constructor(message: string) {
        super(message);
        this.name = "JWTValidationError";
    }
}

/**
 * Represents an error caused by an expired JWT.
 */
export class JWTExpiredError extends JWTValidationError {
    constructor() {
        super("JWT has expired");
        this.name = "JWTExpiredError";
    }
}

/**
 * Represents an error caused by a JWT that is not yet valid.
 */
export class JWTNotYetValidError extends JWTValidationError {
    constructor() {
        super("JWT is not yet valid");
        this.name = "JWTNotYetValidError";
    }
}

/**
 * Represents an error caused by a JWT that is missing a required standard claim.
 */
export class JWTRequiredClaimMissingError extends JWTValidationError {
    /**
     * @param {string} claimName - The name of the missing claim (e.g., 'exp', 'nbf').
     */
    constructor(claimName: string) {
        super(`Missing required claim: ${claimName}`);
        this.name = "JWTRequiredClaimMissingError";
    }
}

/**
 * Represents an error caused by a JWTOption that is missing a required property
 */
export class JWTRequiredOptionMissingError extends JWTFormatError {
    /**
     * @param {string} optionName - The name of the missing option.
     */
    constructor(optionName: string) {
        super(`Missing required option: ${optionName}`);
        this.name = "JWTRequiredOptionMissingError";
    }
}
