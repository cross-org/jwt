/**
 * Options for customizing JWT creation and parsing behavior.
 */
export interface JWTOptions {
    /**
     * algorithm to use, will default to trying to parse one from the supplied key.
     */
    algorithm?: string;
    /**
     * If true, the 'iat' (issued at) claim will be automatically added to the JWT payload during creation.
     */
    setIat?: boolean;

    /**
     * If true, the 'exp' (expiration time) claim will be validated during creation and parsing.
     */
    validateExp?: boolean;

    /**
     *  If true, the 'nbf' (not before) claim will be validated during creation and parsing.
     */
    validateNbf?: boolean;

    /**
     * The number of seconds of leeway to allow for clock skew during expiration validation. (Default: 60)
     */
    clockSkewLeewaySeconds?: number;
    /**
     * Salt length for RSA-PSS sign and verify (default: 32).
     */
    saltLength?: number;
    /**
     * A duration string (e.g., "1h", "30m") specifying the expiration time relative to the current time.
     * Cannot be used if the `exp` claim is explicitly set in the payload.
     */
    expiresIn?: string;

    /**
     * A duration string (e.g., "5m") specifying the "not before" time relative to the current time.
     * Cannot be used if the `nbf` claim is explicitly set in the payload.
     */
    notBefore?: string;
}

/**
 * A set of default options.
 */
export const defaultOptions: JWTOptions = {
    setIat: true,
    clockSkewLeewaySeconds: 60,
    validateExp: false,
    validateNbf: false,
};

/**
 * Mapping of library supported algorithms.
 */
export const algorithmMapping = {
    // HMAC
    HS256: {
        name: "HMAC",
        hash: "SHA-256",
    },
    HS384: {
        name: "HMAC",
        hash: "SHA-384",
    },
    HS512: {
        name: "HMAC",
        hash: "SHA-512",
    },

    // RSA
    RS256: {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
    },
    RS384: {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-384",
    },
    RS512: {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-512",
    },

    // ECDSA
    ES256: {
        name: "ECDSA",
        namedCurve: "P-256",
    },
    ES384: {
        name: "ECDSA",
        namedCurve: "P-384",
    },

    // RSA-PPS
    PS256: {
        name: "RSA-PSS",
        hash: "SHA-256",
    },
    PS384: {
        name: "RSA-PSS",
        hash: "SHA-384",
    },
    PS512: {
        name: "RSA-PSS",
        hash: "SHA-512",
    },
    none: {
        name: "none",
    },
};
