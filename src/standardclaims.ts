/**
 * Represents the standard claims that may be included in a JWT.
 * See RFC 7519 (https://tools.ietf.org/html/rfc7519) for details.
 */
interface StandardClaims {
    /**
     * Issuer: Identifies the principal that issued the JWT.
     */
    iss?: string;

    /**
     * Subject: Identifies the principal that is the subject of the JWT.
     */
    sub?: string;

    /**
     * Audience: Identifies the recipients that the JWT is intended for.
     * Can be a single string or an array of strings.
     */
    aud?: string | string[];

    /**
     * Expiration Time: Identifies the expiration time on or after which the
     * JWT MUST NOT be accepted for processing. Represented as a NumericDate
     * value as defined in RFC 7519.
     */
    exp?: number;

    /**
     * Not Before Time: Identifies the time before which the JWT MUST NOT be
     * accepted for processing. Represented as a NumericDate value as defined in RFC 7519.
     */
    nbf?: number;

    /**
     * Issued At Time: Identifies the time at which the JWT was issued.
     * Represented as a NumericDate value as defined in RFC 7519.
     */
    iat?: number;

    /**
     * JWT ID: Provides a unique identifier for the JWT.
     */
    jti?: string;
}

/**
 * Represents the payload of a JWT. Includes optional standard claims and allows for the
 * addition of custom properties.
 */
export interface JWTPayload extends StandardClaims {
    // deno-lint-ignore no-explicit-any
    [key: string]: any; // Allow additional custom properties
}
