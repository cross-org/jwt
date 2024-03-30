/**
 * Represents the payload of a JWT. Includes optional standard claims and allows for the
 * addition of custom properties.
 * See RFC 7519 (https://tools.ietf.org/html/rfc7519) for details on standard claims.
 */
export interface JWTPayload {
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

    /**
     * Allows for the inclusion of custom properties with string keys and values of any type.
     */
    // deno-lint-ignore no-explicit-any
    [key: string]: any;
}
