/**
 * The the JOSE header part of a JWT, JWS or JWE structure.
 *
 * Note: only some of the more common claims are defined here. See RFC 7519 (https://tools.ietf.org/html/rfc7519),
 * RFC 7515 (https://tools.ietf.org/html/rfc7515) and RFC 7516 (https://tools.ietf.org/html/rfc7516) for a
 * full list of standard header claims and their explanations.
 */
export interface JOSEHeader {
    /**
     * The cryptographic algorithm used to secure the JWS/JWE structure.
     * If unspecified, the `signJWT()` function will use the algorithm of the provided key
     * as the value of this header claim.
     *
     * (See RFC 7515 section 4.1.1, RFC 7516 section 4.1.1)
     */
    alg?: string;

    /**
     * When the token is signed with a key from a JSON Web Key set (JWKS), this is the identifier
     * of the key in the JWKS.
     *
     * (See RFC 7515 section 4.1.4, RFC 7516 section 4.1.6)
     */
    kid?: string;

    /**
     * The media type of the complete JWT/JWS/JWE. If unspecified, the `signJWT()`
     * function will use "JWT" as the value of this header claim.
     *
     * (see RFC 7519 section 5.1, RFC 7515 section 4.1.9, RFC 7516 section 4.1.11)
     */
    typ?: string;
}

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
