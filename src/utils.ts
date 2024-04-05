/**
 * Options for customizing JWT creation and parsing behavior.
 */
export interface JWTOptions {
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
}
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
};

/**
 * Represents supported HMAC algorithms filtered from the `algorithmMapping` object.
 */
export type FilteredHSAlgorithms = {
    [K in keyof typeof algorithmMapping as K extends `HS${string}` ? K : never]: typeof algorithmMapping[K];
};
/**
 * Represents valid HMAC algorithm names (e.g., "HS256", "HS512").
 */
export type AllowedHSAlgorithms = keyof FilteredHSAlgorithms;

/**
 * Represents supported RSA algorithms filtered from the `algorithmMapping` object.
 */
export type FilteredRSAlgorithms = {
    [K in keyof typeof algorithmMapping as K extends `RS${string}` ? K : never]: typeof algorithmMapping[K];
};
/**
 * Represents valid RSA algorithm names (e.g., "RS256", "RS512").
 */
export type AllowedRSAlgorithms = keyof FilteredRSAlgorithms;

/**
 * Represents supported RSA-PSS algorithms filtered from the `algorithmMapping` object.
 */
export type FilteredRSAPSSAlgorithms = {
    [K in keyof typeof algorithmMapping as K extends `PS${string}` ? K : never]: typeof algorithmMapping[K];
};
/**
 * Represents valid RSA-PSS algorithm names (e.g., "PS256").
 */
export type AllowedRSAPSSAlgorithms = keyof FilteredRSAPSSAlgorithms;

/**
 * Represents supported ECDSA algorithms filtered from the `algorithmMapping` object.
 */
export type FilteredESAlgorithms = {
    [K in keyof typeof algorithmMapping as K extends `ES${string}` ? K : never]: typeof algorithmMapping[K];
};
/**
 * Represents valid ECDSA algorithm names (e.g., "ES256", "ES384").
 */
export type AllowedECAlgorithms = keyof FilteredESAlgorithms;

/**
 * Represents valid algorithm names for key generation using HMAC.
 */
export type SupportedGenerateKeyAlgorithms = AllowedHSAlgorithms;
/**
 * Represents valid algorithm names for generating key pairs using RSA, ECDSA and RSA-PSS.
 */
export type SupportedGenerateKeyPairAlgorithms = AllowedRSAlgorithms | AllowedECAlgorithms | AllowedRSAPSSAlgorithms;

/**
 * Represents the properties of an HMAC key algorithm, as expected by the Web Crypto API.
 */
export interface HMACAlgorithm extends KeyAlgorithm {
    /**
     * Must be set to "HMAC".
     */
    name: "HMAC";

    /**
     * Specifies the hash function used by the HMAC algorithm.
     */
    hash: {
        /**
         *  The name of the hash function (e.g., "SHA-256", "SHA-512").
         */
        name: string;
    };
}

/**
 * Represents the properties of an RSA key algorithm, as expected by the Web Crypto API.
 */
export interface RSAAlgorithm extends KeyAlgorithm {
    /**
     * Must be set to either "RSASSA-PKCS1-v1_5" or "RSA-PSS".
     */
    name: "RSASSA-PKCS1-v1_5" | "RSA-PSS";

    /**
     * Specifies the hash function used by the RSA algorithm.
     */
    hash: {
        /**
         * The name of the hash function (e.g., "SHA-256", "SHA-512").
         */
        name: string;
    };
}

/**
 * Represents the properties of an ECDSA key algorithm, as expected by the Web Crypto API.
 */
export interface ECDSAAlgorithm extends KeyAlgorithm {
    /**
     * Must be set to "ECDSA".
     */
    name: "ECDSA";

    /**
     * The name of the elliptic curve used by the ECDSA algorithm (e.g., "P-256", "P-384").
     */
    namedCurve: string;
}

/**
 * Detects the algorithm used by a provided CryptoKey object.
 *
 * @param {CryptoKey} key - The key to analyze.
 * @returns {string | null} The detected algorithm name (e.g., "HS256", "ES384", "RS256") or null if unsupported.
 */
export function detectAlgorithm(key: CryptoKey): string | null {
    const algorithm = key.algorithm;
    if (algorithm.name === "HMAC") {
        const hmacAlgorithm = algorithm as HMACAlgorithm; // Type assertion
        return `HS${hmacAlgorithm.hash.name.replace("SHA-", "")}`;
    } else if (algorithm.name === "RSASSA-PKCS1-v1_5") {
        const rsaAlgorithm = algorithm as RSAAlgorithm; // Type assertion
        return `RS${rsaAlgorithm.hash.name.replace("SHA-", "")}`;
    } else if (algorithm.name === "RSA-PSS") {
        const rsaAlgorithm = algorithm as RSAAlgorithm; // Type assertion
        return `PS${rsaAlgorithm.hash.name.replace("SHA-", "")}`;
    } else if (algorithm.name === "ECDSA") {
        const ecdsaAlgorithm = algorithm as ECDSAAlgorithm; // Type assertion
        return `ES${ecdsaAlgorithm.namedCurve.replace("P-", "")}`;
    } else {
        return null;
    }
}
