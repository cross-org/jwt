// Shimmed webcrypto algorithm interface.
interface ShimmedAlgo {
    // Algo name
    name: string;
    // Specifies the hash function used by the RSA algorithm.
    hash: {
        // The name of the hash function (e.g., "SHA-256", "SHA-512").
        name: string;
    };
    // The name of the elliptic curve used by the ECDSA algorithm (e.g., "P-256", "P-384").
    namedCurve: string;
}
/**
 * Detects the algorithm used by a provided CryptoKey object.
 *
 * @param {CryptoKey | "none"} key - The key to analyze, or a "none"-string.
 * @returns {string | null} The detected algorithm name (e.g., "HS256", "ES384", "RS256") or null if unsupported.
 */
export function detectAlgorithm(key: CryptoKey | "none"): string | null {
    if (typeof key === "string" && key === "none") {
        return key;
    } else if (typeof key === "object") {
        const algorithm = key.algorithm as ShimmedAlgo;
        if (algorithm.name === "HMAC") {
            return `HS${algorithm.hash.name.replace("SHA-", "")}`;
        } else if (algorithm.name === "RSASSA-PKCS1-v1_5") {
            return `RS${algorithm.hash.name.replace("SHA-", "")}`;
        } else if (algorithm.name === "RSA-PSS") {
            return `PS${algorithm.hash.name.replace("SHA-", "")}`;
        } else if (algorithm.name === "ECDSA") {
            return `ES${algorithm.namedCurve.replace("P-", "")}`;
        }
    }

    return null;
}
