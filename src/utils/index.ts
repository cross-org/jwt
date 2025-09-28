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
        const algorithm = key.algorithm;
        if (algorithm.name === "HMAC") {
            return `HS${(algorithm as HmacKeyAlgorithm).hash.name.replace("SHA-", "")}`;
        } else if (algorithm.name === "RSASSA-PKCS1-v1_5") {
            return `RS${(algorithm as RsaHashedKeyAlgorithm).hash.name.replace("SHA-", "")}`;
        } else if (algorithm.name === "RSA-PSS") {
            return `PS${(algorithm as RsaHashedKeyAlgorithm).hash.name.replace("SHA-", "")}`;
        } else if (algorithm.name === "ECDSA") {
            return `ES${(algorithm as EcKeyAlgorithm).namedCurve.replace("P-", "")}`;
        }
    }

    return null;
}
