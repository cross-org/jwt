// examples/basic-usage.ts
// Basic usage with traditional throwing functions

import { generateKey, generateKeyPair, signJWT, unsafeParseJOSEHeader, unsafeParseJWT, validateJWT } from "@cross/jwt";

async function basicUsage() {
    console.log("=== Basic JWT Usage (Traditional Throwing Functions) ===\n");

    // 1. HMAC with string secret
    console.log("1. HMAC with string secret:");
    const secret = "my_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_HS256";
    const payload = { userId: 123, name: "John Doe" };

    try {
        const key = await generateKey(secret, "HS256");
        const jwt = await signJWT(payload, key, { algorithm: "HS256" });
        console.log("JWT:", jwt);

        const decoded = await validateJWT(jwt, key, { algorithm: "HS256" });
        console.log("Decoded payload:", decoded);
    } catch (error) {
        console.error("Error:", (error as Error).message);
    }

    console.log("\n" + "=".repeat(50) + "\n");

    // 2. RSA with key pair
    console.log("2. RSA with key pair:");
    try {
        const { privateKey, publicKey } = await generateKeyPair("RS256");
        const jwt = await signJWT(payload, privateKey, { algorithm: "RS256" });
        console.log("JWT:", jwt);

        const decoded = await validateJWT(jwt, publicKey, { algorithm: "RS256" });
        console.log("Decoded payload:", decoded);
    } catch (error) {
        console.error("Error:", (error as Error).message);
    }

    console.log("\n" + "=".repeat(50) + "\n");

    // 3. Unsafe parsing (no verification)
    console.log("3. Unsafe parsing (no verification):");
    try {
        const key = await generateKey(secret, "HS256");
        const jwt = await signJWT(payload, key);
        const unsafePayload = unsafeParseJWT(jwt);
        const unsafeHeader = unsafeParseJOSEHeader(jwt);

        console.log("Unsafe payload:", unsafePayload);
        console.log("Unsafe header:", unsafeHeader);
    } catch (error) {
        console.error("Error:", (error as Error).message);
    }

    console.log("\n" + "=".repeat(50) + "\n");

    // 4. Error handling example
    console.log("4. Error handling example:");
    try {
        const invalidJWT = "invalid.jwt.token";
        const key = await generateKey(secret, "HS256");
        await validateJWT(invalidJWT, key);
    } catch (error) {
        console.log("Caught expected error:", (error as Error).constructor.name, "-", (error as Error).message);
    }
}

// Run the example
basicUsage().catch(console.error);
