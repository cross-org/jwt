// examples/result-type-usage.ts
// Basic usage with safe Result-based functions

import {
    generateKeyPairSafe,
    generateKeySafe,
    signJWTSafe,
    unsafeParseJOSEHeaderSafe,
    unsafeParseJWTSafe,
    validateJWTSafe,
} from "@cross/jwt";

async function safeUsage() {
    console.log("=== Safe JWT Usage (Result-based Functions) ===\n");

    // 1. HMAC with string secret
    console.log("1. HMAC with string secret:");
    const secret = "my_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_HS256";
    const payload = { userId: 123, name: "John Doe" };

    const keyResult = await generateKeySafe(secret, "HS256");
    if (keyResult.isOk()) {
        const key = keyResult.value;

        const signResult = await signJWTSafe(payload, key, { algorithm: "HS256" });
        if (signResult.isOk()) {
            const jwt = signResult.value;
            console.log("JWT:", jwt);

            const validateResult = await validateJWTSafe(jwt, key, { algorithm: "HS256" });
            if (validateResult.isOk()) {
                console.log("Decoded payload:", validateResult.value);
            } else {
                console.error("Validation failed:", validateResult.errorValue.message);
            }
        } else {
            console.error("Signing failed:", signResult.errorValue.message);
        }
    } else {
        console.error("Key generation failed:", keyResult.errorValue.message);
    }

    console.log("\n" + "=".repeat(50) + "\n");

    // 2. RSA with key pair
    console.log("2. RSA with key pair:");
    const keyPairResult = await generateKeyPairSafe("RS256");
    if (keyPairResult.isOk()) {
        const { privateKey, publicKey } = keyPairResult.value;

        const signResult = await signJWTSafe(payload, privateKey, { algorithm: "RS256" });
        if (signResult.isOk()) {
            const jwt = signResult.value;
            console.log("JWT:", jwt);

            const validateResult = await validateJWTSafe(jwt, publicKey, { algorithm: "RS256" });
            if (validateResult.isOk()) {
                console.log("Decoded payload:", validateResult.value);
            } else {
                console.error("Validation failed:", validateResult.errorValue.message);
            }
        } else {
            console.error("Signing failed:", signResult.errorValue.message);
        }
    } else {
        console.error("Key pair generation failed:", keyPairResult.errorValue.message);
    }

    console.log("\n" + "=".repeat(50) + "\n");

    // 3. Unsafe parsing (no verification)
    console.log("3. Unsafe parsing (no verification):");
    const unsafeKeyResult = await generateKeySafe(secret, "HS256");
    if (unsafeKeyResult.isOk()) {
        const key = unsafeKeyResult.value;
        const signResult = await signJWTSafe(payload, key);
        if (signResult.isOk()) {
            const jwt = signResult.value;

            const unsafePayloadResult = unsafeParseJWTSafe(jwt);
            const unsafeHeaderResult = unsafeParseJOSEHeaderSafe(jwt);

            if (unsafePayloadResult.isOk()) {
                console.log("Unsafe payload:", unsafePayloadResult.value);
            } else {
                console.error("Unsafe payload parsing failed:", unsafePayloadResult.errorValue.message);
            }

            if (unsafeHeaderResult.isOk()) {
                console.log("Unsafe header:", unsafeHeaderResult.value);
            } else {
                console.error("Unsafe header parsing failed:", unsafeHeaderResult.errorValue.message);
            }
        } else {
            console.error("Signing failed:", signResult.errorValue.message);
        }
    } else {
        console.error("Key generation failed:", unsafeKeyResult.errorValue.message);
    }

    console.log("\n" + "=".repeat(50) + "\n");

    // 4. Error handling example
    console.log("4. Error handling example:");
    const invalidJWT = "invalid.jwt.token";
    const errorKeyResult = await generateKeySafe(secret, "HS256");
    if (errorKeyResult.isOk()) {
        const key = errorKeyResult.value;
        const validateResult = await validateJWTSafe(invalidJWT, key);
        if (validateResult.isErr()) {
            console.log(
                "Caught expected error:",
                validateResult.errorValue.constructor.name,
                "-",
                validateResult.errorValue.message,
            );
        } else {
            console.log("Unexpected success with invalid JWT");
        }
    } else {
        console.error("Key generation failed:", errorKeyResult.errorValue.message);
    }
}

// Run the example
safeUsage().catch(console.error);
