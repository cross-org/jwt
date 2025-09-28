import { assertEquals } from "@std/assert";
import { test } from "@cross/test";
import {
    err,
    generateKeyPairSafe as generateKeyPair,
    generateKeySafe as generateKey,
    JWTAmbiguousClaimError,
    JWTExpiredError,
    JWTFormatError,
    JWTNotYetValidError,
    JWTParseError,
    JWTUnsupportedAlgorithmError,
    JWTValidationError,
    ok,
    signJWTSafe,
    unsafeParseJOSEHeaderSafe as unsafeParseJOSEHeader,
    unsafeParseJWTSafe as unsafeParseJWT,
    validateJWTSafe,
} from "./mod.ts";
import type { SupportedKeyAlgorithms, SupportedKeyPairAlgorithms } from "./src/crypto/keys.ts";

// Test Result type functionality
test("Result type - Ok", () => {
    const result = ok("success");
    assertEquals(result.isOk(), true);
    assertEquals(result.isErr(), false);
    assertEquals(result.value, "success");
});

test("Result type - Err", () => {
    const result = err(new Error("failure"));
    assertEquals(result.isOk(), false);
    assertEquals(result.isErr(), true);
    assertEquals(result.errorValue.message, "failure");
});

test("Result type - map", () => {
    const result = ok(5);
    const mapped = result.map((x) => x * 2);
    assertEquals(mapped.isOk(), true);
    if (mapped.isOk()) {
        assertEquals(mapped.value, 10);
    }
});

test("Result type - flatMap", () => {
    const result = ok(5);
    const flatMapped = result.flatMap((x) => ok(x * 2));
    assertEquals(flatMapped.isOk(), true);
    if (flatMapped.isOk()) {
        assertEquals(flatMapped.value, 10);
    }
});

test("generateKey() with valid input (safe mode)", async () => {
    const secret = "my_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_HS256";
    const result = await generateKey(secret, "HS256");
    assertEquals(result.isOk(), true);
    if (result.isOk()) {
        assertEquals(result.value.type, "secret");
        assertEquals(result.value.algorithm.name, "HMAC");
    }
});

test("generateKey() with invalid algorithm", async () => {
    const secret = "my_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_HS256";
    const result = await generateKey(secret, "INVALID" as SupportedKeyAlgorithms);
    assertEquals(result.isErr(), true);
    if (result.isErr()) {
        assertEquals(result.errorValue instanceof JWTUnsupportedAlgorithmError, true);
    }
});

test("generateKey() with short secret", async () => {
    const secret = "short";
    const result = await generateKey(secret, "HS256");
    assertEquals(result.isErr(), true);
    if (result.isErr()) {
        assertEquals(result.errorValue instanceof JWTValidationError, true);
    }
});

test("generateKeyPair() with valid input", async () => {
    const result = await generateKeyPair("RS256");
    assertEquals(result.isOk(), true);
    if (result.isOk()) {
        assertEquals(result.value.privateKey.type, "private");
        assertEquals(result.value.publicKey.type, "public");
    }
});

test("generateKeyPair() with invalid algorithm", async () => {
    const result = await generateKeyPair("INVALID" as SupportedKeyPairAlgorithms);
    assertEquals(result.isErr(), true);
    if (result.isErr()) {
        assertEquals(result.errorValue instanceof JWTUnsupportedAlgorithmError, true);
    }
});

test("signJWT() and validateJWT() with HMAC", async () => {
    const secret = "my_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_HS256";
    const payload = { foo: "bar" };
    const signResult = await signJWTSafe(payload, secret);
    assertEquals(signResult.isOk(), true);
    if (signResult.isOk()) {
        const validateResult = await validateJWTSafe(signResult.value, secret);
        assertEquals(validateResult.isOk(), true);
        if (validateResult.isOk()) {
            assertEquals(validateResult.value.foo, payload.foo);
        }
    }
});

test("signJWT() with ambiguous claims", async () => {
    const secret = "my_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_HS256";
    const payload = { foo: "bar", exp: Math.floor(Date.now() / 1000) + 3600 };
    const result = await signJWTSafe(payload, secret, { expiresIn: "1h" });
    assertEquals(result.isErr(), true);
    if (result.isErr()) {
        assertEquals(result.errorValue instanceof JWTAmbiguousClaimError, true);
    }
});

test("validateJWT() with invalid JWT format", async () => {
    const secret = "my_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_HS256";
    const invalidJWT = "invalid.jwt";
    const result = await validateJWTSafe(invalidJWT, secret);
    assertEquals(result.isErr(), true);
    if (result.isErr()) {
        assertEquals(result.errorValue instanceof JWTFormatError, true);
    }
});

test("validateJWT() with incorrect key", async () => {
    const secret = "my_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_HS256";
    const payload = { foo: "bar" };
    const signResult = await signJWTSafe(payload, secret);
    assertEquals(signResult.isOk(), true);
    if (signResult.isOk()) {
        const validateResult = await validateJWTSafe(
            signResult.value,
            "incorrect_keyincorrect_keyincorrect_keyincorrect_key",
        );
        assertEquals(validateResult.isErr(), true);
        if (validateResult.isErr()) {
            assertEquals(validateResult.errorValue instanceof JWTValidationError, true);
        }
    }
});

test("validateJWT() with expired JWT", async () => {
    const secret = "my_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_HS256";
    const payload = { foo: "bar", exp: Math.floor(Date.now() / 1000) - 3600 }; // Expired 1 hour ago
    const signResult = await signJWTSafe(payload, secret);
    assertEquals(signResult.isOk(), true);
    if (signResult.isOk()) {
        const validateResult = await validateJWTSafe(signResult.value, secret, { validateExp: true });
        assertEquals(validateResult.isErr(), true);
        if (validateResult.isErr()) {
            assertEquals(validateResult.errorValue instanceof JWTExpiredError, true);
        }
    }
});

test("validateJWT() with JWT not yet valid", async () => {
    const secret = "my_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_HS256";
    const payload = { foo: "bar", nbf: Math.floor(Date.now() / 1000) + 3600 }; // Not valid for 1 hour
    const signResult = await signJWTSafe(payload, secret);
    assertEquals(signResult.isOk(), true);
    if (signResult.isOk()) {
        const validateResult = await validateJWTSafe(signResult.value, secret, { validateNbf: true });
        assertEquals(validateResult.isErr(), true);
        if (validateResult.isErr()) {
            assertEquals(validateResult.errorValue instanceof JWTNotYetValidError, true);
        }
    }
});

test("unsafeParseJWT() with valid JWT", async () => {
    const secret = "my_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_HS256";
    const payload = { foo: "bar", aud: "test" };
    const signResult = await signJWTSafe(payload, secret);
    assertEquals(signResult.isOk(), true);
    if (signResult.isOk()) {
        const parseResult = unsafeParseJWT(signResult.value);
        assertEquals(parseResult.isOk(), true);
        if (parseResult.isOk()) {
            assertEquals(parseResult.value.foo, payload.foo);
            assertEquals(parseResult.value.aud, payload.aud);
        }
    }
});

test("unsafeParseJWT() with invalid JWT", () => {
    const result = unsafeParseJWT("invalid.jwt");
    assertEquals(result.isErr(), true);
    if (result.isErr()) {
        assertEquals(result.errorValue instanceof JWTParseError, true);
    }
});

test("unsafeParseJOSEHeader() with valid JWT", async () => {
    const secret = "my_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_HS256";
    const payload = { foo: "bar" };
    const signResult = await signJWTSafe(payload, secret);
    assertEquals(signResult.isOk(), true);
    if (signResult.isOk()) {
        const parseResult = unsafeParseJOSEHeader(signResult.value);
        assertEquals(parseResult.isOk(), true);
        if (parseResult.isOk()) {
            assertEquals(parseResult.value.alg, "HS256");
            assertEquals(parseResult.value.typ, "JWT");
        }
    }
});
