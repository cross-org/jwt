import { assertEquals, assertRejects } from "@std/assert";
import { test } from "@cross/test";
import { generateKey, generateKeyPair, signJWT, unsafeParseJOSEHeader, unsafeParseJWT, validateJWT } from "./mod.ts";
import { JWTAmbiguousClaimError, JWTFormatError, JWTValidationError } from "./src/error.ts";
import type { SupportedKeyAlgorithms, SupportedKeyPairAlgorithms } from "./src/cryptokeys.ts";
import type { JOSEHeader } from "./mod.ts";

test("signJWT() and validateJWT() with HMAC algorithms", async () => {
    for (const algorithm of ["HS256", "HS384", "HS512"]) {
        const secret =
            `my_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_${algorithm}`;
        const key = await generateKey(secret, algorithm as SupportedKeyAlgorithms);
        const payload = { foo: `bar_${algorithm}` };
        const jwtString = await signJWT(payload, key, { algorithm });
        const decodedPayload = await validateJWT(jwtString, key, { algorithm });
        assertEquals(decodedPayload.foo, payload.foo);
    }
});

test("signJWT() and validateJWT() with RSA algorithms", async () => {
    for (const algorithm of ["RS256", "RS384", "RS512"]) {
        const { privateKey, publicKey } = await generateKeyPair(algorithm as SupportedKeyPairAlgorithms);
        const payload = { foo: `bar_${algorithm}` };
        const jwtString = await signJWT(payload, privateKey, { algorithm });
        const decodedPayload = await validateJWT(jwtString, publicKey, { algorithm });
        assertEquals(decodedPayload.foo, payload.foo);
    }
});

test("signJWT() and validateJWT() with ECDSA algorithms", async () => {
    for (const algorithm of ["ES256", "ES384"]) {
        const { privateKey, publicKey } = await generateKeyPair(algorithm as SupportedKeyPairAlgorithms);
        const payload = { foo: `bar_${algorithm}` };
        const jwtString = await signJWT(payload, privateKey, { algorithm });
        const decodedPayload = await validateJWT(jwtString, publicKey, { algorithm });
        assertEquals(decodedPayload.foo, payload.foo);
    }
});

test("signJWT() and validateJWT() with RSA-PPS algorithms", async () => {
    for (const algorithm of ["PS256", "PS384", "PS512"]) {
        const { privateKey, publicKey } = await generateKeyPair(algorithm as SupportedKeyPairAlgorithms);
        const payload = { foo: `bar_${algorithm}` };
        const jwtString = await signJWT(payload, privateKey, { algorithm });
        const decodedPayload = await validateJWT(jwtString, publicKey, { algorithm });
        assertEquals(decodedPayload.foo, payload.foo);
    }
});

test("validateJWT() throws JWTFormatError on invalid jwt structure", async () => {
    const secret = "mySuperSecretAtLeast32CharsLong!";
    const payload = { foo: "bar" };
    let jwtString = await signJWT(payload, secret);

    // Add extra period
    jwtString += ".extraPart";
    await assertRejects(() => validateJWT(jwtString, secret), JWTFormatError);
});

test("validateJWT() throws JWTValidationError on incorrect key", async () => {
    const secret = "mySuperSecretAtLeast32CharsLong!";
    const jwtString = await signJWT({ foo: "bar" }, secret);

    await assertRejects(
        () => validateJWT(jwtString, "incorrect_keyincorrect_keyincorrect_keyincorrect_key"),
        JWTValidationError,
    );
});

test("validateJWT() throws JWTFormatError on invalid Base64URL", async () => {
    const secret = "mySuperSecretAtLeast32CharsLong!";
    const payload = { foo: "bar" };
    let jwtString = await signJWT(payload, secret);
    const parts = jwtString.split(".");

    // Tamper with the header
    const tamperedHeader = parts[0] + "A";
    jwtString = [tamperedHeader, parts[1], parts[2]].join(".");
    await assertRejects(() => validateJWT(jwtString, secret), JWTFormatError);
});

test("validateJWT() throws JWTValidationError on tampered payload ", async () => {
    const secret = "mySuperSecretAtLeast32CharsLong!";
    const payload = { foo: "bar" };
    let jwtString = await signJWT(payload, secret);
    const parts = jwtString.split(".");

    // Tamper with the payload
    const tamperedPayload = parts[1].slice(0, -2);
    jwtString = [parts[0], tamperedPayload, parts[2]].join(".");
    await assertRejects(() => validateJWT(jwtString, secret), JWTValidationError);
});

// Tests for JWTAmbiguousClaimError
test("signJWT() throws JWTAmbiguousClaimError with 'expiresIn' and 'exp'", async () => {
    const secret = "mySuperSecretAtLeast32CharsLong!";
    const payload = { foo: "bar", exp: 1234567890 }; // Explicit exp

    await assertRejects(
        () => signJWT(payload, secret, { expiresIn: "1h" }), // Also using expiresIn
        JWTAmbiguousClaimError,
    );
});

test("signJWT() throws JWTAmbiguousClaimError with 'notBefore' and 'nbf'", async () => {
    const secret = "mySuperSecretAtLeast32CharsLong!";
    const payload = { foo: "bar", nbf: 1234567890 }; // Explicit nbf

    await assertRejects(
        () => signJWT(payload, secret, { notBefore: "5m" }), // Also using notBefore
        JWTAmbiguousClaimError,
    );
});

test("signJWT() works with 'expiresIn' only", async () => {
    const secret = "mySuperSecretAtLeast32CharsLong!";
    const payload = { foo: "bar" };

    const jwt = await signJWT(payload, secret, { expiresIn: "1h" });
    const decoded = await validateJWT(jwt, secret);
    assertEquals(typeof decoded.exp, "number");
});

test("signJWT() works with 'notBefore' only", async () => {
    const secret = "mySuperSecretAtLeast32CharsLong!";
    const payload = { foo: "bar" };

    const jwt = await signJWT(payload, secret, { notBefore: "5m" });
    const decoded = await validateJWT(jwt, secret);
    assertEquals(typeof decoded.nbf, "number");
});

test("signJWT() supports additional header claims", async () => {
    const algorithm: SupportedKeyPairAlgorithms = "RS256";
    const { privateKey, publicKey } = await generateKeyPair(algorithm);
    const payload = { foo: "bar", baz: 42 };
    const jwtString = await signJWT(payload, privateKey, {
        algorithm: algorithm,
        additionalHeaderClaims: { typ: "JOSE", kid: "abc123", someOther: [1, 2, 3] },
    });

    const unsafeHeader = unsafeParseJOSEHeader(jwtString);
    const unsafePayload = unsafeParseJWT(jwtString);
    const decodedPayload = await validateJWT(jwtString, publicKey, { algorithm });

    assertEquals(unsafePayload, payload);
    assertEquals(decodedPayload, payload);
    const expectedHeader: JOSEHeader = { alg: algorithm, typ: "JOSE", kid: "abc123", someOther: [1, 2, 3] };
    assertEquals(unsafeHeader, expectedHeader);
});

test("validateJWT() ignores the `alg` header claim", async () => {
    const algorithm: SupportedKeyPairAlgorithms = "RS256";
    const { privateKey, publicKey } = await generateKeyPair(algorithm);
    const payload = { foo: "bar", baz: 42 };
    const jwtString = await signJWT(payload, privateKey, {
        algorithm: algorithm,
        additionalHeaderClaims: { alg: "none" }, // Note the algorithm mismatch
    });

    // Should use the algorithm present in the public key, not the algorithm claimed by the JWT.
    const decodedPayload = await validateJWT(jwtString, publicKey);
    assertEquals(decodedPayload, payload);
});

test("validateJWT() throws JWTValidationError on stripped token", async () => {
    const algorithm: SupportedKeyPairAlgorithms = "RS256";
    const keyPair = await generateKeyPair(algorithm);

    const payload = { foo: "bar", baz: 42 };

    // Simulates the scenario where the attacker tampered with the body and tries to pass an
    // unsigned token as the real item.
    const jwtString = await signJWT(payload, false);

    await assertRejects(
        () => validateJWT(jwtString, keyPair.publicKey),
        JWTValidationError,
    );
});
