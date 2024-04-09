import { assertEquals, assertRejects } from "@std/assert";
import { test } from "@cross/test";
import { generateKey, generateKeyPair, signJWT, validateJWT } from "./mod.ts";
import { JWTFormatError, JWTValidationError } from "./src/error.ts";
import type { SupportedGenerateKeyAlgorithms, SupportedGenerateKeyPairAlgorithms } from "./src/cryptokeys.ts";

test("signJWT() and validateJWT() with HMAC algorithms", async () => {
    for (const algorithm of ["HS256", "HS384", "HS512"]) {
        const secret =
            `my_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_secretmy_strong_${algorithm}`;
        const key = await generateKey(secret, algorithm as SupportedGenerateKeyAlgorithms);
        const payload = { foo: `bar_${algorithm}` };
        const jwtString = await signJWT(payload, key, { algorithm });
        const decodedPayload = await validateJWT(jwtString, key, { algorithm });
        assertEquals(decodedPayload.foo, payload.foo);
    }
});

test("signJWT() and validateJWT() with RSA algorithms", async () => {
    for (const algorithm of ["RS256", "RS384", "RS512"]) {
        const { privateKey, publicKey } = await generateKeyPair(algorithm as SupportedGenerateKeyPairAlgorithms);
        const payload = { foo: `bar_${algorithm}` };
        const jwtString = await signJWT(payload, privateKey, { algorithm });
        const decodedPayload = await validateJWT(jwtString, publicKey, { algorithm });
        assertEquals(decodedPayload.foo, payload.foo);
    }
});

test("signJWT() and validateJWT() with ECDSA algorithms", async () => {
    for (const algorithm of ["ES256", "ES384"]) {
        const { privateKey, publicKey } = await generateKeyPair(algorithm as SupportedGenerateKeyPairAlgorithms);
        const payload = { foo: `bar_${algorithm}` };
        const jwtString = await signJWT(payload, privateKey, { algorithm });
        const decodedPayload = await validateJWT(jwtString, publicKey, { algorithm });
        assertEquals(decodedPayload.foo, payload.foo);
    }
});

test("signJWT() and validateJWT() with RSA-PPS algorithms", async () => {
    for (const algorithm of ["PS256", "PS384", "PS512"]) {
        const { privateKey, publicKey } = await generateKeyPair(algorithm as SupportedGenerateKeyPairAlgorithms);
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
