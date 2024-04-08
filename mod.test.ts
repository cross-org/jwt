import { assertEquals } from "@std/assert";
import { test } from "@cross/test";
import { generateKey, generateKeyPair, signJWT, validateJWT } from "./mod.ts";
import type { SupportedGenerateKeyAlgorithms, SupportedGenerateKeyPairAlgorithms } from "./src/cryptokeys.ts";

/** ==== Signing and Verification ==== */
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
/*
More tests to come.
test("validateJWT() fails with incorrect key", async () => {
    const secret = "mySuperSecretAtLeast32CharsLong!";
    const jwtString = await signJWT({ hello: "world" }, secret);

    assertThrows(async () => await validateJWT(jwtString, "incorrect_keyincorrect_keyincorrect_keyincorrect_key"));
});
*/
