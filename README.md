## @cross/jwt

[![JSR Version](https://jsr.io/badges/@cross/jwt)](https://jsr.io/@cross/jwt)
[![JSR Score](https://jsr.io/badges/@cross/jwt/score)](https://jsr.io/@cross/jwt/score)

A versatile JSON Web Token (JWT) library for Deno, Bun, and Node.js providing cross-runtime compatibility.

Part of the @cross suite - check out our growing collection of cross-runtime tools at
[github.com/cross-org](https://github.com/cross-org).

## Features

- **Secure Cryptography:** Supports HMAC, RSA, RSA-PSS and ECDSA signing algorithms for robust JWT protection.
- **Cross-Platform:** Functions seamlessly across Deno, Bun, and Node.js environments.
- **Intuitive API:** Provides simple-to-use functions for JWT creation, parsing, signing, and verification.
- **Key Management:** Includes helpers for generating HMAC secret keys and RSA or ECDSA key pairs.

## Installation

```bash
# For Deno
deno add @cross/jwt

# For Bun
bunx jsr add @cross/jwt

# For Node.js
npx jsr add @cross/jwt
```

## API

See [docs on jsr.io](https://jsr.io/@cross/jwt/doc) for details.

**Helper Functions**

- **`generateKey(keyStr: string, optionsOrAlgorithm?: SupportedGenerateKeyAlgorithms | Options): Promise<CryptoKey>`**

- **`generateKeyPair(optionsOrAlgorithm?: KeyPairOptions): Promise<CryptoKeyPair>`**

- **`exportKeyFiles(options: exportKeyFilesOptions): Promise<ExportedKeyFiles>`** (Experimental)

**Sign and validate**

- **`signJWT(payload: JWTPayload, key: CryptoKey | string, options?: Options): Promise<string>`**

- **`validateJWT(jwt: string, key: CryptoKey | string, options?: Options): Promise<JWTPayload>`**

**GenerateKeyOptions Object**

The `GenerateKeyOptions` object can be used to provide flexibility when generating HMAC keys:

```typescript
/**
 * Options for key generation
 */
interface GenerateKeyOptions {
    //The HMAC algorithm to use for key generation. Defaults to 'HS256'.
    algorithm?: SupportedGenerateKeyAlgorithms;
    // Use with caution, as shorter keys are less secure.
    allowInsecureKeyLengths?: boolean;
}
```

**GenerateKeyPairOptions Object**

The `GenerateKeyPairOptions` object can be used to provide flexibility when generating RSA key pairs:

```typescript
/**
 * Options for key pair generation.
 */
interface GenerateKeyPairOptions {
    //The algorithm to use for key pair generation. Defaults to 'RS256'.
    algorithm?: SupportedGenerateKeyPairAlgorithms;
    // The desired length of the RSA modulus in bits. Larger values offer greater
    // security, but impact performance. A common default is 2048.
    modulusLength?: number;
}
```

The `exportKeyFilesOptions` object can be used to provide flexibility when exporting key pairs:

```typescript
/**
 * Represents the options for the `exportKeyFiles` function.
 */
export interface exportKeyFilesOptions {
    /**
     * The private key to be exported.
     */
    privateKey: CryptoKey;

    /**
     * The file path where the PEM-formatted private key will be written. No file will be written if undefined.
     */
    privateFile?: string;

    /**
     * The public key to be exported.
     */
    publicKey: CryptoKey;

    /**
     * The file path where the PEM-formatted public key will be written. No file will be written if undefined.
     */
    publicFile?: string;
}
```

**JWTOptions Object**

The `JWTOptions` object can be used to provide flexibility when creating JWTs:

```typescript
/**
 * Options for customizing JWT creation and parsing behavior.
 */
interface JWTOptions {
    // Algorithm to use.
    // Algorithm for signing should be the same as key algorithm, used to enforce the use of a specific algorithm (can be useful for security reasons). (default: parsed from the supplied key)
    algorithm?: string;
    // If true, the 'iat' (issued at) claim will be automatically added to the JWT payload during creation. (default: true)
    setIat?: boolean;
    // If true, the 'exp' (expiration time) claim will be validated during creation and parsing.
    validateExp?: boolean;
    // If true, the 'nbf' (not before) claim will be validated during creation and parsing.
    validateNbf?: boolean;
    //The number of seconds of leeway to allow for clock skew during expiration validation. (default: 60)
    clockSkewLeewaySeconds?: number;
    //Salt length for RSA-PSS sign and verify (default: 32).
    saltLength?: number;
}
```

## Supported algorithms

| Algorithm | Description                                    |
| --------- | ---------------------------------------------- |
| HS256     | HMAC using SHA-256                             |
| HS384     | HMAC using SHA-384                             |
| HS512     | HMAC using SHA-512                             |
| RS256     | RSASSA-PKCS1-v1_5 using SHA-256                |
| RS384     | RSASSA-PKCS1-v1_5 using SHA-384                |
| RS512     | RSASSA-PKCS1-v1_5 using SHA-512                |
| ES256     | ECDSA using P-256 and SHA-256                  |
| ES384     | ECDSA using P-384 and SHA-384                  |
| PS256     | RSASSA-PSS using SHA-256 and MGF1 with SHA-256 |
| PS384     | RSASSA-PSS using SHA-384 and MGF1 with SHA-384 |
| PS512     | RSASSA-PSS using SHA-512 and MGF1 with SHA-512 |
| none      | Unsecured JWT                                  |

## Usage

The most common way to sign and verify JWTs is using HMAC.

```javascript
import { signJWT, validateJWT } from "@cross/jwt";

// Signing the JWT with HS256 by default, here with a string secret used to generate a key.
const secret = "mySuperSecretAtLeast32CharsLong!";
const jwt = await signJWT({ hello: "world" }, secret);

// Verifying and parsing the content of the JWT.
const data = await validateJWT(jwt, secret);
console.log(data);
//Outputs: { hello: "world", iat: 1712516617 }
```

Here is how you can use it with a RSA key pair.

```javascript
import { generateKeyPair, signJWT, validateJWT } from "@cross/jwt";

// Signing the JWT with a RSA private key. You can generate a key pair with the generateKeyPair() helper function.
const { privateKey, publicKey } = await generateKeyPair();
const jwt = await signJWT({ userId: 123 }, privateKey);

// Verifying and parsing the content of the JWT with the public key.
const data = await validateJWT(jwt, publicKey);
console.log(data);
//Outputs: { userId: 123, iat: 1712516617 }
```

Usage with custom options to disable writing the 'iat' (issued at) claim to the JWT payload during creation.

```javascript
import { signJWT, validateJWT } from "@cross/jwt";

const options = {
    setIat: false,
};

const secret = "mySuperSecretAtLeast32CharsLong!";
const jwt = await signJWT({ hello: "world" }, secret, options);

const data = await validateJWT(jwt, secret);
console.log(data);
//Outputs: { hello: "world"}
```

Full example with standard JWT claims. See [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1)

```javascript
import { generateKey, signJWT, validateJWT } from "@cross/jwt";
import type { GenerateKeyOptions, JWTPayload } from "@cross/jwt";

// Optional key generation, you could have a key already.
// HS512 suggests 64 byte secret. Can be omitted with allowInsecureKeyLengths option.
const keyOptions: GenerateKeyOptions = { algorithm: "HS512" };
const secret = "mySuperSecretAtLeast64CharsLongmySuperSecretAtLeast64CharsLong!!";
const key = await generateKey(secret, keyOptions);

// JWT content with standard claims.
const data: JWTPayload = {
    // Standard Claims
    iss: "https://your-api.com", // Issuer
    sub: "user12345", // Subject
    aud: ["clientApp1", "clientApp2"], // Audience (array in this case)
    exp: Math.floor(Date.now() / 1000) + (60 * 60), // Expires in 1 hour
    nbf: Math.floor(Date.now() / 1000), // Not Before (effective now)
    iat: Math.floor(Date.now() / 1000), // Issued At

    // Custom Properties
    userId: 12345,
    roles: ["admin", "editor"],
};

// Sign the JWT
const jwt = await signJWT(data, key);

// Validate the JWT
const validatedData = await validateJWT(jwt, key);
```

Using a unsecured JWT. Cases in which the JWT content is secured by a means other than a signature and/or encryption
contained within the JWT.

```javascript
//Supply false or "none" instead of key for unsecured JWT.
const jwt = await signJWT({ hello: "world" }, false);
const data = await validateJWT(jwt, "none");
```

Generate a RSA key pair with custom Modulus length. (only key generation)

```javascript
const keyPairOptions: GenerateKeyPairOptions = { algorithm: "RS256", modulusLength: 4096 };
const { privateKey, publicKey } = await generateKeyPair(keyPairOptions);
```

Generate a HMAC key with short insecure secret, not recommended. (only key generation)

```javascript
const keyOptions: GenerateKeyOptions = { algorithm: "HS512", allowInsecureKeyLengths: true };
const insecureString = "shortString";
const key = await generateKey(insecureString, keyOptions);
```

Export a key pair to local files. (Experimental, not fully implemented)

```javascript
const { privateKey, publicKey } = await generateKeyPair("RS512");
const fileOptions = {
    privateKey,
    privateFile: "./keys/private_key.pem",
    publicKey,
    publicFile: "./keys/public_key.pem",
};
await exportKeyFiles(fileOptions);
```

## Issues

Issues or questions concerning the library can be raised at the
[github repository](https://github.com/cross-org/jwt/issues) page.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
