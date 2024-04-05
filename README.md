## @cross/jwt

[![JSR Version](https://jsr.io/badges/@cross/jwt)](https://jsr.io/@cross/jwt)
[![JSR Score](https://jsr.io/badges/@cross/jwt/score)](https://jsr.io/@cross/jwt/score)

A versatile JSON Web Token (JWT) library for Deno, Bun, and Node.js providing cross-runtime compatibility.

Part of the @cross suite - check out our growing collection of cross-runtime tools at
[github.com/cross-org](https://github.com/cross-org).

## Features

- **Secure Cryptography:** Supports HMAC (SHA-256) and RSA (RSASSA-PKCS1-v1_5) signing algorithms for robust JWT
  protection.
- **Cross-Platform:** Functions seamlessly across Deno, Bun, and Node.js environments.
- **Intuitive API:** Provides simple-to-use functions for JWT creation, parsing, signing, and verification.
- **Key Management:** Includes helpers for generating HMAC secret keys and RSA key pairs.

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

**Helper Functions**

- **`generateKey(keyStr: string, options?: SupportedGenerateKeyAlgorithms | Options): Promise<CryptoKey>`**
  - Generates an HMAC key from a provided secret string.
  - **`keyStr`**: The secret string to use as the key.
  - **`options`**: Can be one of the following:
    - **`SupportedGenerateKeyAlgorithms`** (string): "HS256", "HS384", or "HS512"
    - OR
    - **GenerateKeyOptions Object**
      - `algorithm` (optional): "HS256", "HS384" or "HS512"
      - `allowInsecureKeyLengths` (optional): If true, bypasses the minimum recommended secret length requirement. Use
        with caution, as shorter secret strings weaken security.

- **`generateKeyPair(options?: KeyPairOptions): Promise<CryptoKeyPair>`**
  - Generates an RSA key pair (public and private keys).
  - **`options`**: Can be one of the following:
    - **`SupportedGenerateKeyPairAlgorithms`** (string): For example "RS256" or "ES256" See table below. Defaults to
      "RS256".
    - OR
    - **GenerateKeyPairOptions Object**
      - `algorithm` (optional): For example "RS256" or "ES256" See table below. Defaults to "RS256".
      - `modulusLength` (optional): Modulus length for RSA keys, common values are 2048, 3072 and 4096. Defaults
        to 2048.

- **`signJWT(payload: JWTPayload, key: CryptoKey | string | Options, options?: Options): Promise<string>`**
  - Creates a signed JWT.
  - **`payload`**: The data to include in the JWT.
  - **`key`**: Can be one of the following:
    - HMAC key (`CryptoKey`)
    - RSA public key (`CryptoKey`)
    - String to generate an HMAC key
  - **`options`** (optional): See `JWTOptions` below.

- **`validateJWT(jwt: string, key: CryptoKey | string, options?: Options): Promise<JWTPayload>`**
  - Verifies and parses a JWT.
  - **`jwt`**: The encoded JWT string.
  - **`key`**: Can be one of the following:
    - HMAC key (`CryptoKey`)
    - RSA public key (`CryptoKey`)
    - String to generate an HMAC key
  - **`options`:** (optional) See `JWTOptions` below.

**Options Object**

The `JWTOptions` object can be used to provide flexibility when creating JWTs:

```typescript
/**
 * Options for customizing JWT creation and parsing behavior.
 */
interface JWTOptions {
    // If true, the 'iat' (issued at) claim will be automatically added to the JWT payload during creation.
    setIat?: boolean;
    // If true, the 'exp' (expiration time) claim will be validated during creation and parsing.
    validateExp?: boolean;
    // If true, the 'nbf' (not before) claim will be validated during creation and parsing.
    validateNbf?: boolean;
    //The number of seconds of leeway to allow for clock skew during expiration validation. (Default: 60)
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
//Outputs: { hello: "world" }
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
//Outputs: { userId: 123 }
```

Usage with custom options to enable writing the 'iat' (issued at) claim to the JWT payload during creation.

```javascript
import { signJWT, validateJWT } from "@cross/jwt";

const options = {
    setIat: true,
};

const secret = "mySuperSecretAtLeast32CharsLong!";
const jwt = await signJWT({ hello: "world" }, secret, options);

const data = await validateJWT(jwt, secret);
console.log(data);
//Outputs: { hello: "world", iat: 1711977982}
```

## Issues

Issues or questions concerning the library can be raised at the
[github repository](https://github.com/cross-org/jwt/issues) page.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
