# WIP

Work in progress

## @cross/jwt

A versatile JSON Web Token (JWT) library for Deno, Bun, and Node.js providing cross-runtime compatibility.

Part of the @cross suite - check out our growing collection of cross-runtime tools at
[github.com/cross-org](https://github.com/cross-org).

## Features

- **HMAC Signing and Verification:** Securely sign and verify JWTs using HMAC with SHA-256.
- **RSA Signing and Verification:** Employ robust RSA (RSASSA-PKCS1-v1_5) signatures for enhanced JWT security.
- **Simple API:** Intuitive functions for generating, parsing, signing, and verifying JWTs.
- **Key Generation:** Conveniently create HMAC secret keys and RSA key pairs.
- **Cross-Runtime Support:** Seamlessly work across Deno, Bun, and Node.js environments.

## Installation

```bash
#For Deno
deno add @cross/jwt

#For Bun
bunx jsr add @cross/jwt

#For Node.js
npx jsr add @cross/jwt
```

## Usage

**HMAC Example**

The most common way to sign and verify JWTs

```javascript
import { createJWT, generateKey, parseJWT } from "@cross/jwt";

const secret = "mySuperSecretAtLeast32CharsLongmySuperSecretAtLeast32CharsLong";
const key = await generateKey(secret);

const jwt = await createJWT(key, { hello: "world" });
const data = await parseJWT(key, jwt);

console.log(data); // Outputs: { hello: "world" }
```

**RSA Example**

```javascript
import { createJWT, generateKeyPair, parseJWT } from "@cross/jwt";

const { privateKey, publicKey } = await generateKeyPair();

const jwt = await createJWT(privateKey, { userId: 123 });
const data = await parseJWT(publicKey, jwt);

console.log(data); // Outputs: { userId: 123 }
```

## Issues

Issues or questions concerning the library can be raised at the
[github repository](https://github.com/cross-org/jwt/issues) page.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
