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
- **Safe Error Handling:** Optional Result-based error handling with `*Safe` function variants for functional
  programming patterns and type safety.

## Installation

```bash
# For Deno
deno add jsr:@cross/jwt

# For Bun
bunx jsr add @cross/jwt

# For Node.js
npx jsr add @cross/jwt
```

## API

See [docs on jsr.io](https://jsr.io/@cross/jwt/doc) for details.

> **🔧 Safe Error Handling**: Use `*Safe` function variants (e.g., `signJWTSafe`, `validateJWTSafe`) to get
> `Result<T, JWTError>` instead of throwing exceptions. Good for functional programming patterns and type inference. See
> the Result<T, E>-section further down.

**Sign and validate**

- **`signJWT(payload: JWTPayload, key: CryptoKey | string | false, options?: JWTOptions): Promise<string>`**

```javascript
// Create and sign a JWT from a string directly, uses a HS256 key by default.
const jwt = await signJWT({ hello: "world" }, "mySuperSecretAtLeast32CharsLong!");

// Create and sign a JWT from a string directly, using a HS512 algorithm.
const jwt = await signJWT({ hello: "world" }, "Secret my Super Secret at least 64 bytes long for HS512 algorithm!!!!", {
    algorithm: "HS512",
});

// Create and sign a JWT from a CryptoKey (secret based or private key), and opting out of writing IAT claim when signing.
// Using a cryptokey the library will parse algorithm from the supplied key
const jwt = await signJWT({ hello: "world" }, cryptoKey, { setIat: false });

// Create a JWT without signing it, essentially an unsecure JWT.
const jwt = await signJWT({ hello: "world" }, false);
```

- **`validateJWT(jwt: string, key: CryptoKey | string | false, options?: JWTOptions): Promise<JWTPayload>`**

```javascript
// Validate and parse JWT with a string secret directly, uses a HS256 key by default.
const data = await validateJWT(jwt, "mySuperSecretAtLeast32CharsLong!");

// Validate and parse JWT with a string secret directly, uses a HS256 key by default.
const data = await validateJWT(jwt, "Secret my Super Secret at least 64 bytes long for HS512 algorithm!!!!", {
    algorithm: "HS512",
});

// Validate and parse JWT with a CryptoKey (secret based or public key).
// Using a cryptokey the library will parse algorithm from the supplied key.
const data = await validateJWT(jwt, cryptoKey);

// Parsing a unsecure JWT
const data = await validateJWT(jwt, false);
```

- **`unsafeParseJWT(jwt: string): JWTPayload`**

```javascript
// "unsafely" parse a JWT without cryptokey, will return the payload.
const unsafeData = unsafeParseJWT(jwt);
```

- **`unsafeParseJOSEHeader(jwt: string): JOSEHeader`**

```javascript
// "unsafely" parse the JOSE header of a JWT without cryptokey.
const unsafeData = unsafeParseJOSEHeader(jwt);
```

**Helper Functions**

- **`generateKey(keyStr: string, optionsOrAlgorithm?: SupportedKeyAlgorithms | GenerateKeyOptions): Promise<CryptoKey>`**

```javascript
// Generates a HS256 key by default
const key = await generateKey(stringSecret);

// Generates a HS512 key
const key = await generateKey(stringSecret, "HS512");

// Generates a HS256 key by using options object (see GenerateKeyOptions)
const key = await generateKey(stringSecret, { algorithm: "HS512" });
```

- **`generateKeyPair(optionsOrAlgorithm?: SupportedKeyPairAlgorithms | GenerateKeyPairOptions): Promise<CryptoKeyPair>`**

```javascript
// Generates a RS256 key pair by default.
const { privateKey, publicKey } = await generateKeyPair();

// Generates a RS512 key pair.
const { privateKey, publicKey } = await generateKeyPair("RS512");

// Generates a RS512 key pair by using options object (see GenerateKeyPairOptions).
const key = await generateKeyPair({ algorithm: "RS512" });
```

- **`exportPEMKey(key: CryptoKey, filePathOrOptions?: string | ExportPEMKeyOptions): Promise<string>`**
- **`importPEMKey(keyDataOrPath: string, algorithm: SupportedKeyPairAlgorithms): Promise<CryptoKey>`**

```javascript
// Generate and export RS512 keys in PEM-format. (filePath and write mode can be supplied as optional second parameter at export)
const { privateKey, publicKey } = await generateKeyPair("RS512");
await exportPEMKey(privateKey, "./private_key_RS512.pem");
await exportPEMKey(publicKey, "./public_key_RS512.pem");

// Import RS512 keys from PEM-format.
const importedPrivateKey = await importPEMKey("./private_key_RS512.pem", "RS512");
const importedPublicKey = await importPEMKey("./public_key_RS512.pem", "RS512");
```

**Safe Error Handling Functions**

For functional programming patterns or similar use cases you can use the `*Safe` variants that return
`Result<T, JWTError>` instead of throwing exceptions:

- **`signJWTSafe(payload: JWTPayload, key: CryptoKey | string | false, options?: JWTOptions): Promise<Result<string, JWTError>>`**
- **`validateJWTSafe(jwt: string, key: CryptoKey | string | false, options?: JWTOptions): Promise<Result<JWTPayload, JWTError>>`**
- **`unsafeParseJWTSafe(jwt: string): Result<JWTPayload, JWTError>`**
- **`unsafeParseJOSEHeaderSafe(jwt: string): Result<JOSEHeader, JWTError>`**
- **`generateKeySafe(keyStr: string, optionsOrAlgorithm?: SupportedKeyAlgorithms | GenerateKeyOptions): Promise<Result<CryptoKey, JWTError>>`**
- **`generateKeyPairSafe(optionsOrAlgorithm?: SupportedKeyPairAlgorithms | GenerateKeyPairOptions): Promise<Result<CryptoKeyPair, JWTError>>`**
- **`exportPEMKeySafe(key: CryptoKey, filePathOrOptions?: string | ExportPEMKeyOptions): Promise<Result<string, JWTError>>`**
- **`importPEMKeySafe(pem: string, algorithm: SupportedKeyPairAlgorithms): Promise<Result<CryptoKey, JWTError>>`**

```javascript
import { generateKeySafe, signJWTSafe, validateJWTSafe } from "@cross/jwt";

// Using safe functions with Result types
const keyResult = await generateKeySafe("mySecret", "HS256");
if (keyResult.isOk()) {
    const key = keyResult.value;

    const signResult = await signJWTSafe({ hello: "world" }, key);
    if (signResult.isOk()) {
        const jwt = signResult.value;

        const validateResult = await validateJWTSafe(jwt, key);
        if (validateResult.isOk()) {
            console.log("Payload:", validateResult.value);
        } else {
            console.error("Validation failed:", validateResult.errorValue.message);
        }
    } else {
        console.error("Signing failed:", signResult.errorValue.message);
    }
} else {
    console.error("Key generation failed:", keyResult.errorValue.message);
}
```

**GenerateKeyOptions Object**

The `GenerateKeyOptions` object can be used to provide flexibility when generating HMAC keys:

```typescript
/**
 * Options for key generation
 */
interface GenerateKeyOptions {
    //The HMAC algorithm to use for key generation. Defaults to 'HS256'.
    algorithm?: SupportedKeyAlgorithms;
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
    algorithm?: SupportedKeyPairAlgorithms;
    // The desired length of the RSA modulus in bits. Larger values offer greater
    // security, but impact performance. A common default is 2048.
    modulusLength?: number;
    // If true, allows generation of key pairs with modulus length shorter than recommended security guidelines.
    // Use with caution, as shorter lengths are less secure.
    allowInsecureModulusLengths?: boolean;
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
    // A duration string (e.g., "1h", "30m") specifying the expiration time claim relative to the current time.
    // Cannot be used if the `exp` claim is explicitly set in the payload.
    expiresIn?: string;
    //A duration string (e.g., "5m") specifying the "not before" time claim relative to the current time.
    //Cannot be used if the `nbf` claim is explicitly set in the payload.
    notBefore?: string;
    // Additional claims to include as part of the JWT's JOSE header.
    additionalHeaderClaims?: JOSEHeader;
}
```

**Working with JWT Headers**

Some usage scenarios, such as interoperating with OIDC providers that set key identifier (`kid`) header claims in the
JWTs they issue, require JWT header introspection. Similarly, it is sometimes necessary to create tokens with additional
header claims or override existing claims (e.g., the `typ` claim).

The `additionalHeaderClaims` property in the `JWTOptions` provide the means to set/override header claims in tokens
created through `signJWT`. Conversely, the `unsafeParseJOSEHeader` function reads the header claims of a token without
validating it.

## Result<T, E> Type

The safe functions return a `Result<T, E>` type that represents either a success (`Ok<T>`) or failure (`Err<E>`). This
enables functional error handling patterns without exceptions.

### Basic Usage

```javascript
import { validateJWTSafe } from "@cross/jwt";

const result = await validateJWTSafe(jwt, "secret");
if (result.isOk()) {
    console.log("Success:", result.value);
} else {
    console.error("Error:", result.errorValue);
}
```

### Available Methods

**Checking Status:**

- `isOk()` - Returns `true` if the result contains a success value
- `isErr()` - Returns `true` if the result contains an error value

**Accessing Values:**

- `value` - Get the success value (only safe when `isOk()` is true)
- `errorValue` - Get the error value (only safe when `isErr()` is true)
- `unwrapOr(defaultValue)` - Get the success value or return a fallback

**Transforming Values:**

- `map(fn)` - Transform success value, leave errors unchanged
- `flatMap(fn)` - Chain Results (function returns another Result)

## Examples

See [`examples/basic-usage.ts`](./examples/basic-usage.ts) for comprehensive examples including:

- Basic JWT usage with traditional throwing functions
- Error handling with try/catch blocks
- HMAC and RSA key usage
- Unsafe parsing examples

See [`examples/result-type-usage.ts`](./examples/result-type-usage.ts) for examples using the safe Result-based
functions:

- Functional error handling with Result types
- Safe JWT operations without exceptions
- Error handling patterns with `*Safe` function variants

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

Export/import a key pair to and from local files.

```javascript
// Generate and export RS512 keys in PEM-format.
const { privateKey, publicKey } = await generateKeyPair("RS512");
await exportPEMKey(privateKey, "./private_key_RS512.pem");
await exportPEMKey(publicKey, "./public_key_RS512.pem");

// Import RS512 keys from PEM-format.
const importedPrivateKey = await importPEMKey("./private_key_RS512.pem", "RS512");
const importedPublicKey = await importPEMKey("./public_key_RS512.pem", "RS512");
```

## Issues

Issues or questions concerning the library can be raised at the
[github repository](https://github.com/cross-org/jwt/issues) page.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
