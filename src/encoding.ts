//encoding.ts
export { decodeBase64Url, encodeBase64Url } from "@std/encoding/base64url";

// Encodes a string to Uint8Array using TextEncoder.
export function textEncode(data: string): Uint8Array {
    return new TextEncoder().encode(data);
}

// Decodes a Uint8Array to string using TextDecoder.
export function textDecode(data: Uint8Array): string {
    return new TextDecoder().decode(data);
}
