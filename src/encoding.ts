//encoding.ts
/**
 * Re-exports base64url encoding and decoding functions JSR standard library.
 */
export { decodeBase64Url, encodeBase64Url } from "@std/encoding/base64url";
export { encodeBase64 } from "@std/encoding/base64";

/**
 * Encodes a string into a Uint8Array representation using the TextEncoder API.
 *
 * @param data - The string to be encoded.
 * @returns A Uint8Array containing the encoded string data.
 */
export function textEncode(data: string): Uint8Array {
    return new TextEncoder().encode(data);
}

/**
 * Decodes a Uint8Array into a string using the TextDecoder API.
 *
 * @param data - The Uint8Array containing encoded string data.
 * @returns The decoded string.
 */
export function textDecode(data: Uint8Array): string {
    return new TextDecoder().decode(data);
}
