import { timingSafeEqual } from "node:crypto";
import * as v from "valibot";

const EncryptedPayloadSchema = v.object({
  iv: v.string(),
  data: v.string(),
});

const MAX_WORKERS_PBKDF2_ITERATIONS = 100000;

/**
 * Compares two strings in constant time to prevent timing side-channel attacks.
 * Both strings are pre-hashed with SHA-256 to guarantee identical byte lengths.
 */
export async function constantTimeEqual(a: string, b: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const hashA = await crypto.subtle.digest("SHA-256", encoder.encode(a));
  const hashB = await crypto.subtle.digest("SHA-256", encoder.encode(b));
  const bufA = new Uint8Array(hashA);
  const bufB = new Uint8Array(hashB);

  return timingSafeEqual(bufA, bufB);
}

export async function hashPassword(password: string, iterations: number): Promise<string> {
  const effectiveIterations = Math.min(Math.max(Math.trunc(iterations), 10000), MAX_WORKERS_PBKDF2_ITERATIONS);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"],
  );

  const hashBuffer = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: effectiveIterations,
      hash: "SHA-256",
    },
    keyMaterial,
    256,
  );

  const saltBase64 = bufferToBase64(salt);
  const hashBase64 = bufferToBase64(hashBuffer);

  return `pbkdf2_sha256:${effectiveIterations}:${saltBase64}:${hashBase64}`;
}

export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  const parts = storedHash.split(":");
  if (parts.length !== 4 || parts[0] !== "pbkdf2_sha256") {
    return false;
  }

  const iterations = Number.parseInt(parts[1] ?? "0", 10);
  if (!Number.isSafeInteger(iterations) || iterations <= 0 || iterations > MAX_WORKERS_PBKDF2_ITERATIONS) {
    return false;
  }

  const saltBase64 = parts[2] ?? "";
  const hashBase64 = parts[3] ?? "";
  if (!saltBase64 || !hashBase64) {
    return false;
  }

  let salt: Uint8Array<ArrayBuffer>;
  try {
    salt = base64ToBuffer(saltBase64);
  } catch {
    return false;
  }

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"],
  );

  const hashBuffer = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    256,
  );

  const computedHashBase64 = bufferToBase64(hashBuffer);
  return constantTimeEqual(computedHashBase64, hashBase64);
}

export function needsRehash(storedHash: string, targetIterations: number): boolean {
  const parts = storedHash.split(":");
  if (parts.length !== 4 || parts[0] !== "pbkdf2_sha256") {
    return true;
  }

  const iterations = Number.parseInt(parts[1] ?? "0", 10);
  const clampedTarget = Math.min(targetIterations, MAX_WORKERS_PBKDF2_ITERATIONS);
  return !Number.isSafeInteger(iterations) || iterations < clampedTarget;
}

export function bufferToBase64(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    const byte = bytes[i];
    if (byte !== undefined) {
      binary += String.fromCharCode(byte);
    }
  }
  return btoa(binary);
}

export function base64ToBuffer(b64: string): Uint8Array<ArrayBuffer> {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function encodeBase64UrlUtf8(plainText: string): string {
  const bytes = new TextEncoder().encode(plainText);
  return bufferToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function decodeBase64UrlUtf8(encoded: string): string {
  const normalized = encoded.replace(/-/g, "+").replace(/_/g, "/");
  const paddingLength = (4 - (normalized.length % 4)) % 4;
  const padded = normalized + "=".repeat(paddingLength);
  const bytes = base64ToBuffer(padded);
  return new TextDecoder().decode(bytes);
}

async function getAesKey(secretKey: string): Promise<CryptoKey> {
  const keyMaterial = new TextEncoder().encode(secretKey);
  const hash = await crypto.subtle.digest("SHA-256", keyMaterial);
  return crypto.subtle.importKey("raw", hash, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function encryptKV(plainText: string, secretKey: string): Promise<string> {
  const key = await getAesKey(secretKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encodedText = new TextEncoder().encode(plainText);

  const cipherBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encodedText);

  return JSON.stringify({
    iv: bufferToBase64(iv),
    data: bufferToBase64(cipherBuffer),
  });
}

export async function decryptKV(encryptedJson: string, secretKey: string): Promise<string> {
  let rawParsed: unknown;
  try {
    rawParsed = JSON.parse(encryptedJson);
  } catch {
    throw new Error("Invalid JSON format for encrypted string");
  }

  const parsed = v.safeParse(EncryptedPayloadSchema, rawParsed);
  if (!parsed.success) {
    throw new Error("Invalid encrypted JSON structure");
  }

  const iv = base64ToBuffer(parsed.output.iv);
  const cipherData = base64ToBuffer(parsed.output.data);
  const key = await getAesKey(secretKey);

  const decryptedBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipherData);
  return new TextDecoder().decode(decryptedBuffer);
}
