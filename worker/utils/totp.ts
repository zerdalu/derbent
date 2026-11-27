import { constantTimeEqual } from "@worker/utils/crypto";

const RFC4648_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buffer: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = "";

  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i] ?? 0;
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += RFC4648_ALPHABET[(value >>> (bits - 5)) & 31] ?? "";
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += RFC4648_ALPHABET[(value << (5 - bits)) & 31] ?? "";
  }
  return output;
}

export function base32Decode(input: string): Uint8Array<ArrayBuffer> {
  const cleanedInput = input.toUpperCase().replace(/\s+/g, "").replace(/=+$/, "");
  const length = cleanedInput.length;
  let bits = 0;
  let value = 0;
  let index = 0;
  const output = new Uint8Array(((length * 5) / 8) | 0);

  for (let i = 0; i < length; i++) {
    const char = cleanedInput[i] ?? "";
    const charIndex = RFC4648_ALPHABET.indexOf(char);
    if (charIndex === -1) {
      throw new Error(`Invalid Base32 character: ${char}`);
    }

    value = (value << 5) | charIndex;
    bits += 5;
    if (bits >= 8) {
      output[index++] = (value >>> (bits - 8)) & 255;
      bits -= 8;
    }
  }
  return output;
}

export async function generateSecret(): Promise<string> {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  return base32Encode(bytes);
}

export async function generateHOTP(secret: string, counter: number): Promise<string> {
  const decodedSecret = base32Decode(secret);
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);

  // Enforce big-endian 64-bit counter layout required by HOTP
  view.setUint32(4, counter, false);

  const key = await crypto.subtle.importKey("raw", decodedSecret, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);

  const signature = await crypto.subtle.sign("HMAC", key, buffer);
  const hmac = new Uint8Array(signature);

  const offset = (hmac[hmac.length - 1] ?? 0) & 0x0f;
  const b0 = hmac[offset] ?? 0;
  const b1 = hmac[offset + 1] ?? 0;
  const b2 = hmac[offset + 2] ?? 0;
  const b3 = hmac[offset + 3] ?? 0;

  const code = ((b0 & 0x7f) << 24) | ((b1 & 0xff) << 16) | ((b2 & 0xff) << 8) | (b3 & 0xff);

  return (code % 1000000).toString().padStart(6, "0");
}

export async function verifyTOTP(secret: string, token: string, window = 1): Promise<boolean> {
  if (!/^[0-9]{6}$/.test(token)) {
    return false;
  }

  try {
    const counter = Math.floor(Date.now() / 30000);
    for (let i = -window; i <= window; i++) {
      const generatedToken = await generateHOTP(secret, counter + i);
      const matches = await constantTimeEqual(generatedToken, token);
      if (matches) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}
