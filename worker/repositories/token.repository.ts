import * as v from "valibot";

const TwoFactorLoginPayloadSchema = v.object({
  userId: v.string(),
  appId: v.string(),
  ip: v.string(),
  userAgent: v.string(),
  attempts: v.optional(v.number(), 0),
});

export type TwoFactorLoginPayload = v.InferInput<typeof TwoFactorLoginPayloadSchema>;
export type TwoFactorLoginRecord = v.InferOutput<typeof TwoFactorLoginPayloadSchema>;

export class TokenRepository {
  private readonly kv: KVNamespace;

  constructor(kv: KVNamespace) {
    this.kv = kv;
  }

  async saveEmailVerificationToken(token: string, userId: string, ttlSeconds = 900): Promise<void> {
    await this.kv.put(`verify_email:${token}`, userId, { expirationTtl: ttlSeconds });
  }

  async getUserIdFromVerifyToken(token: string): Promise<string | null> {
    return await this.kv.get(`verify_email:${token}`);
  }

  async deleteEmailVerificationToken(token: string): Promise<void> {
    await this.kv.delete(`verify_email:${token}`);
  }

  async isVerificationEmailOnCooldown(userId: string): Promise<boolean> {
    const val = await this.kv.get(`verify_email_cd:${userId}`);
    return val !== null;
  }

  async setVerificationEmailCooldown(userId: string, ttlSeconds = 60): Promise<void> {
    await this.kv.put(`verify_email_cd:${userId}`, "1", { expirationTtl: ttlSeconds });
  }

  async savePasswordResetToken(token: string, userId: string, ttlSeconds = 900): Promise<void> {
    await this.kv.put(`reset_pwd:${token}`, userId, { expirationTtl: ttlSeconds });
  }

  async getUserIdFromResetToken(token: string): Promise<string | null> {
    return await this.kv.get(`reset_pwd:${token}`);
  }

  async deletePasswordResetToken(token: string): Promise<void> {
    await this.kv.delete(`reset_pwd:${token}`);
  }

  async saveMagicLinkToken(token: string, userId: string, ttlSeconds = 900): Promise<void> {
    await this.kv.put(`magic_link:${token}`, userId, { expirationTtl: ttlSeconds });
  }

  async getUserIdFromMagicLinkToken(token: string): Promise<string | null> {
    return await this.kv.get(`magic_link:${token}`);
  }

  async deleteMagicLinkToken(token: string): Promise<void> {
    await this.kv.delete(`magic_link:${token}`);
  }

  async saveTwoFactorSetupSecret(userId: string, secret: string, ttlSeconds = 900): Promise<void> {
    await this.kv.put(`2fa_setup:${userId}`, secret, { expirationTtl: ttlSeconds });
  }

  async getTwoFactorSetupSecret(userId: string): Promise<string | null> {
    return await this.kv.get(`2fa_setup:${userId}`);
  }

  async deleteTwoFactorSetupSecret(userId: string): Promise<void> {
    await this.kv.delete(`2fa_setup:${userId}`);
  }

  async saveTwoFactorLoginToken(token: string, data: TwoFactorLoginPayload, ttlSeconds = 300): Promise<void> {
    await this.kv.put(`2fa_login:${token}`, JSON.stringify({ ...data, attempts: data.attempts ?? 0 }), {
      expirationTtl: ttlSeconds,
    });
  }

  async getTwoFactorLoginData(token: string): Promise<TwoFactorLoginRecord | null> {
    const val = await this.kv.get(`2fa_login:${token}`);
    if (!val) {
      return null;
    }

    try {
      const parsed: unknown = JSON.parse(val);
      const result = v.safeParse(TwoFactorLoginPayloadSchema, parsed);
      return result.success ? result.output : null;
    } catch {
      return null;
    }
  }

  async incrementTwoFactorLoginAttempts(token: string, data: TwoFactorLoginRecord, ttlSeconds = 300): Promise<number> {
    const nextAttempts = data.attempts + 1;
    await this.kv.put(`2fa_login:${token}`, JSON.stringify({ ...data, attempts: nextAttempts }), {
      expirationTtl: ttlSeconds,
    });
    return nextAttempts;
  }

  async deleteTwoFactorLoginToken(token: string): Promise<void> {
    await this.kv.delete(`2fa_login:${token}`);
  }

  async getTotpActionAttempts(userId: string): Promise<number> {
    const val = await this.kv.get(`totp_attempts:${userId}`);
    if (!val) {
      return 0;
    }
    const parsed = Number.parseInt(val, 10);
    return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : 0;
  }

  async incrementTotpActionAttempts(userId: string, ttlSeconds = 300): Promise<number> {
    const nextAttempts = (await this.getTotpActionAttempts(userId)) + 1;
    await this.kv.put(`totp_attempts:${userId}`, String(nextAttempts), { expirationTtl: ttlSeconds });
    return nextAttempts;
  }

  async clearTotpActionAttempts(userId: string): Promise<void> {
    await this.kv.delete(`totp_attempts:${userId}`);
  }

  async isTotpCodeUsed(userId: string, code: string): Promise<boolean> {
    const val = await this.kv.get(`totp_used:${userId}:${code}`);
    return val !== null;
  }

  async markTotpCodeUsed(userId: string, code: string, ttlSeconds = 90): Promise<void> {
    await this.kv.put(`totp_used:${userId}:${code}`, "1", { expirationTtl: ttlSeconds });
  }
}
