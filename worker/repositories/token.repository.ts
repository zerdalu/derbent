import * as v from "valibot";

const VersionedUserTokenSchema = v.object({
  userId: v.string(),
  tokenVersion: v.number(),
});

export type VersionedUserToken = v.InferOutput<typeof VersionedUserTokenSchema>;

const TwoFactorLoginPayloadSchema = v.object({
  userId: v.string(),
  appId: v.string(),
  ip: v.string(),
  userAgent: v.string(),
  tokenVersion: v.number(),
  attempts: v.optional(v.number(), 0),
});

export type TwoFactorLoginPayload = v.InferInput<typeof TwoFactorLoginPayloadSchema>;
export type TwoFactorLoginRecord = v.InferOutput<typeof TwoFactorLoginPayloadSchema>;

function parseVersionedUserToken(raw: string | null): VersionedUserToken | null {
  if (!raw) {
    return null;
  }

  try {
    const parsed: unknown = JSON.parse(raw);
    const result = v.safeParse(VersionedUserTokenSchema, parsed);
    return result.success ? result.output : null;
  } catch {
    return null;
  }
}

function parseTwoFactorLoginRecord(raw: string | null, attempts: number): TwoFactorLoginRecord | null {
  if (!raw) {
    return null;
  }

  try {
    const parsed: unknown = JSON.parse(raw);
    const result = v.safeParse(TwoFactorLoginPayloadSchema, parsed);
    if (!result.success) {
      return null;
    }
    return {
      ...result.output,
      attempts: Math.max(result.output.attempts, attempts),
    };
  } catch {
    return null;
  }
}

export class TokenRepository {
  private readonly db: D1Database;

  constructor(db: D1Database) {
    this.db = db;
  }

  private async putToken(key: string, payload: string, ttlSeconds: number, attempts = 0): Promise<void> {
    const expiresAt = Date.now() + ttlSeconds * 1000;
    await this.db
      .prepare(
        `INSERT INTO auth_tokens (key, payload, attempts, expires_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET
           payload = excluded.payload,
           attempts = excluded.attempts,
           expires_at = excluded.expires_at`,
      )
      .bind(key, payload, attempts, expiresAt)
      .run();
  }

  private async getTokenRow(key: string): Promise<{ readonly payload: string; readonly attempts: number } | null> {
    return await this.db
      .prepare("SELECT payload, attempts FROM auth_tokens WHERE key = ? AND expires_at > ?")
      .bind(key, Date.now())
      .first<{ payload: string; attempts: number }>();
  }

  private async consumeTokenRow(key: string): Promise<{ readonly payload: string; readonly attempts: number } | null> {
    return await this.db
      .prepare("DELETE FROM auth_tokens WHERE key = ? AND expires_at > ? RETURNING payload, attempts")
      .bind(key, Date.now())
      .first<{ payload: string; attempts: number }>();
  }

  private async deleteToken(key: string): Promise<void> {
    await this.db.prepare("DELETE FROM auth_tokens WHERE key = ?").bind(key).run();
  }

  private async hasActiveToken(key: string): Promise<boolean> {
    const row = await this.db
      .prepare("SELECT 1 as present FROM auth_tokens WHERE key = ? AND expires_at > ?")
      .bind(key, Date.now())
      .first<{ present: number }>();
    return row !== null;
  }

  async saveEmailVerificationToken(
    token: string,
    userId: string,
    tokenVersion: number,
    ttlSeconds = 900,
  ): Promise<void> {
    await this.putToken(`verify_email:${token}`, JSON.stringify({ userId, tokenVersion }), ttlSeconds);
  }

  async getVerifyTokenData(token: string): Promise<VersionedUserToken | null> {
    const row = await this.getTokenRow(`verify_email:${token}`);
    return parseVersionedUserToken(row?.payload ?? null);
  }

  async consumeVerifyToken(token: string): Promise<VersionedUserToken | null> {
    const row = await this.consumeTokenRow(`verify_email:${token}`);
    return parseVersionedUserToken(row?.payload ?? null);
  }

  async deleteEmailVerificationToken(token: string): Promise<void> {
    await this.deleteToken(`verify_email:${token}`);
  }

  async isVerificationEmailOnCooldown(userId: string): Promise<boolean> {
    return this.hasActiveToken(`verify_email_cd:${userId}`);
  }

  async setVerificationEmailCooldown(userId: string, ttlSeconds = 60): Promise<void> {
    await this.putToken(`verify_email_cd:${userId}`, "1", ttlSeconds);
  }

  async savePasswordResetToken(token: string, userId: string, tokenVersion: number, ttlSeconds = 900): Promise<void> {
    await this.putToken(`reset_pwd:${token}`, JSON.stringify({ userId, tokenVersion }), ttlSeconds);
  }

  async getResetTokenData(token: string): Promise<VersionedUserToken | null> {
    const row = await this.getTokenRow(`reset_pwd:${token}`);
    return parseVersionedUserToken(row?.payload ?? null);
  }

  async consumeResetToken(token: string): Promise<VersionedUserToken | null> {
    const row = await this.consumeTokenRow(`reset_pwd:${token}`);
    return parseVersionedUserToken(row?.payload ?? null);
  }

  async deletePasswordResetToken(token: string): Promise<void> {
    await this.deleteToken(`reset_pwd:${token}`);
  }

  async isPasswordResetOnCooldown(userId: string): Promise<boolean> {
    return this.hasActiveToken(`reset_pwd_cd:${userId}`);
  }

  async setPasswordResetCooldown(userId: string, ttlSeconds = 60): Promise<void> {
    await this.putToken(`reset_pwd_cd:${userId}`, "1", ttlSeconds);
  }

  async saveMagicLinkToken(token: string, userId: string, tokenVersion: number, ttlSeconds = 900): Promise<void> {
    await this.putToken(`magic_link:${token}`, JSON.stringify({ userId, tokenVersion }), ttlSeconds);
  }

  async getMagicLinkTokenData(token: string): Promise<VersionedUserToken | null> {
    const row = await this.getTokenRow(`magic_link:${token}`);
    return parseVersionedUserToken(row?.payload ?? null);
  }

  async consumeMagicLinkToken(token: string): Promise<VersionedUserToken | null> {
    const row = await this.consumeTokenRow(`magic_link:${token}`);
    return parseVersionedUserToken(row?.payload ?? null);
  }

  async deleteMagicLinkToken(token: string): Promise<void> {
    await this.deleteToken(`magic_link:${token}`);
  }

  async isMagicLinkOnCooldown(userId: string): Promise<boolean> {
    return this.hasActiveToken(`magic_link_cd:${userId}`);
  }

  async setMagicLinkCooldown(userId: string, ttlSeconds = 60): Promise<void> {
    await this.putToken(`magic_link_cd:${userId}`, "1", ttlSeconds);
  }

  async hasLoggedIpChangeNotice(sessionId: string, ip: string): Promise<boolean> {
    return this.hasActiveToken(`ip_notice:${sessionId}:${ip.trim()}`);
  }

  async markIpChangeNoticeLogged(sessionId: string, ip: string, ttlSeconds = 86400): Promise<void> {
    await this.putToken(`ip_notice:${sessionId}:${ip.trim()}`, "1", ttlSeconds);
  }

  async saveTwoFactorSetupSecret(userId: string, secret: string, ttlSeconds = 900): Promise<void> {
    await this.putToken(`2fa_setup:${userId}`, secret, ttlSeconds);
  }

  async getTwoFactorSetupSecret(userId: string): Promise<string | null> {
    const row = await this.getTokenRow(`2fa_setup:${userId}`);
    return row?.payload ?? null;
  }

  async deleteTwoFactorSetupSecret(userId: string): Promise<void> {
    await this.deleteToken(`2fa_setup:${userId}`);
  }

  async saveTwoFactorLoginToken(token: string, data: TwoFactorLoginPayload, ttlSeconds = 300): Promise<void> {
    const attempts = data.attempts ?? 0;
    await this.putToken(`2fa_login:${token}`, JSON.stringify({ ...data, attempts }), ttlSeconds, attempts);
  }

  async getTwoFactorLoginData(token: string): Promise<TwoFactorLoginRecord | null> {
    const row = await this.getTokenRow(`2fa_login:${token}`);
    if (!row) {
      return null;
    }
    return parseTwoFactorLoginRecord(row.payload, row.attempts);
  }

  async consumeTwoFactorLoginToken(token: string): Promise<TwoFactorLoginRecord | null> {
    const row = await this.consumeTokenRow(`2fa_login:${token}`);
    if (!row) {
      return null;
    }
    return parseTwoFactorLoginRecord(row.payload, row.attempts);
  }

  async incrementTwoFactorLoginAttempts(token: string, ttlSeconds = 300): Promise<number> {
    const now = Date.now();
    const expiresAt = now + ttlSeconds * 1000;
    const row = await this.db
      .prepare(
        `UPDATE auth_tokens
         SET attempts = attempts + 1, expires_at = ?
         WHERE key = ? AND expires_at > ?
         RETURNING attempts`,
      )
      .bind(expiresAt, `2fa_login:${token}`, now)
      .first<{ attempts: number }>();

    return row?.attempts ?? 1;
  }

  async deleteTwoFactorLoginToken(token: string): Promise<void> {
    await this.deleteToken(`2fa_login:${token}`);
  }

  async getTotpActionAttempts(userId: string): Promise<number> {
    const row = await this.db
      .prepare("SELECT count FROM auth_counters WHERE key = ? AND expires_at > ?")
      .bind(`totp_attempts:${userId}`, Date.now())
      .first<{ count: number }>();

    return row && Number.isSafeInteger(row.count) && row.count > 0 ? row.count : 0;
  }

  async incrementTotpActionAttempts(userId: string, ttlSeconds = 300): Promise<number> {
    const now = Date.now();
    const expiresAt = now + ttlSeconds * 1000;
    const row = await this.db
      .prepare(
        `INSERT INTO auth_counters (key, count, expires_at)
         VALUES (?, 1, ?)
         ON CONFLICT(key) DO UPDATE SET
           count = CASE WHEN auth_counters.expires_at <= ? THEN 1 ELSE auth_counters.count + 1 END,
           expires_at = excluded.expires_at
         RETURNING count`,
      )
      .bind(`totp_attempts:${userId}`, expiresAt, now)
      .first<{ count: number }>();

    return row?.count ?? 1;
  }

  async clearTotpActionAttempts(userId: string): Promise<void> {
    await this.db.prepare("DELETE FROM auth_counters WHERE key = ?").bind(`totp_attempts:${userId}`).run();
  }

  /**
   * Atomically claims a TOTP code for single-use replay protection.
   * Returns true if the code was newly claimed, or false if already active in the replay window.
   */
  async tryMarkTotpCodeUsed(userId: string, code: string, ttlSeconds = 90): Promise<boolean> {
    const now = Date.now();
    const expiresAt = now + ttlSeconds * 1000;
    const row = await this.db
      .prepare(
        `INSERT INTO auth_tokens (key, payload, attempts, expires_at)
         VALUES (?, '1', 0, ?)
         ON CONFLICT(key) DO UPDATE SET expires_at = excluded.expires_at
         WHERE auth_tokens.expires_at <= ?
         RETURNING key`,
      )
      .bind(`totp_used:${userId}:${code}`, expiresAt, now)
      .first<{ key: string }>();

    return row !== null;
  }

  async isTotpCodeUsed(userId: string, code: string): Promise<boolean> {
    return this.hasActiveToken(`totp_used:${userId}:${code}`);
  }

  async markTotpCodeUsed(userId: string, code: string, ttlSeconds = 90): Promise<void> {
    await this.putToken(`totp_used:${userId}:${code}`, "1", ttlSeconds);
  }

  async pruneExpired(): Promise<number> {
    try {
      const result = await this.db.prepare("DELETE FROM auth_tokens WHERE expires_at <= ?").bind(Date.now()).run();
      return result.meta.changes;
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("[TokenRepo] Failed to prune expired tokens:", error.message);
      }
      return 0;
    }
  }
}
