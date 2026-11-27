import type { UserRecord } from "@worker/types/models";

function escapeLikePattern(raw: string): string {
  return raw.replace(/[\\%_]/g, "\\$&");
}

export class UserRepository {
  private readonly db: D1Database;

  constructor(db: D1Database) {
    this.db = db;
  }

  private normalizeEmail(email: string): string {
    return email.trim().toLowerCase();
  }

  async findById(id: string): Promise<UserRecord | null> {
    return await this.db.prepare("SELECT * FROM users WHERE id = ?").bind(id).first<UserRecord>();
  }

  async findByEmailAndApp(email: string, app: string): Promise<UserRecord | null> {
    return await this.db
      .prepare("SELECT * FROM users WHERE email = ? AND app = ?")
      .bind(this.normalizeEmail(email), app)
      .first<UserRecord>();
  }

  async findAllByEmail(email: string): Promise<readonly UserRecord[]> {
    const { results } = await this.db
      .prepare("SELECT * FROM users WHERE email = ?")
      .bind(this.normalizeEmail(email))
      .all<UserRecord>();
    return results || [];
  }

  async findForLogin(email: string, app: string): Promise<UserRecord | null> {
    return await this.db
      .prepare(
        `SELECT * FROM users
         WHERE email = ? AND (app = ? OR app = 'sso')
         ORDER BY app = 'sso' DESC
         LIMIT 1`,
      )
      .bind(this.normalizeEmail(email), app)
      .first<UserRecord>();
  }

  async hasAnyAppAccount(email: string): Promise<boolean> {
    const result = await this.db
      .prepare("SELECT id FROM users WHERE email = ? AND app != 'sso'")
      .bind(this.normalizeEmail(email))
      .first();
    return result !== null;
  }

  async hasAnyVerifiedAppAccount(email: string): Promise<boolean> {
    const result = await this.db
      .prepare("SELECT id FROM users WHERE email = ? AND app != 'sso' AND email_verified = 1")
      .bind(this.normalizeEmail(email))
      .first();
    return result !== null;
  }

  async deleteUnverifiedByEmail(email: string, excludeUserId?: string): Promise<void> {
    const normalized = this.normalizeEmail(email);
    if (excludeUserId) {
      await this.db
        .prepare("DELETE FROM users WHERE email = ? AND email_verified = 0 AND id != ?")
        .bind(normalized, excludeUserId)
        .run();
      return;
    }

    await this.db.prepare("DELETE FROM users WHERE email = ? AND email_verified = 0").bind(normalized).run();
  }

  async create(user: Omit<UserRecord, "created_at" | "updated_at">): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO users (id, app, email, phash, metadata, email_verified, token_version, two_factor_secret, two_factor_enabled, is_locked)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        user.id,
        user.app,
        this.normalizeEmail(user.email),
        user.phash,
        user.metadata,
        user.email_verified,
        user.token_version,
        user.two_factor_secret,
        user.two_factor_enabled,
        user.is_locked,
      )
      .run();
  }

  async setLockedStatus(userId: string, locked: boolean): Promise<void> {
    await this.db
      .prepare("UPDATE users SET is_locked = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
      .bind(locked ? 1 : 0, userId)
      .run();
  }

  async markEmailVerified(userId: string): Promise<void> {
    await this.db
      .prepare("UPDATE users SET email_verified = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
      .bind(userId)
      .run();
  }

  async updatePassword(userId: string, phash: string): Promise<void> {
    await this.db
      .prepare(
        "UPDATE users SET phash = ?, token_version = token_version + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      )
      .bind(phash, userId)
      .run();
  }

  async updatePasswordHash(userId: string, phash: string): Promise<void> {
    await this.db
      .prepare("UPDATE users SET phash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
      .bind(phash, userId)
      .run();
  }

  async incrementTokenVersion(userId: string): Promise<number> {
    const result = await this.db
      .prepare("UPDATE users SET token_version = token_version + 1 WHERE id = ? RETURNING token_version")
      .bind(userId)
      .first<{ token_version: number }>();

    if (!result) {
      throw new Error("User not found during version increment");
    }
    return result.token_version;
  }

  async enableTwoFactor(userId: string, secret: string): Promise<void> {
    await this.db
      .prepare(
        "UPDATE users SET two_factor_secret = ?, two_factor_enabled = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      )
      .bind(secret, userId)
      .run();
  }

  async disableTwoFactor(userId: string): Promise<void> {
    await this.db
      .prepare(
        "UPDATE users SET two_factor_secret = NULL, two_factor_enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      )
      .bind(userId)
      .run();
  }

  async findMany(limit: number, offset: number, search?: string): Promise<readonly UserRecord[]> {
    let query = "SELECT * FROM users";
    const params: (string | number)[] = [];

    if (search) {
      const trimmed = search.trim();
      query += " WHERE email LIKE ? ESCAPE '\\' OR id = ?";
      params.push(`%${escapeLikePattern(trimmed.toLowerCase())}%`, trimmed);
    }

    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?";
    params.push(limit, offset);

    const { results } = await this.db
      .prepare(query)
      .bind(...params)
      .all<UserRecord>();
    return results || [];
  }

  async count(search?: string): Promise<number> {
    let query = "SELECT COUNT(*) as total FROM users";
    const params: (string | number)[] = [];

    if (search) {
      const trimmed = search.trim();
      query += " WHERE email LIKE ? ESCAPE '\\' OR id = ?";
      params.push(`%${escapeLikePattern(trimmed.toLowerCase())}%`, trimmed);
    }

    const result = await this.db
      .prepare(query)
      .bind(...params)
      .first<{ total: number }>();
    return result?.total || 0;
  }

  async countByApp(appId: string): Promise<number> {
    const result = await this.db
      .prepare("SELECT COUNT(*) as total FROM users WHERE app = ?")
      .bind(appId)
      .first<{ total: number }>();
    return result?.total || 0;
  }

  async update(
    id: string,
    data: Partial<Pick<UserRecord, "metadata" | "email_verified" | "app">>,
  ): Promise<UserRecord | null> {
    const updates: string[] = [];
    const params: (string | number)[] = [];

    if (data.metadata !== undefined) {
      updates.push("metadata = ?");
      params.push(data.metadata);
    }
    if (data.email_verified !== undefined) {
      updates.push("email_verified = ?");
      params.push(data.email_verified);
    }
    if (data.app !== undefined) {
      updates.push("app = ?");
      params.push(data.app);
    }

    if (updates.length > 0) {
      params.push(id);
      const query = `UPDATE users SET ${updates.join(", ")}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;
      await this.db
        .prepare(query)
        .bind(...params)
        .run();
    }

    return this.findById(id);
  }

  async delete(id: string): Promise<void> {
    await this.db.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
  }

  async getDashboardStats(): Promise<{
    readonly total: number;
    readonly newLast7Days: number;
    readonly mfaEnabled: number;
    readonly locked: number;
  }> {
    const result = await this.db
      .prepare(
        `SELECT
           COUNT(*) as total,
           SUM(CASE WHEN created_at >= datetime('now', '-7 days') THEN 1 ELSE 0 END) as newLast7Days,
           SUM(CASE WHEN two_factor_enabled = 1 THEN 1 ELSE 0 END) as mfaEnabled,
           SUM(CASE WHEN is_locked = 1 THEN 1 ELSE 0 END) as locked
         FROM users`,
      )
      .first<{ total: number; newLast7Days: number; mfaEnabled: number; locked: number }>();

    return {
      total: result?.total || 0,
      newLast7Days: result?.newLast7Days || 0,
      mfaEnabled: result?.mfaEnabled || 0,
      locked: result?.locked || 0,
    };
  }

  async getSignupsTrend(days: number): Promise<readonly { readonly date: string; readonly count: number }[]> {
    const safeDays = Math.max(1, Math.trunc(days));
    const { results } = await this.db
      .prepare(
        `SELECT
           DATE(created_at) as date,
           COUNT(*) as count
         FROM users
         WHERE created_at >= date('now', ?)
         GROUP BY DATE(created_at)
         ORDER BY date ASC`,
      )
      .bind(`-${safeDays} days`)
      .all<{ date: string; count: number }>();

    return results || [];
  }
}
