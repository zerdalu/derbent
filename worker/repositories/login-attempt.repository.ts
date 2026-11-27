export interface LoginAttemptCounts {
  readonly ipAttempts: number;
  readonly emailAttempts: number;
}

export class LoginAttemptRepository {
  private readonly db: D1Database;

  constructor(db: D1Database) {
    this.db = db;
  }

  private getKey(email: string, ip: string): string {
    const normalizedEmail = email.toLowerCase().trim();
    const normalizedIp = ip.trim();
    return `login_attempt:${normalizedEmail}:${normalizedIp}`;
  }

  private getEmailKey(email: string): string {
    const normalizedEmail = email.toLowerCase().trim();
    return `login_attempt_email:${normalizedEmail}`;
  }

  private async readActiveCount(key: string, now: number): Promise<number> {
    const row = await this.db
      .prepare("SELECT count FROM auth_counters WHERE key = ? AND expires_at > ?")
      .bind(key, now)
      .first<{ count: number }>();

    return row && Number.isSafeInteger(row.count) && row.count > 0 ? row.count : 0;
  }

  private async incrementKey(key: string, now: number, expiresAt: number): Promise<number> {
    const row = await this.db
      .prepare(
        `INSERT INTO auth_counters (key, count, expires_at)
         VALUES (?, 1, ?)
         ON CONFLICT(key) DO UPDATE SET
           count = CASE WHEN auth_counters.expires_at <= ? THEN 1 ELSE auth_counters.count + 1 END,
           expires_at = excluded.expires_at
         RETURNING count`,
      )
      .bind(key, expiresAt, now)
      .first<{ count: number }>();

    return row?.count ?? 1;
  }

  async getAttempts(email: string, ip: string): Promise<number> {
    return this.readActiveCount(this.getKey(email, ip), Date.now());
  }

  async getEmailAttempts(email: string): Promise<number> {
    return this.readActiveCount(this.getEmailKey(email), Date.now());
  }

  async getAttemptCounts(email: string, ip: string): Promise<LoginAttemptCounts> {
    const now = Date.now();
    const [ipAttempts, emailAttempts] = await Promise.all([
      this.readActiveCount(this.getKey(email, ip), now),
      this.readActiveCount(this.getEmailKey(email), now),
    ]);
    return { ipAttempts, emailAttempts };
  }

  async incrementAttempts(email: string, ip: string, ttlSeconds = 900): Promise<LoginAttemptCounts> {
    const now = Date.now();
    const expiresAt = now + ttlSeconds * 1000;
    const [ipAttempts, emailAttempts] = await Promise.all([
      this.incrementKey(this.getKey(email, ip), now, expiresAt),
      this.incrementKey(this.getEmailKey(email), now, expiresAt),
    ]);

    return { ipAttempts, emailAttempts };
  }

  async clearAttempts(email: string, ip: string): Promise<void> {
    await this.db
      .prepare("DELETE FROM auth_counters WHERE key IN (?, ?)")
      .bind(this.getKey(email, ip), this.getEmailKey(email))
      .run();
  }

  async pruneExpired(): Promise<number> {
    try {
      const result = await this.db.prepare("DELETE FROM auth_counters WHERE expires_at <= ?").bind(Date.now()).run();
      return result.meta.changes;
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("[LoginAttemptRepo] Failed to prune expired counters:", error.message);
      }
      return 0;
    }
  }
}
