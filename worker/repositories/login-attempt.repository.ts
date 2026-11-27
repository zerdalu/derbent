export interface LoginAttemptCounts {
  readonly ipAttempts: number;
  readonly emailAttempts: number;
}

export class LoginAttemptRepository {
  private readonly kv: KVNamespace;

  constructor(kv: KVNamespace) {
    this.kv = kv;
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

  private parseCount(val: string | null): number {
    if (!val) {
      return 0;
    }
    const parsed = Number.parseInt(val, 10);
    return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : 0;
  }

  async getAttempts(email: string, ip: string): Promise<number> {
    const val = await this.kv.get(this.getKey(email, ip));
    return this.parseCount(val);
  }

  async getEmailAttempts(email: string): Promise<number> {
    const val = await this.kv.get(this.getEmailKey(email));
    return this.parseCount(val);
  }

  async getAttemptCounts(email: string, ip: string): Promise<LoginAttemptCounts> {
    const [ipAttempts, emailAttempts] = await Promise.all([this.getAttempts(email, ip), this.getEmailAttempts(email)]);
    return { ipAttempts, emailAttempts };
  }

  async incrementAttempts(email: string, ip: string, ttlSeconds = 900): Promise<LoginAttemptCounts> {
    const { ipAttempts, emailAttempts } = await this.getAttemptCounts(email, ip);
    const nextIpAttempts = ipAttempts + 1;
    const nextEmailAttempts = emailAttempts + 1;

    await Promise.all([
      this.kv.put(this.getKey(email, ip), String(nextIpAttempts), { expirationTtl: ttlSeconds }),
      this.kv.put(this.getEmailKey(email), String(nextEmailAttempts), { expirationTtl: ttlSeconds }),
    ]);

    return {
      ipAttempts: nextIpAttempts,
      emailAttempts: nextEmailAttempts,
    };
  }

  async clearAttempts(email: string, ip: string): Promise<void> {
    await Promise.all([this.kv.delete(this.getKey(email, ip)), this.kv.delete(this.getEmailKey(email))]);
  }
}
