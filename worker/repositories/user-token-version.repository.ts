export class UserTokenVersionRepository {
  private readonly kv: KVNamespace;

  constructor(kv: KVNamespace) {
    this.kv = kv;
  }

  private getKey(userId: string): string {
    return `user_ver:${userId}`;
  }

  async getUserVersion(userId: string): Promise<number | null> {
    const val = await this.kv.get(this.getKey(userId));
    if (!val) {
      return null;
    }

    const parsed = Number.parseInt(val, 10);
    return Number.isSafeInteger(parsed) ? parsed : null;
  }

  async setUserVersion(userId: string, version: number): Promise<void> {
    await this.kv.put(this.getKey(userId), String(version), { expirationTtl: 604800 });
  }

  async clearUserVersion(userId: string): Promise<void> {
    await this.kv.delete(this.getKey(userId));
  }
}
