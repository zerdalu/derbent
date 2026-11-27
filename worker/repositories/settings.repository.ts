import type { SettingRecord } from "@worker/types/models";
import { decryptKV, decryptSecret, encryptKV, encryptSecret } from "@worker/utils/crypto";
import * as v from "valibot";

const ConfigMapSchema = v.record(v.string(), v.string());

export class SettingsRepository {
  private readonly cacheKey = "derbent_config_cache";
  private readonly db: D1Database;
  private readonly kv: KVNamespace;

  constructor(db: D1Database, kv: KVNamespace) {
    this.db = db;
    this.kv = kv;
  }

  async getAll(): Promise<readonly SettingRecord[]> {
    const { results } = await this.db.prepare("SELECT key, value, is_secret FROM settings").all<SettingRecord>();
    return results || [];
  }

  async update(key: string, value: string, isSecret: boolean, masterKey?: string): Promise<void> {
    const storedValue = isSecret && masterKey ? await encryptSecret(value, masterKey) : value;
    await this.db
      .prepare(
        `INSERT INTO settings (key, value, is_secret)
         VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, is_secret = excluded.is_secret`,
      )
      .bind(key, storedValue, isSecret ? 1 : 0)
      .run();
  }

  async delete(key: string): Promise<void> {
    await this.db.prepare("DELETE FROM settings WHERE key = ?").bind(key).run();
  }

  async getCachedConfig(masterKey: string): Promise<Record<string, string> | null> {
    const encryptedCache = await this.kv.get(this.cacheKey);
    if (!encryptedCache) {
      return null;
    }

    try {
      const decryptedString = await decryptKV(encryptedCache, masterKey);
      const rawParsed: unknown = JSON.parse(decryptedString);
      const result = v.safeParse(ConfigMapSchema, rawParsed);
      return result.success ? result.output : null;
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("[SettingsRepo] Failed to decrypt or parse config cache:", error.message);
      }
      return null;
    }
  }

  async buildAndCacheConfig(masterKey: string): Promise<Record<string, string>> {
    const records = await this.getAll();
    const configMap: Record<string, string> = {};

    for (const record of records) {
      if (record.value === null) {
        continue;
      }

      if (record.is_secret === 1) {
        try {
          configMap[record.key] = await decryptSecret(record.value, masterKey);
        } catch (error: unknown) {
          if (error instanceof Error) {
            console.error(`[SettingsRepo] Failed to decrypt secret setting '${record.key}':`, error.message);
          }
        }
      } else {
        configMap[record.key] = record.value;
      }
    }

    try {
      const encryptedString = await encryptKV(JSON.stringify(configMap), masterKey);
      await this.kv.put(this.cacheKey, encryptedString, { expirationTtl: 2592000 });
    } catch (error: unknown) {
      if (error instanceof Error) {
        console.error("[SettingsRepo] Failed to encrypt and cache config:", error.message);
      }
    }

    return configMap;
  }

  async invalidateCache(): Promise<void> {
    await this.kv.delete(this.cacheKey);
  }
}
