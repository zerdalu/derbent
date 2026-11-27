import {
  SECRET_SETTING_KEYS,
  SettingKeys,
  type AdminSettingsMap,
  type AdminUpdateSettingsInput,
  type SettingKey,
} from "@shared/schemas/admin";
import { clearDynamicConfigCache } from "@worker/middleware/config.middleware";
import type { AuditLogRepository } from "@worker/repositories/audit-log.repository";
import type { SettingsRepository } from "@worker/repositories/settings.repository";
import type { DerbentConfig } from "@worker/types/models";

const ORDERED_SETTING_KEYS: readonly SettingKey[] = [
  SettingKeys.AppEnv,
  SettingKeys.LogLevel,
  SettingKeys.AppName,
  SettingKeys.BaseUrl,
  SettingKeys.CookieDomain,
  SettingKeys.ResendDomain,
  SettingKeys.ResendApiKey,
  SettingKeys.GithubClientId,
  SettingKeys.GithubClientSecret,
  SettingKeys.GoogleClientId,
  SettingKeys.GoogleClientSecret,
  SettingKeys.Pbkdf2Iterations,
  SettingKeys.AuditLogRetentionDays,
];

function readConfigSetting(config: DerbentConfig, key: SettingKey): string | undefined {
  switch (key) {
    case SettingKeys.AppEnv:
      return config.APP_ENV;
    case SettingKeys.LogLevel:
      return config.LOG_LEVEL;
    case SettingKeys.AppName:
      return config.APP_NAME;
    case SettingKeys.BaseUrl:
      return config.BASE_URL;
    case SettingKeys.CookieDomain:
      return config.COOKIE_DOMAIN;
    case SettingKeys.ResendDomain:
      return config.RESEND_DOMAIN;
    case SettingKeys.ResendApiKey:
      return config.RESEND_API_KEY;
    case SettingKeys.GithubClientId:
      return config.GITHUB_CLIENT_ID;
    case SettingKeys.GithubClientSecret:
      return config.GITHUB_CLIENT_SECRET;
    case SettingKeys.GoogleClientId:
      return config.GOOGLE_CLIENT_ID;
    case SettingKeys.GoogleClientSecret:
      return config.GOOGLE_CLIENT_SECRET;
    case SettingKeys.Pbkdf2Iterations:
      return config.PBKDF2_ITERATIONS;
    case SettingKeys.AuditLogRetentionDays:
      return config.AUDIT_LOG_RETENTION_DAYS;
    default: {
      const _exhaustive: never = key;
      throw new Error(`Unhandled setting key: ${String(_exhaustive)}`);
    }
  }
}

function readUpdateSetting(updates: AdminUpdateSettingsInput, key: SettingKey): string | null | undefined {
  switch (key) {
    case SettingKeys.AppEnv:
      return undefined;
    case SettingKeys.LogLevel:
      return updates.LOG_LEVEL;
    case SettingKeys.AppName:
      return updates.APP_NAME;
    case SettingKeys.BaseUrl:
      return updates.BASE_URL;
    case SettingKeys.CookieDomain:
      return updates.COOKIE_DOMAIN;
    case SettingKeys.ResendDomain:
      return updates.RESEND_DOMAIN;
    case SettingKeys.ResendApiKey:
      return updates.RESEND_API_KEY;
    case SettingKeys.GithubClientId:
      return updates.GITHUB_CLIENT_ID;
    case SettingKeys.GithubClientSecret:
      return updates.GITHUB_CLIENT_SECRET;
    case SettingKeys.GoogleClientId:
      return updates.GOOGLE_CLIENT_ID;
    case SettingKeys.GoogleClientSecret:
      return updates.GOOGLE_CLIENT_SECRET;
    case SettingKeys.Pbkdf2Iterations:
      return updates.PBKDF2_ITERATIONS;
    case SettingKeys.AuditLogRetentionDays:
      return updates.AUDIT_LOG_RETENTION_DAYS;
    default: {
      const _exhaustive: never = key;
      throw new Error(`Unhandled setting key: ${String(_exhaustive)}`);
    }
  }
}

export class AdminSettingsService {
  private readonly settingsRepo: SettingsRepository;
  private readonly auditLogRepo: AuditLogRepository;

  constructor(settingsRepo: SettingsRepository, auditLogRepo: AuditLogRepository) {
    this.settingsRepo = settingsRepo;
    this.auditLogRepo = auditLogRepo;
  }

  async getSettings(effectiveConfig: DerbentConfig, useDynamicConfig = true): Promise<AdminSettingsMap> {
    const dbKeys = new Set<string>();
    if (useDynamicConfig) {
      const dbRecords = await this.settingsRepo.getAll();
      for (const record of dbRecords) {
        if (record.key !== SettingKeys.AppEnv && record.value !== null && record.value.trim() !== "") {
          dbKeys.add(record.key);
        }
      }
    }

    const response: AdminSettingsMap = {};

    for (const key of ORDERED_SETTING_KEYS) {
      const rawValue = readConfigSetting(effectiveConfig, key);
      if (rawValue === undefined) {
        continue;
      }

      const isSecret = SECRET_SETTING_KEYS.includes(key);
      const isFromDb = key !== SettingKeys.AppEnv && dbKeys.has(key);
      response[key] = {
        value: isSecret && rawValue ? "********" : rawValue,
        source: isFromDb ? "database" : "env",
        is_secret: isSecret,
      };
    }

    return response;
  }

  async updateSettings(updates: AdminUpdateSettingsInput, masterKey: string): Promise<void> {
    let changed = false;
    const updatedKeys: string[] = [];

    for (const key of ORDERED_SETTING_KEYS) {
      if (key === SettingKeys.AppEnv) {
        continue;
      }

      const value = readUpdateSetting(updates, key);
      const isSecret = SECRET_SETTING_KEYS.includes(key);
      if (value === undefined || (isSecret && value === "********")) {
        continue;
      }

      const trimmed = value?.trim() ?? "";
      if (value === null || trimmed === "") {
        await this.settingsRepo.delete(key);
        changed = true;
        updatedKeys.push(key);
      } else {
        await this.settingsRepo.update(key, trimmed, isSecret, masterKey);
        changed = true;
        updatedKeys.push(key);
      }
    }

    if (changed) {
      await this.settingsRepo.buildAndCacheConfig(masterKey);
      clearDynamicConfigCache();
      await this.auditLogRepo.log({
        action: "admin_update_settings",
        details: { updatedKeys },
      });
    }
  }
}
