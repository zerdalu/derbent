import {
  SECRET_SETTING_KEYS,
  SettingKeys,
  type AdminAuditLogView,
  type AdminSettingsMap,
  type AdminStatsData,
  type AdminUpdateAppInput,
  type AdminUpdateSettingsInput,
  type AdminUpdateUserInput,
  type AdminUserView,
  type PaginatedResult,
  type SettingKey,
} from "@shared/schemas/admin";
import type { AppRepository } from "@worker/repositories/app.repository";
import type { AuditLogRepository } from "@worker/repositories/audit-log.repository";
import type { SettingsRepository } from "@worker/repositories/settings.repository";
import type { UserTokenVersionRepository } from "@worker/repositories/user-token-version.repository";
import type { UserRepository } from "@worker/repositories/user.repository";
import { AppError } from "@worker/types/errors";
import type { AppRecord, DerbentConfig, UserRecord } from "@worker/types/models";
import { hashPassword } from "@worker/utils/crypto";

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
      return updates.APP_ENV;
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

function toAdminUserView(user: UserRecord): AdminUserView {
  return {
    id: user.id,
    app: user.app,
    email: user.email,
    email_verified: user.email_verified,
    token_version: user.token_version,
    metadata: user.metadata,
    two_factor_enabled: user.two_factor_enabled,
    is_locked: user.is_locked,
    has_password: !user.phash.startsWith("OAUTH:"),
    created_at: user.created_at,
    updated_at: user.updated_at,
  };
}

export class AdminService {
  private readonly userRepo: UserRepository;
  private readonly auditLogRepo: AuditLogRepository;
  private readonly userTokenVersionRepo: UserTokenVersionRepository;
  private readonly appRepo: AppRepository;
  private readonly settingsRepo: SettingsRepository;
  private readonly hashIterations: number;

  constructor(
    userRepo: UserRepository,
    auditLogRepo: AuditLogRepository,
    userTokenVersionRepo: UserTokenVersionRepository,
    appRepo: AppRepository,
    settingsRepo: SettingsRepository,
    hashIterations: number,
  ) {
    this.userRepo = userRepo;
    this.auditLogRepo = auditLogRepo;
    this.userTokenVersionRepo = userTokenVersionRepo;
    this.appRepo = appRepo;
    this.settingsRepo = settingsRepo;
    this.hashIterations = hashIterations;
  }

  async getSettings(effectiveConfig: DerbentConfig): Promise<AdminSettingsMap> {
    const dbRecords = await this.settingsRepo.getAll();
    const dbValues = new Map<string, string>();
    for (const record of dbRecords) {
      if (record.value !== null && record.value.trim() !== "") {
        dbValues.set(record.key, record.value.trim());
      }
    }

    const response: AdminSettingsMap = {};

    for (const key of ORDERED_SETTING_KEYS) {
      const dbValue = dbValues.get(key);
      const rawValue = dbValue ?? readConfigSetting(effectiveConfig, key);
      if (rawValue === undefined) {
        continue;
      }

      const isSecret = SECRET_SETTING_KEYS.includes(key);
      response[key] = {
        value: isSecret && rawValue ? "********" : rawValue,
        source: dbValue !== undefined ? "database" : "env",
        is_secret: isSecret,
      };
    }

    return response;
  }

  async updateSettings(updates: AdminUpdateSettingsInput, masterKey: string): Promise<void> {
    let changed = false;
    const updatedKeys: string[] = [];

    for (const key of ORDERED_SETTING_KEYS) {
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
        await this.settingsRepo.update(key, trimmed, isSecret);
        changed = true;
        updatedKeys.push(key);
      }
    }

    if (changed) {
      await this.settingsRepo.buildAndCacheConfig(masterKey);
      await this.auditLogRepo.log({
        action: "admin_update_settings",
        details: { updatedKeys },
      });
    }
  }

  async getUsers(page: number, limit: number, search?: string): Promise<PaginatedResult<AdminUserView>> {
    const offset = (page - 1) * limit;
    const [users, total] = await Promise.all([
      this.userRepo.findMany(limit, offset, search),
      this.userRepo.count(search),
    ]);

    return {
      items: users.map(toAdminUserView),
      total,
      page,
      limit,
    };
  }

  async getDashboardStats(): Promise<AdminStatsData> {
    const daysForTrend = 30;

    const [userStats, auditStats, signupsRaw, loginsRaw] = await Promise.all([
      this.userRepo.getDashboardStats(),
      this.auditLogRepo.getDashboardStats(),
      this.userRepo.getSignupsTrend(daysForTrend),
      this.auditLogRepo.getLoginsTrend(daysForTrend),
    ]);

    const mfaPercentage = userStats.total > 0 ? Math.round((userStats.mfaEnabled / userStats.total) * 100) : 0;

    const dates: string[] = [];
    const now = new Date();
    for (let i = daysForTrend - 1; i >= 0; i--) {
      const d = new Date(now);
      d.setUTCDate(d.getUTCDate() - i);
      const isoDate = d.toISOString().split("T")[0];
      if (isoDate) {
        dates.push(isoDate);
      }
    }

    const signupsMap = new Map(signupsRaw.map((row) => [row.date, row.count]));
    const signupsTrend = dates.map((date) => ({
      date,
      count: signupsMap.get(date) || 0,
    }));

    const loginsMap = new Map(loginsRaw.map((row) => [row.date, row]));
    const loginsTrend = dates.map((date) => ({
      date,
      success: loginsMap.get(date)?.success || 0,
      failed: loginsMap.get(date)?.failed || 0,
    }));

    return {
      users: {
        total: userStats.total,
        newLast7Days: userStats.newLast7Days,
        mfaEnabled: userStats.mfaEnabled,
        mfaPercentage,
        locked: userStats.locked,
      },
      activity: {
        failedLogins24h: auditStats.failedLogins24h,
        lockouts24h: auditStats.lockouts24h,
        pwdResets24h: auditStats.pwdResets24h,
      },
      trends: {
        signups: signupsTrend,
        logins: loginsTrend,
      },
    };
  }

  async getUser(userId: string): Promise<AdminUserView> {
    const user = await this.userRepo.findById(userId);
    if (!user) {
      throw new AppError("User not found", 404);
    }
    return toAdminUserView(user);
  }

  async updateUser(userId: string, data: AdminUpdateUserInput): Promise<AdminUserView> {
    const user = await this.userRepo.findById(userId);
    if (!user) {
      throw new AppError("User not found", 404);
    }

    const isAppChanged = data.app !== undefined && data.app !== user.app;

    if (data.app !== undefined) {
      const targetApp = await this.appRepo.findById(data.app);
      if (!targetApp) {
        throw new AppError("Target application does not exist.", 400);
      }

      if (isAppChanged) {
        const existingForEmail = await this.userRepo.findAllByEmail(user.email);
        const otherAccounts = existingForEmail.filter((entry) => entry.id !== user.id);

        if (data.app === "sso" && otherAccounts.length > 0) {
          throw new AppError("Cannot assign user to SSO while app-specific accounts exist for this email.", 409);
        }

        if (otherAccounts.some((entry) => entry.app === "sso" || entry.app === data.app)) {
          throw new AppError("An account for this email already exists on the target application or SSO.", 409);
        }
      }
    }

    const updates: { metadata?: string; email_verified?: 0 | 1; app?: string } = {};
    const auditDetails: { metadata?: string; email_verified?: number; app?: string } = {};

    if (data.metadata !== undefined) {
      const serialized = JSON.stringify(data.metadata);
      updates.metadata = serialized;
      auditDetails.metadata = serialized;
    }
    if (data.email_verified !== undefined) {
      updates.email_verified = data.email_verified;
      auditDetails.email_verified = data.email_verified;
    }
    if (data.app !== undefined) {
      updates.app = data.app;
      auditDetails.app = data.app;
    }

    const isEmailUnverified = data.email_verified === 0 && user.email_verified === 1;
    const isMetadataChanged = updates.metadata !== undefined && updates.metadata !== user.metadata;

    let updatedUser = await this.userRepo.update(userId, updates);
    if (!updatedUser) {
      throw new AppError("Failed to update user", 500);
    }

    if (isAppChanged || isEmailUnverified || isMetadataChanged) {
      await this.userRepo.incrementTokenVersion(userId);
      await this.userTokenVersionRepo.clearUserVersion(userId);
      const refreshed = await this.userRepo.findById(userId);
      if (refreshed) {
        updatedUser = refreshed;
      }
    }

    await this.auditLogRepo.log({
      action: "admin_update_user",
      userId: user.id,
      email: user.email,
      details: auditDetails,
    });

    return toAdminUserView(updatedUser);
  }

  async forceResetPassword(userId: string, newPassword: string): Promise<void> {
    const user = await this.userRepo.findById(userId);
    if (!user) {
      throw new AppError("User not found", 404);
    }

    if (user.phash.startsWith("OAUTH:")) {
      throw new AppError("Cannot reset password for OAuth-only accounts.", 400);
    }

    const phash = await hashPassword(newPassword, this.hashIterations);
    await this.userRepo.updatePassword(userId, phash);
    await this.userTokenVersionRepo.clearUserVersion(userId);

    await this.auditLogRepo.log({
      action: "admin_force_password_reset",
      userId: user.id,
      email: user.email,
    });
  }

  async disable2FA(userId: string): Promise<void> {
    const user = await this.userRepo.findById(userId);
    if (!user) {
      throw new AppError("User not found", 404);
    }

    if (user.two_factor_enabled === 0) {
      throw new AppError("2FA is already disabled for this user.", 400);
    }

    await this.userRepo.disableTwoFactor(userId);

    await this.auditLogRepo.log({
      action: "admin_disable_2fa",
      userId: user.id,
      email: user.email,
    });
  }

  async deleteUser(userId: string): Promise<void> {
    const user = await this.userRepo.findById(userId);
    if (!user) {
      throw new AppError("User not found", 404);
    }

    await this.auditLogRepo.anonymizeByUserId(userId);
    await this.userRepo.delete(userId);
    await this.userTokenVersionRepo.clearUserVersion(userId);

    await this.auditLogRepo.log({
      action: "admin_delete_user",
      details: { deletedUserId: userId },
    });
  }

  async revokeAllSessions(userId: string): Promise<void> {
    const user = await this.userRepo.findById(userId);
    if (!user) {
      throw new AppError("User not found", 404);
    }

    await this.userRepo.incrementTokenVersion(userId);
    await this.userTokenVersionRepo.clearUserVersion(userId);

    await this.auditLogRepo.log({
      action: "admin_revoke_sessions",
      userId: user.id,
      email: user.email,
    });
  }

  async setAccountLockStatus(userId: string, locked: boolean): Promise<void> {
    const user = await this.userRepo.findById(userId);
    if (!user) {
      throw new AppError("User not found", 404);
    }

    if (user.is_locked === (locked ? 1 : 0)) {
      return;
    }

    await this.userRepo.setLockedStatus(userId, locked);

    if (locked) {
      await this.userRepo.incrementTokenVersion(userId);
      await this.userTokenVersionRepo.clearUserVersion(userId);
    }

    await this.auditLogRepo.log({
      action: locked ? "admin_lock_account" : "admin_unlock_account",
      userId: user.id,
      email: user.email,
    });
  }

  async getAuditLogs(page: number, limit: number, action?: string): Promise<PaginatedResult<AdminAuditLogView>> {
    const offset = (page - 1) * limit;
    const [items, total] = await Promise.all([
      this.auditLogRepo.findMany(limit, offset, action),
      this.auditLogRepo.count(action),
    ]);

    return { items, total, page, limit };
  }

  async getUserAuditLogs(userId: string, page: number, limit: number): Promise<PaginatedResult<AdminAuditLogView>> {
    const offset = (page - 1) * limit;
    const [items, total] = await Promise.all([
      this.auditLogRepo.findByUserId(userId, limit, offset),
      this.auditLogRepo.countByUserId(userId),
    ]);

    return { items, total, page, limit };
  }

  async getApps(): Promise<readonly AppRecord[]> {
    return await this.appRepo.findAll();
  }

  async getApp(appId: string): Promise<AppRecord> {
    const app = await this.appRepo.findById(appId);
    if (!app) {
      throw new AppError("App not found", 404);
    }
    return app;
  }

  async createApp(data: Omit<AppRecord, "created_at" | "updated_at">): Promise<void> {
    const existing = await this.appRepo.findById(data.id);
    if (existing) {
      throw new AppError("An app with this ID already exists.", 400);
    }

    await this.appRepo.create(data);

    await this.auditLogRepo.log({
      action: "admin_create_app",
      details: { appId: data.id, appName: data.name },
    });
  }

  async updateApp(appId: string, data: AdminUpdateAppInput): Promise<AppRecord> {
    const app = await this.appRepo.findById(appId);
    if (!app) {
      throw new AppError("App not found", 404);
    }

    const normalizedIcon = data.icon === undefined ? undefined : data.icon?.trim() ? data.icon.trim() : null;

    const updatedApp = await this.appRepo.update(appId, {
      name: data.name,
      description: data.description,
      icon: normalizedIcon,
      prod_url: data.prod_url,
      dev_url: data.dev_url,
      allow_signups: data.allow_signups,
      allow_logins: data.allow_logins,
    });
    if (!updatedApp) {
      throw new AppError("Failed to update app record", 500);
    }

    await this.auditLogRepo.log({
      action: "admin_update_app",
      details: { appId },
    });

    return updatedApp;
  }

  async deleteApp(appId: string): Promise<void> {
    const app = await this.appRepo.findById(appId);
    if (!app) {
      throw new AppError("App not found", 404);
    }

    if (appId === "sso") {
      throw new AppError("The core SSO app cannot be deleted.", 403);
    }

    const userCount = await this.userRepo.countByApp(appId);
    if (userCount > 0) {
      throw new AppError(
        `Cannot delete app. There are ${userCount} users associated with it. Please disable logins instead.`,
        400,
      );
    }

    await this.appRepo.delete(appId);

    await this.auditLogRepo.log({
      action: "admin_delete_app",
      details: { appId, appName: app.name },
    });
  }
}
