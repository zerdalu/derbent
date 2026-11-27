import type {
  AdminAuditLogView,
  AdminSettingsMap,
  AdminStatsData,
  AdminUpdateAppInput,
  AdminUpdateSettingsInput,
  AdminUpdateUserInput,
  AdminUserView,
  PaginatedResult,
} from "@shared/schemas/admin";
import type { AppRepository } from "@worker/repositories/app.repository";
import type { AuditLogRepository } from "@worker/repositories/audit-log.repository";
import type { SettingsRepository } from "@worker/repositories/settings.repository";
import type { UserTokenVersionRepository } from "@worker/repositories/user-token-version.repository";
import type { UserRepository } from "@worker/repositories/user.repository";
import { AdminSettingsService } from "@worker/services/admin-settings.service";
import { AdminUserService } from "@worker/services/admin-user.service";
import { AppError } from "@worker/types/errors";
import type { AppRecord, DerbentConfig } from "@worker/types/models";

export class AdminService {
  private readonly userRepo: UserRepository;
  private readonly auditLogRepo: AuditLogRepository;
  private readonly appRepo: AppRepository;
  private readonly settingsService: AdminSettingsService;
  private readonly userService: AdminUserService;

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
    this.appRepo = appRepo;
    this.settingsService = new AdminSettingsService(settingsRepo, auditLogRepo);
    this.userService = new AdminUserService(userRepo, auditLogRepo, userTokenVersionRepo, appRepo, hashIterations);
  }

  getSettings(effectiveConfig: DerbentConfig, useDynamicConfig = true): Promise<AdminSettingsMap> {
    return this.settingsService.getSettings(effectiveConfig, useDynamicConfig);
  }

  updateSettings(updates: AdminUpdateSettingsInput, masterKey: string): Promise<void> {
    return this.settingsService.updateSettings(updates, masterKey);
  }

  getUsers(page: number, limit: number, search?: string): Promise<PaginatedResult<AdminUserView>> {
    return this.userService.getUsers(page, limit, search);
  }

  getUser(userId: string): Promise<AdminUserView> {
    return this.userService.getUser(userId);
  }

  updateUser(userId: string, data: AdminUpdateUserInput): Promise<AdminUserView> {
    return this.userService.updateUser(userId, data);
  }

  forceResetPassword(userId: string, newPassword: string): Promise<void> {
    return this.userService.forceResetPassword(userId, newPassword);
  }

  disable2FA(userId: string): Promise<void> {
    return this.userService.disable2FA(userId);
  }

  deleteUser(userId: string): Promise<void> {
    return this.userService.deleteUser(userId);
  }

  revokeAllSessions(userId: string): Promise<void> {
    return this.userService.revokeAllSessions(userId);
  }

  setAccountLockStatus(userId: string, locked: boolean): Promise<void> {
    return this.userService.setAccountLockStatus(userId, locked);
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
