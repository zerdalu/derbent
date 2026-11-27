import type { AdminUpdateUserInput, AdminUserView, PaginatedResult } from "@shared/schemas/admin";
import type { AppRepository } from "@worker/repositories/app.repository";
import type { AuditLogRepository } from "@worker/repositories/audit-log.repository";
import type { UserTokenVersionRepository } from "@worker/repositories/user-token-version.repository";
import type { UserRepository } from "@worker/repositories/user.repository";
import { AppError } from "@worker/types/errors";
import type { UserRecord } from "@worker/types/models";
import { hashPassword } from "@worker/utils/crypto";

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

export class AdminUserService {
  private readonly userRepo: UserRepository;
  private readonly auditLogRepo: AuditLogRepository;
  private readonly userTokenVersionRepo: UserTokenVersionRepository;
  private readonly appRepo: AppRepository;
  private readonly hashIterations: number;

  constructor(
    userRepo: UserRepository,
    auditLogRepo: AuditLogRepository,
    userTokenVersionRepo: UserTokenVersionRepository,
    appRepo: AppRepository,
    hashIterations: number,
  ) {
    this.userRepo = userRepo;
    this.auditLogRepo = auditLogRepo;
    this.userTokenVersionRepo = userTokenVersionRepo;
    this.appRepo = appRepo;
    this.hashIterations = hashIterations;
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
      const newVersion = await this.userRepo.incrementTokenVersion(userId);
      await this.userTokenVersionRepo.setUserVersion(userId, newVersion);
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
    await this.userTokenVersionRepo.setUserVersion(userId, user.token_version + 1);

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

    const accountsForEmail = await this.userRepo.findAllByEmail(user.email);
    const hasOtherAccounts = accountsForEmail.some((entry) => entry.id !== userId);

    await this.auditLogRepo.anonymizeByUserId(userId, hasOtherAccounts ? undefined : user.email);
    await this.userRepo.delete(userId);
    await this.userTokenVersionRepo.markUserRevoked(userId);

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

    const newVersion = await this.userRepo.incrementTokenVersion(userId);
    await this.userTokenVersionRepo.setUserVersion(userId, newVersion);

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
      await this.userTokenVersionRepo.markUserRevoked(userId);
    } else {
      await this.userTokenVersionRepo.setUserVersion(userId, user.token_version);
    }

    await this.auditLogRepo.log({
      action: locked ? "admin_lock_account" : "admin_unlock_account",
      userId: user.id,
      email: user.email,
    });
  }
}
