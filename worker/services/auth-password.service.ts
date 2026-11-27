import type { AuditLogRepository } from "@worker/repositories/audit-log.repository";
import type { LoginAttemptRepository } from "@worker/repositories/login-attempt.repository";
import type { TokenRepository } from "@worker/repositories/token.repository";
import type { UserTokenVersionRepository } from "@worker/repositories/user-token-version.repository";
import type { UserRepository } from "@worker/repositories/user.repository";
import type { EmailService } from "@worker/services/email.service";
import { AppError } from "@worker/types/errors";
import type { UserRecord } from "@worker/types/models";
import { hashPassword, verifyPassword } from "@worker/utils/crypto";

export async function assertNoVerifiedAccountConflict(userRepo: UserRepository, user: UserRecord): Promise<void> {
  if (user.app === "sso") {
    if (await userRepo.hasAnyVerifiedAppAccount(user.email)) {
      if (user.email_verified === 0) {
        await userRepo.delete(user.id);
      }
      throw new AppError("An app-level account already exists for this email.", 409);
    }
    return;
  }

  const existingSso = await userRepo.findByEmailAndApp(user.email, "sso");
  if (existingSso && existingSso.email_verified === 1) {
    if (user.email_verified === 0) {
      await userRepo.delete(user.id);
    }
    throw new AppError("An SSO account already exists for this email.", 409);
  }
}

export class AuthPasswordService {
  private readonly userRepo: UserRepository;
  private readonly tokenRepo: TokenRepository;
  private readonly userTokenVersionRepo: UserTokenVersionRepository;
  private readonly emailService: EmailService;
  private readonly auditLogRepo: AuditLogRepository;
  private readonly loginAttemptRepo: LoginAttemptRepository;
  private readonly hashIterations: number;

  constructor(
    userRepo: UserRepository,
    tokenRepo: TokenRepository,
    userTokenVersionRepo: UserTokenVersionRepository,
    emailService: EmailService,
    auditLogRepo: AuditLogRepository,
    loginAttemptRepo: LoginAttemptRepository,
    hashIterations: number,
  ) {
    this.userRepo = userRepo;
    this.tokenRepo = tokenRepo;
    this.userTokenVersionRepo = userTokenVersionRepo;
    this.emailService = emailService;
    this.auditLogRepo = auditLogRepo;
    this.loginAttemptRepo = loginAttemptRepo;
    this.hashIterations = hashIterations;
  }

  async verifyPasswordSafe(password: string, user: UserRecord | null): Promise<boolean> {
    const dummySalt = "U29tZVJhbmRvbVNhbHQ=";
    const dummyHashPart = "U29tZVJhbmRvbUhhc2g=";
    const dummyHash = `pbkdf2_sha256:${this.hashIterations}:${dummySalt}:${dummyHashPart}`;
    const isRealUserWithPassword = Boolean(user && !user.phash.startsWith("OAUTH:"));
    const targetHash = isRealUserWithPassword && user ? user.phash : dummyHash;
    const isMatch = await verifyPassword(password, targetHash);
    return isRealUserWithPassword && isMatch;
  }

  async requestPasswordReset(email: string, appId: string, ip: string, userAgent: string): Promise<void> {
    const normalizedEmail = email.trim().toLowerCase();
    const user = await this.userRepo.findForLogin(normalizedEmail, appId);
    const canReset = Boolean(user && !user.phash.startsWith("OAUTH:") && user.is_locked === 0);

    await this.auditLogRepo.log({
      action: "password_reset_requested",
      email: normalizedEmail,
      userId: user?.id ?? null,
      ip,
      userAgent,
      details: { appId, eligible: canReset },
    });

    if (!user || !canReset) {
      return;
    }

    if (await this.tokenRepo.isPasswordResetOnCooldown(user.id)) {
      return;
    }

    const token = crypto.randomUUID();
    await this.tokenRepo.savePasswordResetToken(token, user.id, user.token_version);

    try {
      await this.emailService.sendPasswordResetEmail(user.email, token);
      await this.tokenRepo.setPasswordResetCooldown(user.id, 60);
    } catch (error: unknown) {
      await this.tokenRepo.deletePasswordResetToken(token);
      throw error;
    }
  }

  async resetPassword(token: string, newPassword: string, ip: string, userAgent: string): Promise<string> {
    const tokenData = await this.tokenRepo.consumeResetToken(token);
    if (!tokenData) {
      await this.auditLogRepo.log({
        action: "password_reset_failed",
        ip,
        userAgent,
        details: { reason: "invalid_token" },
      });
      throw new AppError("Reset link is invalid or has expired.", 400);
    }

    const user = await this.userRepo.findById(tokenData.userId);
    if (!user || user.token_version !== tokenData.tokenVersion) {
      await this.auditLogRepo.log({
        action: "password_reset_failed",
        userId: user?.id ?? null,
        email: user?.email,
        ip,
        userAgent,
        details: { reason: user ? "stale_token" : "user_not_found" },
      });
      throw new AppError("Reset link is invalid or has expired.", 400);
    }

    if (user.phash.startsWith("OAUTH:")) {
      throw new AppError("Password reset is not available for OAuth-only accounts.", 400);
    }

    if (user.is_locked === 1) {
      throw new AppError("This account has been locked. Please contact support.", 403);
    }

    if (user.email_verified === 0) {
      await assertNoVerifiedAccountConflict(this.userRepo, user);
    }

    const phash = await hashPassword(newPassword, this.hashIterations);
    await this.userRepo.updatePassword(user.id, phash);

    // Completing password reset via an email token proves email ownership
    if (user.email_verified === 0) {
      await this.userRepo.markEmailVerified(user.id);
      if (user.app === "sso") {
        await this.userRepo.deleteUnverifiedByEmail(user.email, user.id);
      }
    }

    await this.userTokenVersionRepo.clearUserVersion(user.id);
    await this.loginAttemptRepo.clearAttempts(user.email, ip);

    await this.auditLogRepo.log({
      action: "password_reset_success",
      userId: user.id,
      email: user.email,
      ip,
      userAgent,
    });
    return user.app;
  }

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
    ip: string,
    userAgent: string,
  ): Promise<void> {
    const user = await this.userRepo.findById(userId);
    if (!user) {
      throw new AppError("User not found.", 404);
    }

    if (user.phash.startsWith("OAUTH:")) {
      throw new AppError("Password cannot be changed for OAuth accounts.", 400);
    }

    const isPasswordVerified = await this.verifyPasswordSafe(currentPassword, user);
    if (!isPasswordVerified) {
      await this.auditLogRepo.log({
        action: "change_password_failed",
        userId,
        email: user.email,
        ip,
        userAgent,
        details: { reason: "invalid_current_password" },
      });
      throw new AppError("Incorrect current password.", 400);
    }

    const phash = await hashPassword(newPassword, this.hashIterations);
    await this.userRepo.updatePassword(userId, phash);
    await this.userTokenVersionRepo.clearUserVersion(userId);

    await this.auditLogRepo.log({
      action: "password_changed",
      userId,
      email: user.email,
      ip,
      userAgent,
    });
  }
}
