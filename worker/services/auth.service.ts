import type { Session } from "@shared/schemas/auth";
import type { AppRepository } from "@worker/repositories/app.repository";
import type { AuditLogRepository } from "@worker/repositories/audit-log.repository";
import type { LoginAttemptRepository } from "@worker/repositories/login-attempt.repository";
import type { SessionRepository } from "@worker/repositories/session.repository";
import type { TokenRepository } from "@worker/repositories/token.repository";
import type { UserTokenVersionRepository } from "@worker/repositories/user-token-version.repository";
import type { UserRepository } from "@worker/repositories/user.repository";
import { AuthMagicLinkService } from "@worker/services/auth-magic-link.service";
import { AuthPasswordService, assertNoVerifiedAccountConflict } from "@worker/services/auth-password.service";
import { AuthSessionService, type VerifySessionOptions } from "@worker/services/auth-session.service";
import { AuthTwoFactorService } from "@worker/services/auth-two-factor.service";
import type { EmailService } from "@worker/services/email.service";
import { AppError } from "@worker/types/errors";
import type { LoginResult, LoginSuccessResult, UserRecord } from "@worker/types/models";
import { hashPassword, needsRehash } from "@worker/utils/crypto";
import { generateUUIDv7 } from "@worker/utils/uuid";

export type { VerifySessionOptions };

const MAX_IP_LOGIN_ATTEMPTS = 5;
const MAX_EMAIL_LOGIN_ATTEMPTS = 15;

function isUniqueConstraintError(error: unknown): boolean {
  return error instanceof Error && /unique constraint/i.test(error.message);
}

export class AuthService {
  private readonly userRepo: UserRepository;
  private readonly tokenRepo: TokenRepository;
  private readonly userTokenVersionRepo: UserTokenVersionRepository;
  private readonly appRepo: AppRepository;
  private readonly emailService: EmailService;
  private readonly auditLogRepo: AuditLogRepository;
  private readonly loginAttemptRepo: LoginAttemptRepository;
  private readonly hashIterations: number;
  private readonly sessionService: AuthSessionService;
  private readonly passwordService: AuthPasswordService;
  private readonly twoFactorService: AuthTwoFactorService;
  private readonly magicLinkService: AuthMagicLinkService;

  constructor(
    userRepo: UserRepository,
    sessionRepo: SessionRepository,
    tokenRepo: TokenRepository,
    userTokenVersionRepo: UserTokenVersionRepository,
    appRepo: AppRepository,
    emailService: EmailService,
    auditLogRepo: AuditLogRepository,
    loginAttemptRepo: LoginAttemptRepository,
    hashIterations: number,
  ) {
    this.userRepo = userRepo;
    this.tokenRepo = tokenRepo;
    this.userTokenVersionRepo = userTokenVersionRepo;
    this.appRepo = appRepo;
    this.emailService = emailService;
    this.auditLogRepo = auditLogRepo;
    this.loginAttemptRepo = loginAttemptRepo;
    this.hashIterations = hashIterations;

    this.sessionService = new AuthSessionService(
      userRepo,
      sessionRepo,
      tokenRepo,
      userTokenVersionRepo,
      appRepo,
      auditLogRepo,
    );
    this.passwordService = new AuthPasswordService(
      userRepo,
      tokenRepo,
      userTokenVersionRepo,
      emailService,
      auditLogRepo,
      loginAttemptRepo,
      hashIterations,
    );
    this.twoFactorService = new AuthTwoFactorService(
      userRepo,
      tokenRepo,
      userTokenVersionRepo,
      appRepo,
      auditLogRepo,
      this.sessionService,
    );
    this.magicLinkService = new AuthMagicLinkService(
      userRepo,
      tokenRepo,
      appRepo,
      emailService,
      auditLogRepo,
      this.sessionService,
    );
  }

  async getUser(userId: string): Promise<UserRecord | null> {
    return await this.userRepo.findById(userId);
  }

  async login(email: string, password: string, appId: string, ip: string, userAgent: string): Promise<LoginResult> {
    const normalizedEmail = email.trim().toLowerCase();
    const appRecord = await this.appRepo.findById(appId);
    if (!appRecord || appRecord.allow_logins === 0) {
      throw new AppError("Logins are currently disabled for this application.", 403);
    }

    const { ipAttempts, emailAttempts } = await this.loginAttemptRepo.getAttemptCounts(normalizedEmail, ip);
    if (ipAttempts >= MAX_IP_LOGIN_ATTEMPTS) {
      throw new AppError("Too many failed login attempts from this network. Please try again in 15 minutes.", 429);
    }
    if (emailAttempts >= MAX_EMAIL_LOGIN_ATTEMPTS) {
      throw new AppError("Too many failed login attempts for this account. Please try again in 15 minutes.", 429);
    }

    const user = await this.userRepo.findForLogin(normalizedEmail, appId);
    const isPasswordVerified = await this.passwordService.verifyPasswordSafe(password, user);

    if (!user || !isPasswordVerified) {
      const nextCounts = await this.loginAttemptRepo.incrementAttempts(normalizedEmail, ip);
      await this.auditLogRepo.log({
        action: "login_failed",
        email: normalizedEmail,
        ip,
        userAgent,
        details: { reason: "invalid_credentials", appId },
      });

      if (nextCounts.ipAttempts === MAX_IP_LOGIN_ATTEMPTS || nextCounts.emailAttempts === MAX_EMAIL_LOGIN_ATTEMPTS) {
        await this.auditLogRepo.log({
          action: "login_locked_out",
          email: normalizedEmail,
          ip,
          userAgent,
          details: { attempts: nextCounts.ipAttempts, emailAttempts: nextCounts.emailAttempts },
        });
      }

      throw new AppError("Invalid email or password", 401);
    }

    if (user.app === "sso" && appId !== "sso") {
      const ssoApp = await this.appRepo.findById("sso");
      if (!ssoApp || ssoApp.allow_logins === 0) {
        throw new AppError("Single sign-on is currently disabled.", 403);
      }
    }

    if (user.is_locked === 1) {
      await this.auditLogRepo.log({
        action: "login_failed_locked",
        userId: user.id,
        email: user.email,
        ip,
        userAgent,
        details: { appId },
      });
      throw new AppError("This account has been locked. Please contact support.", 403);
    }

    await this.loginAttemptRepo.clearAttempts(normalizedEmail, ip);

    if (user.email_verified === 0) {
      throw new AppError("Email verification is required.", 403, "EMAIL_NOT_VERIFIED");
    }

    if (!user.phash.startsWith("OAUTH:") && needsRehash(user.phash, this.hashIterations)) {
      try {
        const newHash = await hashPassword(password, this.hashIterations);
        await this.userRepo.updatePasswordHash(user.id, newHash);
      } catch (error: unknown) {
        if (error instanceof Error) {
          console.error("[AuthService] Failed to upgrade password hash:", error.message);
        }
      }
    }

    return this.sessionService.handleSuccessfulAuthentication(user, appId, ip, userAgent, "password");
  }

  async loginWithOAuth(
    email: string,
    provider: string,
    appId: string,
    ip: string,
    userAgent: string,
  ): Promise<LoginResult> {
    const normalizedEmail = email.trim().toLowerCase();
    const appRecord = await this.appRepo.findById(appId);
    if (!appRecord || appRecord.allow_logins === 0) {
      throw new AppError("Logins are currently disabled for this application.", 403);
    }

    let user = await this.userRepo.findForLogin(normalizedEmail, appId);

    // Prevent unverified app-account pre-squatting from trapping an OAuth user outside SSO
    if (
      user &&
      user.email_verified === 0 &&
      user.app !== "sso" &&
      !(await this.userRepo.hasAnyVerifiedAppAccount(normalizedEmail))
    ) {
      const ssoAppRecord = await this.appRepo.findById("sso");
      if (ssoAppRecord && ssoAppRecord.allow_signups === 1 && ssoAppRecord.allow_logins === 1) {
        await this.userRepo.deleteUnverifiedByEmail(normalizedEmail);
        user = null;
      }
    }

    if (!user) {
      if (appRecord.allow_signups === 0) {
        throw new AppError("Registrations are currently closed for this application.", 403);
      }

      if (appId !== "sso") {
        const ssoAppRecord = await this.appRepo.findById("sso");
        if (!ssoAppRecord || ssoAppRecord.allow_signups === 0) {
          throw new AppError("Registrations are currently closed for this application.", 403);
        }
        if (ssoAppRecord.allow_logins === 0) {
          throw new AppError("Single sign-on is currently disabled.", 403);
        }
      }

      if (await this.userRepo.hasAnyVerifiedAppAccount(normalizedEmail)) {
        throw new AppError("An app-level account already exists for this email.", 409);
      }

      // Remove any unverified squatted app records before provisioning the verified SSO account
      await this.userRepo.deleteUnverifiedByEmail(normalizedEmail);

      const userId = generateUUIDv7();
      try {
        await this.userRepo.create({
          id: userId,
          app: "sso",
          email: normalizedEmail,
          phash: `OAUTH:${provider.toUpperCase()}`,
          metadata: JSON.stringify({ provider }),
          email_verified: 1,
          token_version: 1,
          two_factor_secret: null,
          two_factor_enabled: 0,
          is_locked: 0,
        });
      } catch (error: unknown) {
        if (isUniqueConstraintError(error)) {
          throw new AppError("An account conflict occurred. Please try signing in again.", 409);
        }
        throw error;
      }
      user = await this.userRepo.findById(userId);
    }

    if (!user) {
      throw new AppError("Failed to sync user", 500);
    }

    if (user.app === "sso" && appId !== "sso") {
      const ssoApp = await this.appRepo.findById("sso");
      if (!ssoApp || ssoApp.allow_logins === 0) {
        throw new AppError("Single sign-on is currently disabled.", 403);
      }
    }

    if (user.is_locked === 1) {
      await this.auditLogRepo.log({
        action: "login_failed_locked",
        userId: user.id,
        email: user.email,
        ip,
        userAgent,
        details: { appId, method: `oauth_${provider}` },
      });
      throw new AppError("This account has been locked. Please contact support.", 403);
    }

    // If an unverified password registration existed for this email, clear the untrusted password hash
    if (user.email_verified === 0) {
      await this.userRepo.updatePassword(user.id, `OAUTH:${provider.toUpperCase()}`);
      await this.userRepo.markEmailVerified(user.id);
      if (user.app === "sso") {
        await this.userRepo.deleteUnverifiedByEmail(normalizedEmail, user.id);
      }
      await this.userTokenVersionRepo.clearUserVersion(user.id);
      const refreshedUser = await this.userRepo.findById(user.id);
      if (!refreshedUser) {
        throw new AppError("Failed to sync user", 500);
      }
      user = refreshedUser;
    }

    return this.sessionService.handleSuccessfulAuthentication(user, appId, ip, userAgent, `oauth_${provider}`);
  }

  async register(
    email: string,
    password: string,
    appId: string,
    redirect: string,
    ip: string,
    userAgent: string,
  ): Promise<void> {
    const normalizedEmail = email.trim().toLowerCase();
    const appRecord = await this.appRepo.findById(appId);
    if (!appRecord || appRecord.allow_signups === 0) {
      throw new AppError("Registrations are currently closed for this application.", 403);
    }

    const existingSso = await this.userRepo.findByEmailAndApp(normalizedEmail, "sso");
    if (existingSso && existingSso.email_verified === 1) {
      throw new AppError("An SSO account already exists for this email.", 409);
    }

    if (appId === "sso" && (await this.userRepo.hasAnyVerifiedAppAccount(normalizedEmail))) {
      throw new AppError("An app-level account already exists for this email.", 409);
    }

    const existingAppUser =
      appId === "sso" ? existingSso : await this.userRepo.findByEmailAndApp(normalizedEmail, appId);

    if (existingAppUser) {
      if (existingAppUser.email_verified === 1) {
        throw new AppError("Account already exists for this app.", 409);
      }

      if (existingAppUser.is_locked === 1) {
        throw new AppError("This account has been locked. Please contact support.", 403);
      }

      if (await this.tokenRepo.isVerificationEmailOnCooldown(existingAppUser.id)) {
        throw new AppError("A verification email was recently sent. Please wait a minute and try again.", 429);
      }

      const phash = await hashPassword(password, this.hashIterations);
      await this.userRepo.updatePassword(existingAppUser.id, phash);
      await this.userTokenVersionRepo.clearUserVersion(existingAppUser.id);
      const refreshedUser = await this.userRepo.findById(existingAppUser.id);
      const nextTokenVersion = refreshedUser?.token_version ?? existingAppUser.token_version + 1;

      const token = crypto.randomUUID();
      await this.tokenRepo.saveEmailVerificationToken(token, existingAppUser.id, nextTokenVersion);

      try {
        await this.emailService.sendVerificationEmail(normalizedEmail, token, appId, redirect);
        await this.tokenRepo.setVerificationEmailCooldown(existingAppUser.id, 60);
      } catch (error: unknown) {
        await this.tokenRepo.deleteEmailVerificationToken(token);
        throw error;
      }

      await this.auditLogRepo.log({
        action: "register",
        userId: existingAppUser.id,
        email: normalizedEmail,
        ip,
        userAgent,
        details: { appId, overwrittenUnverified: true },
      });
      return;
    }

    const phash = await hashPassword(password, this.hashIterations);
    const userId = generateUUIDv7();

    try {
      await this.userRepo.create({
        id: userId,
        app: appId,
        email: normalizedEmail,
        phash,
        metadata: "{}",
        email_verified: 0,
        token_version: 1,
        two_factor_secret: null,
        two_factor_enabled: 0,
        is_locked: 0,
      });
    } catch (error: unknown) {
      if (isUniqueConstraintError(error)) {
        throw new AppError("Account already exists for this app.", 409);
      }
      throw error;
    }

    const token = crypto.randomUUID();
    await this.tokenRepo.saveEmailVerificationToken(token, userId, 1);

    try {
      await this.emailService.sendVerificationEmail(normalizedEmail, token, appId, redirect);
      await this.tokenRepo.setVerificationEmailCooldown(userId, 60);
    } catch (error: unknown) {
      await this.tokenRepo.deleteEmailVerificationToken(token);
      await this.userRepo.delete(userId);
      throw error;
    }

    await this.auditLogRepo.log({
      action: "register",
      userId,
      email: normalizedEmail,
      ip,
      userAgent,
      details: { appId },
    });
  }

  async requestNewVerification(
    email: string,
    appId: string,
    redirect: string,
    ip: string,
    userAgent: string,
  ): Promise<void> {
    const normalizedEmail = email.trim().toLowerCase();
    const user = await this.userRepo.findForLogin(normalizedEmail, appId);
    if (!user || user.email_verified === 1) {
      return;
    }

    if (await this.tokenRepo.isVerificationEmailOnCooldown(user.id)) {
      return;
    }

    const token = crypto.randomUUID();
    await this.tokenRepo.saveEmailVerificationToken(token, user.id, user.token_version);

    try {
      await this.emailService.sendVerificationEmail(user.email, token, appId, redirect);
      await this.tokenRepo.setVerificationEmailCooldown(user.id, 60);
    } catch (error: unknown) {
      await this.tokenRepo.deleteEmailVerificationToken(token);
      throw error;
    }

    await this.auditLogRepo.log({
      action: "verification_email_requested",
      userId: user.id,
      email: user.email,
      ip,
      userAgent,
    });
  }

  async verifyEmailToken(token: string, ip: string, userAgent: string): Promise<void> {
    const tokenData = await this.tokenRepo.consumeVerifyToken(token);
    if (!tokenData) {
      await this.auditLogRepo.log({
        action: "verify_email_failed",
        ip,
        userAgent,
        details: { reason: "invalid_token" },
      });
      throw new AppError("Verification link is invalid or has expired.", 400);
    }

    const user = await this.userRepo.findById(tokenData.userId);
    if (!user || user.token_version !== tokenData.tokenVersion) {
      await this.auditLogRepo.log({
        action: "verify_email_failed",
        userId: user?.id ?? null,
        email: user?.email,
        ip,
        userAgent,
        details: { reason: user ? "stale_token" : "user_not_found" },
      });
      throw new AppError("Verification link is invalid or has expired.", 400);
    }

    await assertNoVerifiedAccountConflict(this.userRepo, user);

    await this.userRepo.markEmailVerified(user.id);
    if (user.app === "sso") {
      await this.userRepo.deleteUnverifiedByEmail(user.email, user.id);
    }

    await this.auditLogRepo.log({
      action: "email_verified",
      userId: user.id,
      email: user.email,
      ip,
      userAgent,
    });
  }

  verifySession(
    sessionId: string,
    requiredAppId: string,
    currentIp?: string,
    currentUserAgent?: string,
    options?: VerifySessionOptions,
  ): Promise<Session> {
    return this.sessionService.verifySession(sessionId, requiredAppId, currentIp, currentUserAgent, options);
  }

  logout(sessionId: string, expectedAppId?: string): Promise<void> {
    return this.sessionService.logout(sessionId, expectedAppId);
  }

  logoutAll(userId: string, ip: string, userAgent: string): Promise<void> {
    return this.sessionService.logoutAll(userId, ip, userAgent);
  }

  logoutAllByEmail(email: string, ip: string, userAgent: string): Promise<void> {
    return this.sessionService.logoutAllByEmail(email, ip, userAgent);
  }

  requestPasswordReset(email: string, appId: string, ip: string, userAgent: string): Promise<void> {
    return this.passwordService.requestPasswordReset(email, appId, ip, userAgent);
  }

  resetPassword(token: string, newPassword: string, ip: string, userAgent: string): Promise<string> {
    return this.passwordService.resetPassword(token, newPassword, ip, userAgent);
  }

  changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
    ip: string,
    userAgent: string,
  ): Promise<void> {
    return this.passwordService.changePassword(userId, currentPassword, newPassword, ip, userAgent);
  }

  requestMagicLink(email: string, appId: string, redirect: string, ip: string, userAgent: string): Promise<void> {
    return this.magicLinkService.requestMagicLink(email, appId, redirect, ip, userAgent);
  }

  verifyMagicLink(token: string, requiredAppId: string, ip: string, userAgent: string): Promise<LoginResult> {
    return this.magicLinkService.verifyMagicLink(token, requiredAppId, ip, userAgent);
  }

  verifyTwoFactorLogin(
    token: string,
    code: string,
    ip: string,
    userAgent: string,
    expectedAppId?: string,
  ): Promise<LoginSuccessResult> {
    return this.twoFactorService.verifyTwoFactorLogin(token, code, ip, userAgent, expectedAppId);
  }

  enableTwoFactor(userId: string, code: string, ip?: string, userAgent?: string): Promise<void> {
    return this.twoFactorService.enableTwoFactor(userId, code, ip, userAgent);
  }

  disableTwoFactor(userId: string, code: string, ip?: string, userAgent?: string): Promise<void> {
    return this.twoFactorService.disableTwoFactor(userId, code, ip, userAgent);
  }

  getTwoFactorSetupSecret(userId: string): Promise<string | null> {
    return this.twoFactorService.getTwoFactorSetupSecret(userId);
  }

  saveTwoFactorSetupSecret(userId: string, secret: string): Promise<void> {
    return this.twoFactorService.saveTwoFactorSetupSecret(userId, secret);
  }
}
