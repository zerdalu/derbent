import type { Session } from "@shared/schemas/auth";
import { JsonObjectSchema, type JsonObject } from "@shared/types/json";
import type { AppRepository } from "@worker/repositories/app.repository";
import type { AuditLogRepository } from "@worker/repositories/audit-log.repository";
import type { LoginAttemptRepository } from "@worker/repositories/login-attempt.repository";
import type { SessionRepository } from "@worker/repositories/session.repository";
import type { TokenRepository } from "@worker/repositories/token.repository";
import type { UserTokenVersionRepository } from "@worker/repositories/user-token-version.repository";
import type { UserRepository } from "@worker/repositories/user.repository";
import type { EmailService } from "@worker/services/email.service";
import { AppError } from "@worker/types/errors";
import type { LoginResult, LoginSuccessResult, UserRecord } from "@worker/types/models";
import { hashPassword, needsRehash, verifyPassword } from "@worker/utils/crypto";
import { verifyTOTP } from "@worker/utils/totp";
import { generateUUIDv7 } from "@worker/utils/uuid";
import * as v from "valibot";

const MAX_2FA_TOKEN_ATTEMPTS = 5;
const MAX_IP_LOGIN_ATTEMPTS = 5;
const MAX_EMAIL_LOGIN_ATTEMPTS = 15;

export class AuthService {
  private readonly userRepo: UserRepository;
  private readonly sessionRepo: SessionRepository;
  private readonly tokenRepo: TokenRepository;
  private readonly userTokenVersionRepo: UserTokenVersionRepository;
  private readonly appRepo: AppRepository;
  private readonly emailService: EmailService;
  private readonly auditLogRepo: AuditLogRepository;
  private readonly loginAttemptRepo: LoginAttemptRepository;
  private readonly hashIterations: number;

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
    this.sessionRepo = sessionRepo;
    this.tokenRepo = tokenRepo;
    this.userTokenVersionRepo = userTokenVersionRepo;
    this.appRepo = appRepo;
    this.emailService = emailService;
    this.auditLogRepo = auditLogRepo;
    this.loginAttemptRepo = loginAttemptRepo;
    this.hashIterations = hashIterations;
  }

  private async verifyPasswordSafe(password: string, user: UserRecord | null): Promise<boolean> {
    const dummySalt = "U29tZVJhbmRvbVNhbHQ=";
    const dummyHashPart = "U29tZVJhbmRvbUhhc2g=";
    const dummyHash = `pbkdf2_sha256:${this.hashIterations}:${dummySalt}:${dummyHashPart}`;
    const isRealUserWithPassword = Boolean(user && !user.phash.startsWith("OAUTH:"));
    const targetHash = isRealUserWithPassword && user ? user.phash : dummyHash;
    const isMatch = await verifyPassword(password, targetHash);
    return isRealUserWithPassword && isMatch;
  }

  private async createSessionForUser(user: UserRecord, ip: string, userAgent: string): Promise<string> {
    let userMetadata: JsonObject = {};
    if (user.metadata) {
      try {
        const parsed: unknown = JSON.parse(user.metadata);
        const result = v.safeParse(JsonObjectSchema, parsed);
        if (result.success) {
          userMetadata = result.output;
        }
      } catch (error: unknown) {
        if (error instanceof Error) {
          console.error("Failed to parse user metadata:", error.message);
        }
      }
    }

    const sessionId = crypto.randomUUID();
    const session: Session = {
      userId: user.id,
      email: user.email,
      appId: user.app,
      createdAt: Date.now(),
      ip,
      userAgent,
      tokenVersion: user.token_version,
      data: userMetadata,
    };

    await this.sessionRepo.create(sessionId, session);
    await this.userTokenVersionRepo.setUserVersion(user.id, user.token_version);
    return sessionId;
  }

  private async handleSuccessfulAuthentication(
    user: UserRecord,
    appId: string,
    ip: string,
    userAgent: string,
    method: string,
  ): Promise<LoginResult> {
    if (user.two_factor_enabled === 1) {
      const token = crypto.randomUUID();
      await this.tokenRepo.saveTwoFactorLoginToken(token, {
        userId: user.id,
        appId,
        ip,
        userAgent,
      });
      return { requires2FA: true, twoFactorToken: token, app: user.app };
    }

    const sessionId = await this.createSessionForUser(user, ip, userAgent);
    await this.auditLogRepo.log({
      action: "login_success",
      userId: user.id,
      email: user.email,
      ip,
      userAgent,
      details: { appId: user.app, sessionId, method },
    });
    return { requires2FA: false, sessionId, app: user.app };
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
    if (ipAttempts >= MAX_IP_LOGIN_ATTEMPTS || emailAttempts >= MAX_EMAIL_LOGIN_ATTEMPTS) {
      throw new AppError("Too many failed login attempts from this network. Please try again in 15 minutes.", 429);
    }

    const user = await this.userRepo.findForLogin(normalizedEmail, appId);
    const isPasswordVerified = await this.verifyPasswordSafe(password, user);

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

    return this.handleSuccessfulAuthentication(user, appId, ip, userAgent, "password");
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

    if (!user) {
      if (appRecord.allow_signups === 0) {
        throw new AppError("Registrations are currently closed for this application.", 403);
      }

      if (appId !== "sso") {
        const ssoAppRecord = await this.appRepo.findById("sso");
        if (!ssoAppRecord || ssoAppRecord.allow_signups === 0) {
          throw new AppError("Registrations are currently closed for this application.", 403);
        }
      }

      if (await this.userRepo.hasAnyAppAccount(normalizedEmail)) {
        throw new AppError("An app-level account already exists for this email.", 409);
      }

      const userId = generateUUIDv7();
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
      user = await this.userRepo.findById(userId);
    }

    if (!user) {
      throw new AppError("Failed to sync user", 500);
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
      await this.userTokenVersionRepo.clearUserVersion(user.id);
      const refreshedUser = await this.userRepo.findById(user.id);
      if (!refreshedUser) {
        throw new AppError("Failed to sync user", 500);
      }
      user = refreshedUser;
    }

    return this.handleSuccessfulAuthentication(user, appId, ip, userAgent, `oauth_${provider}`);
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
    if (existingSso) {
      throw new AppError("An SSO account already exists for this email.", 409);
    }

    if (appId !== "sso") {
      const existingAppUser = await this.userRepo.findByEmailAndApp(normalizedEmail, appId);
      if (existingAppUser) {
        throw new AppError("Account already exists for this app.", 409);
      }
    } else if (await this.userRepo.hasAnyAppAccount(normalizedEmail)) {
      throw new AppError("An app-level account already exists for this email.", 409);
    }

    const phash = await hashPassword(password, this.hashIterations);
    const userId = generateUUIDv7();

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

    const token = crypto.randomUUID();
    await this.tokenRepo.saveEmailVerificationToken(token, userId);

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
    await this.tokenRepo.saveEmailVerificationToken(token, user.id);
    await this.tokenRepo.setVerificationEmailCooldown(user.id, 60);
    await this.emailService.sendVerificationEmail(user.email, token, appId, redirect);

    await this.auditLogRepo.log({
      action: "verification_email_requested",
      userId: user.id,
      email: user.email,
      ip,
      userAgent,
    });
  }

  async verifySession(
    sessionId: string,
    requiredAppId: string,
    currentIp?: string,
    currentUserAgent?: string,
  ): Promise<Session> {
    const session = await this.sessionRepo.get(sessionId);
    if (!session) {
      throw new AppError("Session not found", 401);
    }

    if (session.appId !== requiredAppId && session.appId !== "sso") {
      throw new AppError("Forbidden", 403);
    }

    const targetApp = await this.appRepo.findById(requiredAppId);
    if (!targetApp || targetApp.allow_logins === 0) {
      throw new AppError("Logins are currently disabled for this application.", 403);
    }

    if (currentUserAgent && session.userAgent !== currentUserAgent) {
      await this.auditLogRepo.log({
        action: "security_alert_hijack",
        userId: session.userId,
        email: session.email,
        ip: currentIp,
        userAgent: currentUserAgent,
        details: { reason: "user_agent_mismatch", expected: session.userAgent },
      });
      throw new AppError("Session invalid (Client Mismatch)", 401);
    }

    if (currentIp && session.ip !== currentIp) {
      await this.auditLogRepo.log({
        action: "security_notice_ip_changed",
        userId: session.userId,
        email: session.email,
        ip: currentIp,
        userAgent: currentUserAgent,
        details: { sessionIp: session.ip, currentIp },
      });
    }

    let currentVersion = await this.userTokenVersionRepo.getUserVersion(session.userId);
    if (currentVersion === null) {
      const user = await this.userRepo.findById(session.userId);
      if (!user || user.is_locked === 1) {
        throw new AppError("User not found or locked", 401);
      }
      currentVersion = user.token_version;
      await this.userTokenVersionRepo.setUserVersion(user.id, currentVersion);
    }

    if (session.tokenVersion !== currentVersion) {
      throw new AppError("Session expired (Revoked)", 401);
    }

    return session;
  }

  async verifyEmailToken(token: string, ip: string, userAgent: string): Promise<void> {
    const userId = await this.tokenRepo.getUserIdFromVerifyToken(token);
    if (!userId) {
      await this.auditLogRepo.log({
        action: "verify_email_failed",
        ip,
        userAgent,
        details: { reason: "invalid_token" },
      });
      throw new AppError("Verification link is invalid or has expired.", 400);
    }

    const user = await this.userRepo.findById(userId);
    if (!user) {
      throw new AppError("Verification link is invalid or has expired.", 400);
    }

    await this.userRepo.markEmailVerified(userId);
    await this.tokenRepo.deleteEmailVerificationToken(token);

    await this.auditLogRepo.log({
      action: "email_verified",
      userId,
      email: user.email,
      ip,
      userAgent,
    });
  }

  async logout(sessionId: string, expectedAppId?: string): Promise<void> {
    const session = await this.sessionRepo.get(sessionId);
    if (session && expectedAppId && session.appId !== expectedAppId && session.appId !== "sso") {
      throw new AppError("Forbidden", 403);
    }

    await this.sessionRepo.delete(sessionId);

    if (session) {
      await this.auditLogRepo.log({
        action: "logout",
        userId: session.userId,
        email: session.email,
        ip: session.ip,
        details: { appId: session.appId },
      });
    }
  }

  async logoutAll(userId: string, ip: string, userAgent: string): Promise<void> {
    const newVersion = await this.userRepo.incrementTokenVersion(userId);
    await this.userTokenVersionRepo.setUserVersion(userId, newVersion);
    await this.auditLogRepo.log({ action: "logout_all_devices", userId, ip, userAgent });
  }

  async logoutAllByEmail(email: string, ip: string, userAgent: string): Promise<void> {
    const normalizedEmail = email.trim().toLowerCase();
    const users = await this.userRepo.findAllByEmail(normalizedEmail);
    for (const user of users) {
      const newVersion = await this.userRepo.incrementTokenVersion(user.id);
      await this.userTokenVersionRepo.setUserVersion(user.id, newVersion);
    }

    await this.auditLogRepo.log({
      action: "logout_all_by_email",
      email: normalizedEmail,
      ip,
      userAgent,
      details: { affectedAccounts: users.length },
    });
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

    const token = crypto.randomUUID();
    await this.tokenRepo.savePasswordResetToken(token, user.id);
    await this.emailService.sendPasswordResetEmail(user.email, token);
  }

  async resetPassword(token: string, newPassword: string, ip: string, userAgent: string): Promise<string> {
    const userId = await this.tokenRepo.getUserIdFromResetToken(token);
    if (!userId) {
      await this.auditLogRepo.log({
        action: "password_reset_failed",
        ip,
        userAgent,
        details: { reason: "invalid_token" },
      });
      throw new AppError("Reset link is invalid or has expired.", 400);
    }

    const user = await this.userRepo.findById(userId);
    if (!user) {
      throw new AppError("User not found.", 400);
    }

    if (user.phash.startsWith("OAUTH:")) {
      throw new AppError("Password reset is not available for OAuth-only accounts.", 400);
    }

    if (user.is_locked === 1) {
      throw new AppError("This account has been locked. Please contact support.", 403);
    }

    const phash = await hashPassword(newPassword, this.hashIterations);
    await this.userRepo.updatePassword(userId, phash);
    await this.userTokenVersionRepo.clearUserVersion(userId);
    await this.tokenRepo.deletePasswordResetToken(token);
    await this.loginAttemptRepo.clearAttempts(user.email, ip);

    await this.auditLogRepo.log({
      action: "password_reset_success",
      userId,
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

  async requestMagicLink(email: string, appId: string, redirect: string, ip: string, userAgent: string): Promise<void> {
    const normalizedEmail = email.trim().toLowerCase();
    const appRecord = await this.appRepo.findById(appId);
    if (!appRecord || appRecord.allow_logins === 0) {
      throw new AppError("Logins are currently disabled for this application.", 403);
    }

    const user = await this.userRepo.findForLogin(normalizedEmail, appId);
    const canSend = Boolean(user && user.is_locked === 0 && user.email_verified === 1);

    await this.auditLogRepo.log({
      action: "magic_link_requested",
      email: normalizedEmail,
      userId: user?.id ?? null,
      ip,
      userAgent,
      details: { appId, eligible: canSend },
    });

    if (!user || !canSend) {
      return;
    }

    const token = crypto.randomUUID();
    await this.tokenRepo.saveMagicLinkToken(token, user.id);
    await this.emailService.sendMagicLinkEmail(user.email, token, appId, redirect);
  }

  async verifyMagicLink(token: string, requiredAppId: string, ip: string, userAgent: string): Promise<LoginResult> {
    const appRecord = await this.appRepo.findById(requiredAppId);
    if (!appRecord || appRecord.allow_logins === 0) {
      throw new AppError("Logins are currently disabled for this application.", 403);
    }

    const userId = await this.tokenRepo.getUserIdFromMagicLinkToken(token);
    if (!userId) {
      await this.auditLogRepo.log({
        action: "magic_link_failed",
        ip,
        userAgent,
        details: { reason: "invalid_token" },
      });
      throw new AppError("Magic link is invalid or has expired.", 400);
    }

    const user = await this.userRepo.findById(userId);
    if (!user) {
      throw new AppError("User not found.", 400);
    }

    if (user.is_locked === 1) {
      await this.auditLogRepo.log({
        action: "login_failed_locked",
        userId: user.id,
        email: user.email,
        ip,
        userAgent,
        details: { appId: requiredAppId, method: "magic_link" },
      });
      throw new AppError("This account has been locked. Please contact support.", 403);
    }

    if (user.app !== requiredAppId && user.app !== "sso") {
      await this.auditLogRepo.log({
        action: "magic_link_forbidden",
        userId,
        email: user.email,
        ip,
        userAgent,
        details: { requiredAppId, userApp: user.app },
      });
      throw new AppError("Forbidden: You do not have access to this app.", 403);
    }

    if (user.email_verified === 0) {
      await this.tokenRepo.deleteMagicLinkToken(token);
      throw new AppError("Email verification is required.", 403, "EMAIL_NOT_VERIFIED");
    }

    await this.tokenRepo.deleteMagicLinkToken(token);
    await this.userTokenVersionRepo.setUserVersion(user.id, user.token_version);

    return this.handleSuccessfulAuthentication(user, requiredAppId, ip, userAgent, "magic_link");
  }

  async verifyTwoFactorLogin(
    token: string,
    code: string,
    ip: string,
    userAgent: string,
    expectedAppId?: string,
  ): Promise<LoginSuccessResult> {
    const loginData = await this.tokenRepo.getTwoFactorLoginData(token);
    if (!loginData) {
      throw new AppError("Session expired. Please log in again.", 401);
    }

    if (expectedAppId && loginData.appId !== expectedAppId) {
      throw new AppError("Application context mismatch for two-factor verification.", 400);
    }

    if (loginData.userAgent !== userAgent) {
      await this.tokenRepo.deleteTwoFactorLoginToken(token);
      await this.auditLogRepo.log({
        action: "security_alert_hijack",
        userId: loginData.userId,
        ip,
        userAgent,
        details: { reason: "2fa_user_agent_mismatch", expected: loginData.userAgent },
      });
      throw new AppError("Session invalid (Client Mismatch)", 401);
    }

    const appRecord = await this.appRepo.findById(loginData.appId);
    if (!appRecord || appRecord.allow_logins === 0) {
      throw new AppError("Logins are currently disabled for this application.", 403);
    }

    const user = await this.userRepo.findById(loginData.userId);
    if (!user || user.two_factor_enabled === 0 || !user.two_factor_secret) {
      throw new AppError("Invalid request.", 400);
    }

    if (user.is_locked === 1) {
      await this.auditLogRepo.log({
        action: "login_failed_locked",
        userId: user.id,
        email: user.email,
        ip,
        userAgent,
        details: { appId: loginData.appId, method: "2fa" },
      });
      throw new AppError("This account has been locked. Please contact support.", 403);
    }

    const isCodeReused = await this.tokenRepo.isTotpCodeUsed(user.id, code);
    if (isCodeReused) {
      throw new AppError("Code has already been used. Please wait for the next authenticator code.", 400);
    }

    const isValid = await verifyTOTP(user.two_factor_secret, code);
    if (!isValid) {
      const attempts = await this.tokenRepo.incrementTwoFactorLoginAttempts(token, loginData);
      await this.auditLogRepo.log({
        action: "login_2fa_failed",
        userId: user.id,
        email: user.email,
        ip,
        userAgent,
        details: { attempts },
      });
      if (attempts >= MAX_2FA_TOKEN_ATTEMPTS) {
        await this.tokenRepo.deleteTwoFactorLoginToken(token);
        throw new AppError("Too many failed verification attempts. Please sign in again.", 429);
      }
      throw new AppError("Invalid two-factor code.", 400);
    }

    await this.tokenRepo.markTotpCodeUsed(user.id, code, 90);
    await this.tokenRepo.deleteTwoFactorLoginToken(token);

    const sessionId = await this.createSessionForUser(user, ip, userAgent);

    await this.auditLogRepo.log({
      action: "login_success",
      userId: user.id,
      email: user.email,
      ip,
      userAgent,
      details: { appId: loginData.appId, sessionId, method: "2fa" },
    });

    return { requires2FA: false, sessionId, app: user.app };
  }

  async enableTwoFactor(userId: string, code: string): Promise<void> {
    const secret = await this.tokenRepo.getTwoFactorSetupSecret(userId);
    if (!secret) {
      throw new AppError("Setup session expired. Please try again.", 400);
    }

    const isCodeReused = await this.tokenRepo.isTotpCodeUsed(userId, code);
    if (isCodeReused) {
      throw new AppError("Code has already been used. Please wait for the next authenticator code.", 400);
    }

    const isValid = await verifyTOTP(secret, code);
    if (!isValid) {
      const attempts = await this.tokenRepo.incrementTotpActionAttempts(userId);
      if (attempts >= MAX_2FA_TOKEN_ATTEMPTS) {
        await this.tokenRepo.deleteTwoFactorSetupSecret(userId);
        await this.tokenRepo.clearTotpActionAttempts(userId);
        throw new AppError("Too many failed verification attempts. Setup session has been reset.", 429);
      }
      throw new AppError("Invalid code. Please try again.", 400);
    }

    await this.tokenRepo.clearTotpActionAttempts(userId);
    await this.tokenRepo.markTotpCodeUsed(userId, code, 90);
    await this.userRepo.enableTwoFactor(userId, secret);
    await this.tokenRepo.deleteTwoFactorSetupSecret(userId);

    await this.auditLogRepo.log({ action: "2fa_enabled", userId });
  }

  async disableTwoFactor(userId: string, code: string): Promise<void> {
    const user = await this.userRepo.findById(userId);
    if (!user || user.two_factor_enabled === 0 || !user.two_factor_secret) {
      throw new AppError("2FA is not enabled.", 400);
    }

    const isCodeReused = await this.tokenRepo.isTotpCodeUsed(userId, code);
    if (isCodeReused) {
      throw new AppError("Code has already been used. Please wait for the next authenticator code.", 400);
    }

    const isValid = await verifyTOTP(user.two_factor_secret, code);
    if (!isValid) {
      const attempts = await this.tokenRepo.incrementTotpActionAttempts(userId);
      await this.auditLogRepo.log({
        action: "2fa_disable_failed",
        userId,
        email: user.email,
        details: { attempts },
      });
      if (attempts >= MAX_2FA_TOKEN_ATTEMPTS) {
        const newVersion = await this.userRepo.incrementTokenVersion(userId);
        await this.userTokenVersionRepo.setUserVersion(userId, newVersion);
        await this.tokenRepo.clearTotpActionAttempts(userId);
        throw new AppError("Too many failed verification attempts. Please sign in again.", 429);
      }
      throw new AppError("Invalid code.", 400);
    }

    await this.tokenRepo.clearTotpActionAttempts(userId);
    await this.tokenRepo.markTotpCodeUsed(userId, code, 90);
    await this.userRepo.disableTwoFactor(userId);

    await this.auditLogRepo.log({ action: "2fa_disabled", userId, email: user.email });
  }

  async getTwoFactorSetupSecret(userId: string): Promise<string | null> {
    return await this.tokenRepo.getTwoFactorSetupSecret(userId);
  }

  async saveTwoFactorSetupSecret(userId: string, secret: string): Promise<void> {
    await this.tokenRepo.saveTwoFactorSetupSecret(userId, secret);
  }
}
