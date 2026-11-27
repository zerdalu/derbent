import type { AppRepository } from "@worker/repositories/app.repository";
import type { AuditLogRepository } from "@worker/repositories/audit-log.repository";
import type { TokenRepository } from "@worker/repositories/token.repository";
import type { UserTokenVersionRepository } from "@worker/repositories/user-token-version.repository";
import type { UserRepository } from "@worker/repositories/user.repository";
import type { AuthSessionService } from "@worker/services/auth-session.service";
import { AppError } from "@worker/types/errors";
import type { LoginSuccessResult } from "@worker/types/models";
import { verifyTOTP } from "@worker/utils/totp";

const MAX_2FA_TOKEN_ATTEMPTS = 5;

export class AuthTwoFactorService {
  private readonly userRepo: UserRepository;
  private readonly tokenRepo: TokenRepository;
  private readonly userTokenVersionRepo: UserTokenVersionRepository;
  private readonly appRepo: AppRepository;
  private readonly auditLogRepo: AuditLogRepository;
  private readonly sessionService: AuthSessionService;

  constructor(
    userRepo: UserRepository,
    tokenRepo: TokenRepository,
    userTokenVersionRepo: UserTokenVersionRepository,
    appRepo: AppRepository,
    auditLogRepo: AuditLogRepository,
    sessionService: AuthSessionService,
  ) {
    this.userRepo = userRepo;
    this.tokenRepo = tokenRepo;
    this.userTokenVersionRepo = userTokenVersionRepo;
    this.appRepo = appRepo;
    this.auditLogRepo = auditLogRepo;
    this.sessionService = sessionService;
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

    const priorUserAttempts = await this.tokenRepo.getTotpActionAttempts(user.id);
    if (priorUserAttempts >= MAX_2FA_TOKEN_ATTEMPTS) {
      await this.tokenRepo.deleteTwoFactorLoginToken(token);
      throw new AppError("Too many failed verification attempts. Please try again in 5 minutes.", 429);
    }

    const isCodeReused = await this.tokenRepo.isTotpCodeUsed(user.id, code);
    if (isCodeReused) {
      throw new AppError("Code has already been used. Please wait for the next authenticator code.", 400);
    }

    const isValid = await verifyTOTP(user.two_factor_secret, code);
    if (!isValid) {
      const [tokenAttempts, userAttempts] = await Promise.all([
        this.tokenRepo.incrementTwoFactorLoginAttempts(token, loginData),
        this.tokenRepo.incrementTotpActionAttempts(user.id),
      ]);
      const effectiveAttempts = Math.max(tokenAttempts, userAttempts);

      await this.auditLogRepo.log({
        action: "login_2fa_failed",
        userId: user.id,
        email: user.email,
        ip,
        userAgent,
        details: { attempts: effectiveAttempts },
      });
      if (effectiveAttempts >= MAX_2FA_TOKEN_ATTEMPTS) {
        await this.tokenRepo.deleteTwoFactorLoginToken(token);
        throw new AppError("Too many failed verification attempts. Please try again in 5 minutes.", 429);
      }
      throw new AppError("Invalid two-factor code.", 400);
    }

    await this.tokenRepo.clearTotpActionAttempts(user.id);
    await this.tokenRepo.markTotpCodeUsed(user.id, code, 90);
    await this.tokenRepo.deleteTwoFactorLoginToken(token);

    const sessionId = await this.sessionService.createSessionForUser(user, ip, userAgent);

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

    const priorAttempts = await this.tokenRepo.getTotpActionAttempts(userId);
    if (priorAttempts >= MAX_2FA_TOKEN_ATTEMPTS) {
      await this.tokenRepo.deleteTwoFactorSetupSecret(userId);
      throw new AppError("Too many failed verification attempts. Please try again in 5 minutes.", 429);
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

    const priorAttempts = await this.tokenRepo.getTotpActionAttempts(userId);
    if (priorAttempts >= MAX_2FA_TOKEN_ATTEMPTS) {
      throw new AppError("Too many failed verification attempts. Please try again in 5 minutes.", 429);
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
