import type { AppRepository } from "@worker/repositories/app.repository";
import type { AuditLogRepository } from "@worker/repositories/audit-log.repository";
import type { TokenRepository } from "@worker/repositories/token.repository";
import type { UserRepository } from "@worker/repositories/user.repository";
import type { AuthSessionService } from "@worker/services/auth-session.service";
import type { EmailService } from "@worker/services/email.service";
import { AppError } from "@worker/types/errors";
import type { LoginResult } from "@worker/types/models";

export class AuthMagicLinkService {
  private readonly userRepo: UserRepository;
  private readonly tokenRepo: TokenRepository;
  private readonly appRepo: AppRepository;
  private readonly emailService: EmailService;
  private readonly auditLogRepo: AuditLogRepository;
  private readonly sessionService: AuthSessionService;

  constructor(
    userRepo: UserRepository,
    tokenRepo: TokenRepository,
    appRepo: AppRepository,
    emailService: EmailService,
    auditLogRepo: AuditLogRepository,
    sessionService: AuthSessionService,
  ) {
    this.userRepo = userRepo;
    this.tokenRepo = tokenRepo;
    this.appRepo = appRepo;
    this.emailService = emailService;
    this.auditLogRepo = auditLogRepo;
    this.sessionService = sessionService;
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

    if (await this.tokenRepo.isMagicLinkOnCooldown(user.id)) {
      return;
    }

    const token = crypto.randomUUID();
    await this.tokenRepo.saveMagicLinkToken(token, user.id, user.token_version);

    try {
      await this.emailService.sendMagicLinkEmail(user.email, token, appId, redirect);
      await this.tokenRepo.setMagicLinkCooldown(user.id, 60);
    } catch (error: unknown) {
      await this.tokenRepo.deleteMagicLinkToken(token);
      throw error;
    }
  }

  async verifyMagicLink(token: string, requiredAppId: string, ip: string, userAgent: string): Promise<LoginResult> {
    const appRecord = await this.appRepo.findById(requiredAppId);
    if (!appRecord || appRecord.allow_logins === 0) {
      throw new AppError("Logins are currently disabled for this application.", 403);
    }

    const tokenData = await this.tokenRepo.getMagicLinkTokenData(token);
    if (!tokenData) {
      await this.auditLogRepo.log({
        action: "magic_link_failed",
        ip,
        userAgent,
        details: { reason: "invalid_token" },
      });
      throw new AppError("Magic link is invalid or has expired.", 400);
    }

    const user = await this.userRepo.findById(tokenData.userId);
    if (!user || user.token_version !== tokenData.tokenVersion) {
      await this.tokenRepo.deleteMagicLinkToken(token);
      await this.auditLogRepo.log({
        action: "magic_link_failed",
        userId: user?.id ?? null,
        email: user?.email,
        ip,
        userAgent,
        details: { reason: user ? "stale_token" : "user_not_found" },
      });
      throw new AppError("Magic link is invalid or has expired.", 400);
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
        userId: user.id,
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

    return this.sessionService.handleSuccessfulAuthentication(user, requiredAppId, ip, userAgent, "magic_link");
  }
}
