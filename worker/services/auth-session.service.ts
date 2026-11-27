import type { Session } from "@shared/schemas/auth";
import { JsonObjectSchema, type JsonObject } from "@shared/types/json";
import type { AppRepository } from "@worker/repositories/app.repository";
import type { AuditLogRepository } from "@worker/repositories/audit-log.repository";
import type { SessionRepository } from "@worker/repositories/session.repository";
import type { TokenRepository } from "@worker/repositories/token.repository";
import type { UserTokenVersionRepository } from "@worker/repositories/user-token-version.repository";
import type { UserRepository } from "@worker/repositories/user.repository";
import { AppError } from "@worker/types/errors";
import type { LoginResult, UserRecord } from "@worker/types/models";
import * as v from "valibot";

export interface VerifySessionOptions {
  readonly allowDisabledApp?: boolean;
}

export class AuthSessionService {
  private readonly userRepo: UserRepository;
  private readonly sessionRepo: SessionRepository;
  private readonly tokenRepo: TokenRepository;
  private readonly userTokenVersionRepo: UserTokenVersionRepository;
  private readonly appRepo: AppRepository;
  private readonly auditLogRepo: AuditLogRepository;

  constructor(
    userRepo: UserRepository,
    sessionRepo: SessionRepository,
    tokenRepo: TokenRepository,
    userTokenVersionRepo: UserTokenVersionRepository,
    appRepo: AppRepository,
    auditLogRepo: AuditLogRepository,
  ) {
    this.userRepo = userRepo;
    this.sessionRepo = sessionRepo;
    this.tokenRepo = tokenRepo;
    this.userTokenVersionRepo = userTokenVersionRepo;
    this.appRepo = appRepo;
    this.auditLogRepo = auditLogRepo;
  }

  async createSessionForUser(user: UserRecord, ip: string, userAgent: string): Promise<string> {
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

  async handleSuccessfulAuthentication(
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

  async verifySession(
    sessionId: string,
    requiredAppId: string,
    currentIp?: string,
    currentUserAgent?: string,
    options?: VerifySessionOptions,
  ): Promise<Session> {
    const session = await this.sessionRepo.get(sessionId);
    if (!session) {
      throw new AppError("Session not found", 401);
    }

    if (session.appId !== requiredAppId && session.appId !== "sso") {
      throw new AppError("Forbidden", 403);
    }

    if (!options?.allowDisabledApp) {
      const targetApp = await this.appRepo.findById(requiredAppId);
      if (!targetApp || targetApp.allow_logins === 0) {
        throw new AppError("Logins are currently disabled for this application.", 403);
      }

      if (session.appId === "sso" && requiredAppId !== "sso") {
        const ssoApp = await this.appRepo.findById("sso");
        if (!ssoApp || ssoApp.allow_logins === 0) {
          throw new AppError("Single sign-on is currently disabled.", 403);
        }
      }
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
      const alreadyLogged = await this.tokenRepo.hasLoggedIpChangeNotice(sessionId, currentIp);
      if (!alreadyLogged) {
        await this.auditLogRepo.log({
          action: "security_notice_ip_changed",
          userId: session.userId,
          email: session.email,
          ip: currentIp,
          userAgent: currentUserAgent,
          details: { sessionIp: session.ip, currentIp },
        });
        await this.tokenRepo.markIpChangeNoticeLogged(sessionId, currentIp);
      }
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
}
