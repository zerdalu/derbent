import type { ApiResponse } from "@shared/types/api-response";
import { AppRepository } from "@worker/repositories/app.repository";
import { AuditLogRepository } from "@worker/repositories/audit-log.repository";
import { LoginAttemptRepository } from "@worker/repositories/login-attempt.repository";
import { SessionRepository } from "@worker/repositories/session.repository";
import { SettingsRepository } from "@worker/repositories/settings.repository";
import { TokenRepository } from "@worker/repositories/token.repository";
import { UserTokenVersionRepository } from "@worker/repositories/user-token-version.repository";
import { UserRepository } from "@worker/repositories/user.repository";
import { AdminService } from "@worker/services/admin.service";
import { AuthService } from "@worker/services/auth.service";
import { EmailService } from "@worker/services/email.service";
import { AppError } from "@worker/types/errors";
import type { HonoEnv } from "@worker/types/hono-env";
import type { AppRecord, DerbentConfig } from "@worker/types/models";
import { buildCookieOptions } from "@worker/utils/cookie";
import { Logger } from "@worker/utils/logger";
import { sanitizeRedirect } from "@worker/utils/url";
import type { Context } from "hono";
import { deleteCookie, getCookie } from "hono/cookie";

const MAX_PBKDF2_ITERATIONS = 100000;
const MIN_PBKDF2_ITERATIONS = 10000;

export interface RuntimeServices {
  readonly config: DerbentConfig;
  readonly logger: Logger;
  readonly userRepo: UserRepository;
  readonly sessionRepo: SessionRepository;
  readonly tokenRepo: TokenRepository;
  readonly userTokenVersionRepo: UserTokenVersionRepository;
  readonly auditLogRepo: AuditLogRepository;
  readonly loginAttemptRepo: LoginAttemptRepository;
  readonly settingsRepo: SettingsRepository;
  readonly appRepo: AppRepository;
  readonly emailService: EmailService;
  readonly authService: AuthService;
  readonly adminService: AdminService;
}

export interface ResolvedAppContext {
  readonly app: AppRecord;
  readonly appId: string;
  readonly appName: string;
  readonly redirect: string;
}

export function parseHashIterations(raw: string): number {
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(parsed) || parsed < MIN_PBKDF2_ITERATIONS) {
    return MAX_PBKDF2_ITERATIONS;
  }
  return Math.min(parsed, MAX_PBKDF2_ITERATIONS);
}

export function parseRetentionDays(raw: string): number {
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    return 30;
  }
  return parsed;
}

export function createRuntimeServices(
  env: CloudflareBindings,
  config: DerbentConfig,
  disableEmailQueue = false,
): RuntimeServices {
  const logger = new Logger(config.LOG_LEVEL || "info");
  const userRepo = new UserRepository(env.DB);
  const sessionRepo = new SessionRepository(env.KV);
  const tokenRepo = new TokenRepository(env.KV);
  const userTokenVersionRepo = new UserTokenVersionRepository(env.KV);
  const auditLogRepo = new AuditLogRepository(env.DB);
  const loginAttemptRepo = new LoginAttemptRepository(env.KV);
  const settingsRepo = new SettingsRepository(env.DB, env.KV);
  const appRepo = new AppRepository(env.DB);

  const isDev = config.APP_ENV === "development";
  const activeQueue = isDev || disableEmailQueue ? undefined : env.EMAIL_QUEUE;

  const emailService = new EmailService(
    isDev,
    config.APP_NAME,
    config.BASE_URL,
    config.RESEND_API_KEY || "",
    config.RESEND_DOMAIN || "",
    activeQueue,
    logger,
  );

  const hashIterations = parseHashIterations(config.PBKDF2_ITERATIONS);

  const authService = new AuthService(
    userRepo,
    sessionRepo,
    tokenRepo,
    userTokenVersionRepo,
    appRepo,
    emailService,
    auditLogRepo,
    loginAttemptRepo,
    hashIterations,
  );

  const adminService = new AdminService(
    userRepo,
    auditLogRepo,
    userTokenVersionRepo,
    appRepo,
    settingsRepo,
    hashIterations,
  );

  return {
    config,
    logger,
    userRepo,
    sessionRepo,
    tokenRepo,
    userTokenVersionRepo,
    auditLogRepo,
    loginAttemptRepo,
    settingsRepo,
    appRepo,
    emailService,
    authService,
    adminService,
  };
}

export function getClientInfo(c: Context<HonoEnv>): { readonly ip: string; readonly userAgent: string } {
  return {
    ip: c.req.header("cf-connecting-ip") || "unknown",
    userAgent: c.req.header("user-agent") || "unknown",
  };
}

export async function readJsonBody(c: Context<HonoEnv>): Promise<unknown> {
  try {
    return await c.req.json();
  } catch {
    throw new AppError("Invalid JSON request body.", 400, "INVALID_JSON");
  }
}

export function getAllowedAppOrigins(appRecord: AppRecord, appEnv?: string): readonly string[] {
  return appEnv === "development" ? [appRecord.prod_url, appRecord.dev_url] : [appRecord.prod_url];
}

export async function resolveAllowedOriginsForApp(
  appRepo: AppRepository,
  appRecord: AppRecord,
  appEnv?: string,
): Promise<readonly string[]> {
  if (appRecord.id !== "sso") {
    return getAllowedAppOrigins(appRecord, appEnv);
  }

  const allApps = await appRepo.findAll();
  const origins = new Set<string>(getAllowedAppOrigins(appRecord, appEnv));
  for (const candidate of allApps) {
    if (candidate.allow_logins === 1) {
      for (const origin of getAllowedAppOrigins(candidate, appEnv)) {
        origins.add(origin);
      }
    }
  }
  return Array.from(origins);
}

export async function resolveTargetApp(
  appRepo: AppRepository,
  rawAppId?: string,
  rawRedirect?: string,
  appEnv?: string,
  strictAppId = false,
): Promise<ResolvedAppContext> {
  const targetId = rawAppId?.trim() || "sso";
  let appRecord = await appRepo.findById(targetId);

  if (!appRecord) {
    if (strictAppId && targetId !== "sso") {
      throw new AppError("Target application was not found.", 404, "APP_NOT_FOUND");
    }
    appRecord = await appRepo.findById("sso");
  }

  if (!appRecord) {
    throw new AppError("SSO app configuration is missing.", 500);
  }

  const allowedOrigins = await resolveAllowedOriginsForApp(appRepo, appRecord, appEnv);
  const redirect = sanitizeRedirect(rawRedirect ?? "/", allowedOrigins);

  return {
    app: appRecord,
    appId: appRecord.id,
    appName: appRecord.name,
    redirect,
  };
}

export async function clearConflictingSessions(c: Context<HonoEnv>, newlyLoggedInApp: string): Promise<void> {
  const authService = c.get("authService");
  const appRepo = c.get("appRepo");
  const logger = c.get("logger");
  const cookieOpts = buildCookieOptions(c.get("config"));

  if (newlyLoggedInApp === "sso") {
    const allApps = await appRepo.findAll();
    for (const app of allApps) {
      if (app.id === "sso") {
        continue;
      }

      const cookieName = `session_${app.id}`;
      const existingSessionId = getCookie(c, cookieName);
      if (existingSessionId) {
        try {
          await authService.logout(existingSessionId);
        } catch (error: unknown) {
          if (error instanceof Error) {
            logger.warn(`Failed to clean up conflicting session ${cookieName}: ${error.message}`);
          }
        }
        deleteCookie(c, cookieName, cookieOpts);
      }
    }
    return;
  }

  const ssoSessionId = getCookie(c, "session_sso");
  if (ssoSessionId) {
    try {
      await authService.logout(ssoSessionId);
    } catch (error: unknown) {
      if (error instanceof Error) {
        logger.warn(`Failed to clean up SSO session: ${error.message}`);
      }
    }
    deleteCookie(c, "session_sso", cookieOpts);
  }

  const currentAppSessionId = getCookie(c, `session_${newlyLoggedInApp}`);
  if (currentAppSessionId) {
    try {
      await authService.logout(currentAppSessionId);
    } catch (error: unknown) {
      if (error instanceof Error) {
        logger.warn(`Failed to clean up current app session: ${error.message}`);
      }
    }
  }
}

export function handleApiError(c: Context<HonoEnv>, error: unknown): Response {
  if (error instanceof AppError) {
    const response: ApiResponse<never> = {
      success: false,
      error: {
        code: error.code,
        message: error.message,
      },
    };
    return c.json(response, error.status);
  }

  c.get("logger").error("Unhandled API error:", error);
  const response: ApiResponse<never> = {
    success: false,
    error: {
      code: "INTERNAL_ERROR",
      message: "An unexpected system error occurred. Please try again later.",
    },
  };
  return c.json(response, 500);
}
