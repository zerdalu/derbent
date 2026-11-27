import type { HealthData, RpcLogoutResult, RpcVerifyResult } from "@shared/schemas/auth";
import type { ApiResponse } from "@shared/types/api-response";
import { AdminHandler } from "@worker/handlers/admin.handler";
import { AuthHandler } from "@worker/handlers/auth.handler";
import { OAuthHandler } from "@worker/handlers/oauth.handler";
import { configMiddleware, resolveEffectiveConfig } from "@worker/middleware/config.middleware";
import { csrfProtection } from "@worker/middleware/csrf.middleware";
import { adminAuth, rateLimit } from "@worker/middleware/guard.middleware";
import { EmailQueueMessageSchema } from "@worker/services/email.service";
import { AppError } from "@worker/types/errors";
import type { HonoEnv } from "@worker/types/hono-env";
import type { EmailQueueMessage } from "@worker/types/models";
import { parseCookieHeaderAll } from "@worker/utils/cookie";
import { createRuntimeServices, parseRetentionDays } from "@worker/utils/runtime";
import { WorkerEntrypoint } from "cloudflare:workers";
import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { secureHeaders } from "hono/secure-headers";
import * as v from "valibot";

const app = new Hono<HonoEnv>();

function resolveHttpErrorCode(status: number): string {
  switch (status) {
    case 400:
      return "BAD_REQUEST";
    case 401:
      return "UNAUTHORIZED";
    case 403:
      return "FORBIDDEN";
    case 404:
      return "NOT_FOUND";
    case 409:
      return "CONFLICT";
    case 422:
      return "UNPROCESSABLE_ENTITY";
    case 429:
      return "TOO_MANY_REQUESTS";
    default:
      return status >= 500 ? "INTERNAL_ERROR" : "HTTP_ERROR";
  }
}

app.use("*", secureHeaders());
app.use("*", configMiddleware());

app.use("*", async (c, next) => {
  const services = createRuntimeServices(c.env, c.get("config"));
  c.set("logger", services.logger);
  c.set("appRepo", services.appRepo);
  c.set("authService", services.authService);
  c.set("adminService", services.adminService);
  await next();
});

app.get("/api/health", (c): Response => {
  const successResponse: ApiResponse<HealthData> = {
    success: true,
    data: {
      status: "healthy",
      service: c.get("config").APP_NAME || "Derbent",
    },
  };
  return c.json(successResponse, 200);
});

// SPA Auth JSON API Routes
const authApiRoutes = new Hono<HonoEnv>();
authApiRoutes.use("*", csrfProtection());

authApiRoutes.get("/dashboard", (c) => AuthHandler.getDashboard(c));
authApiRoutes.get("/context", (c) => AuthHandler.getAuthContext(c));

authApiRoutes.post("/login", rateLimit(), (c) => AuthHandler.login(c));
authApiRoutes.post("/register", rateLimit(), (c) => AuthHandler.register(c));
authApiRoutes.post("/logout", rateLimit(), (c) => AuthHandler.logout(c));
authApiRoutes.post("/logout-all", rateLimit(), (c) => AuthHandler.logoutAll(c));
authApiRoutes.post("/logout-all-email", rateLimit(), (c) => AuthHandler.logoutAllByEmail(c));

authApiRoutes.post("/verify-email", rateLimit(), (c) => AuthHandler.verifyEmail(c));
authApiRoutes.post("/forgot-password", rateLimit(), (c) => AuthHandler.forgotPassword(c));
authApiRoutes.post("/reset-password", rateLimit(), (c) => AuthHandler.resetPassword(c));
authApiRoutes.post("/change-password", rateLimit(), (c) => AuthHandler.changePassword(c));

authApiRoutes.post("/magic-link/request", rateLimit(), (c) => AuthHandler.requestMagicLink(c));
authApiRoutes.post("/magic-link/verify", rateLimit(), (c) => AuthHandler.verifyMagicLink(c));

authApiRoutes.get("/2fa/setup", (c) => AuthHandler.getTwoFactorSetup(c));
authApiRoutes.post("/2fa/enable", rateLimit(), (c) => AuthHandler.enableTwoFactor(c));
authApiRoutes.post("/2fa/disable", rateLimit(), (c) => AuthHandler.disableTwoFactor(c));
authApiRoutes.post("/2fa/verify", rateLimit(), (c) => AuthHandler.verifyTwoFactorLogin(c));

app.route("/api/auth", authApiRoutes);

// OAuth Routes (kept at /auth/* for existing OAuth provider callback configurations)
app.get("/auth/github", rateLimit(), (c) => OAuthHandler.handleGitHubLogin(c));
app.get("/auth/github/callback", rateLimit(), (c) => OAuthHandler.handleGitHubCallback(c));
app.get("/auth/google", rateLimit(), (c) => OAuthHandler.handleGoogleLogin(c));
app.get("/auth/google/callback", rateLimit(), (c) => OAuthHandler.handleGoogleCallback(c));

// Admin Dashboard API Routes
const adminRoutes = new Hono<HonoEnv>();
adminRoutes.use("*", rateLimit(), adminAuth());

adminRoutes.get("/stats", (c) => AdminHandler.getStats(c));
adminRoutes.get("/settings", (c) => AdminHandler.getSettings(c));
adminRoutes.patch("/settings", (c) => AdminHandler.updateSettings(c));

adminRoutes.get("/apps", (c) => AdminHandler.getApps(c));
adminRoutes.get("/apps/:id", (c) => AdminHandler.getApp(c));
adminRoutes.post("/apps", (c) => AdminHandler.createApp(c));
adminRoutes.patch("/apps/:id", (c) => AdminHandler.updateApp(c));
adminRoutes.delete("/apps/:id", (c) => AdminHandler.deleteApp(c));

adminRoutes.get("/users", (c) => AdminHandler.getUsers(c));
adminRoutes.get("/users/:id", (c) => AdminHandler.getUser(c));
adminRoutes.patch("/users/:id", (c) => AdminHandler.updateUser(c));
adminRoutes.post("/users/:id/password", (c) => AdminHandler.forceResetPassword(c));
adminRoutes.delete("/users/:id/2fa", (c) => AdminHandler.disable2FA(c));
adminRoutes.delete("/users/:id", (c) => AdminHandler.deleteUser(c));
adminRoutes.delete("/users/:id/sessions", (c) => AdminHandler.revokeSessions(c));
adminRoutes.post("/users/:id/lock", (c) => AdminHandler.lockAccount(c));

adminRoutes.get("/audit-logs", (c) => AdminHandler.getAuditLogs(c));
adminRoutes.get("/users/:id/audit-logs", (c) => AdminHandler.getUserAuditLogs(c));

app.route("/api/admin", adminRoutes);

app.notFound((c): Response => {
  const notFoundResponse: ApiResponse<never> = {
    success: false,
    error: {
      code: "NOT_FOUND",
      message: "The requested edge endpoint was not found",
    },
  };
  return c.json(notFoundResponse, 404);
});

app.onError((err, c): Response => {
  if (err instanceof HTTPException) {
    if (err.res) {
      return err.getResponse();
    }

    const isServerError = err.status >= 500;
    if (isServerError) {
      console.error("Worker HTTP error:", err);
    }

    const httpErrorResponse: ApiResponse<never> = {
      success: false,
      error: {
        code: resolveHttpErrorCode(err.status),
        message: isServerError ? "An internal server error occurred" : err.message || "Request failed",
      },
    };
    return c.json(httpErrorResponse, err.status);
  }

  console.error("Worker error:", err);
  const errorResponse: ApiResponse<never> = {
    success: false,
    error: {
      code: "INTERNAL_ERROR",
      message: "An internal server error occurred",
    },
  };
  return c.json(errorResponse, 500);
});

function resolveSessionCookies(cookieHeader: string, appId: string): readonly string[] {
  const candidates: string[] = [];
  for (const appCookie of parseCookieHeaderAll(cookieHeader, `session_${appId}`)) {
    if (!candidates.includes(appCookie)) {
      candidates.push(appCookie);
    }
  }
  if (appId !== "sso") {
    for (const ssoCookie of parseCookieHeaderAll(cookieHeader, "session_sso")) {
      if (!candidates.includes(ssoCookie)) {
        candidates.push(ssoCookie);
      }
    }
  }
  return candidates;
}

export { app };

export default class DerbentWorker extends WorkerEntrypoint<CloudflareBindings> {
  async fetch(request: Request): Promise<Response> {
    return app.fetch(request, this.env, this.ctx);
  }

  async scheduled(controller: ScheduledController): Promise<void> {
    const config = await resolveEffectiveConfig(this.env);
    const services = createRuntimeServices(this.env, config, true);
    const retentionDays = parseRetentionDays(config.AUDIT_LOG_RETENTION_DAYS);

    services.logger.info(`[CRON] Event triggered: ${controller.cron}`);

    this.ctx.waitUntil(
      (async (): Promise<void> => {
        const deletedCount = await services.auditLogRepo.prune(retentionDays);
        services.logger.info(`[CRON] Pruned ${deletedCount} audit logs older than ${retentionDays} days.`);
      })(),
    );
  }

  async queue(batch: MessageBatch<EmailQueueMessage>): Promise<void> {
    const config = await resolveEffectiveConfig(this.env);
    const services = createRuntimeServices(this.env, config, true);

    services.logger.info(`[QUEUE] Processing batch of ${batch.messages.length} messages`);

    await Promise.allSettled(
      batch.messages.map(async (message) => {
        const rawBody: unknown = message.body;
        const parsed = v.safeParse(EmailQueueMessageSchema, rawBody);
        if (!parsed.success) {
          services.logger.warn(`[QUEUE] Dropping malformed email queue message ${message.id}`);
          message.ack();
          return;
        }

        try {
          await services.emailService.processMessage(parsed.output);
          message.ack();
        } catch (error: unknown) {
          services.logger.error(`[QUEUE] Failed to process message ${message.id}`, error);
          message.retry();
        }
      }),
    );
  }

  /**
   * Worker RPC endpoint for consuming Cloudflare Workers to verify user sessions.
   */
  async verifySession(
    cookieHeader: string,
    appId: string,
    clientIp: string,
    clientUserAgent: string,
  ): Promise<RpcVerifyResult> {
    const normalizedAppId = appId.trim();
    if (!normalizedAppId) {
      return {
        ok: false,
        status: 400,
        code: "BAD_REQUEST",
        message: "Missing appId",
      };
    }

    const normalizedUa = clientUserAgent.trim();
    if (!normalizedUa) {
      return {
        ok: false,
        status: 400,
        code: "BAD_REQUEST",
        message: "Missing client User-Agent context",
      };
    }

    const candidates = resolveSessionCookies(cookieHeader, normalizedAppId);
    if (candidates.length === 0) {
      return {
        ok: false,
        status: 401,
        code: "UNAUTHORIZED",
        message: "Unauthorized",
      };
    }

    const config = await resolveEffectiveConfig(this.env);
    const services = createRuntimeServices(this.env, config, true);
    const normalizedIp = clientIp.trim() || "127.0.0.1";

    let lastError: unknown = null;

    for (const sessionId of candidates) {
      try {
        const session = await services.authService.verifySession(
          sessionId,
          normalizedAppId,
          normalizedIp,
          normalizedUa,
        );
        return { ok: true, session };
      } catch (error: unknown) {
        if (!(lastError instanceof AppError && lastError.status === 403)) {
          lastError = error;
        }
      }
    }

    if (lastError instanceof AppError) {
      const status = lastError.status === 403 ? 403 : lastError.status === 400 ? 400 : 401;
      return {
        ok: false,
        status,
        code: lastError.code,
        message: lastError.message,
      };
    }

    services.logger.error("[RPC verifySession] Unexpected error:", lastError);
    return {
      ok: false,
      status: 500,
      code: "INTERNAL_ERROR",
      message: "Internal Server Error",
    };
  }

  /**
   * Worker RPC endpoint for consuming Cloudflare Workers to revoke the active session.
   */
  async logoutSession(cookieHeader: string, appId: string): Promise<RpcLogoutResult> {
    const normalizedAppId = appId.trim();
    if (!normalizedAppId) {
      return {
        ok: false,
        status: 400,
        code: "BAD_REQUEST",
        message: "Missing appId",
      };
    }

    const candidates = resolveSessionCookies(cookieHeader, normalizedAppId);
    if (candidates.length === 0) {
      return {
        ok: false,
        status: 401,
        code: "UNAUTHORIZED",
        message: "Unauthorized",
      };
    }

    const config = await resolveEffectiveConfig(this.env);
    const services = createRuntimeServices(this.env, config, true);

    let lastError: unknown = null;
    let loggedOutAny = false;

    for (const sessionId of candidates) {
      try {
        await services.authService.logout(sessionId, normalizedAppId);
        loggedOutAny = true;
      } catch (error: unknown) {
        lastError = error;
      }
    }

    if (loggedOutAny) {
      return { ok: true };
    }

    if (lastError instanceof AppError) {
      const status =
        lastError.status === 400 ? 400 : lastError.status === 401 ? 401 : lastError.status === 403 ? 403 : 500;
      return {
        ok: false,
        status,
        code: lastError.code,
        message: lastError.message,
      };
    }

    services.logger.error("[RPC logoutSession] Unexpected error:", lastError);
    return {
      ok: false,
      status: 500,
      code: "INTERNAL_ERROR",
      message: "Internal Server Error",
    };
  }
}
