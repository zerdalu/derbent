import {
  LoginInputSchema,
  RegisterInputSchema,
  VerifyEmailInputSchema,
  type AuthContextData,
  type DashboardAppStatus,
  type DashboardData,
  type LoginResultData,
  type PublicSessionSummary,
  type RedirectResultData,
  type Session,
  type SuccessMessageData,
} from "@shared/schemas/auth";
import type { ApiResponse } from "@shared/types/api-response";
import { validationError } from "@worker/handlers/http.utils";
import { AppError } from "@worker/types/errors";
import type { HonoEnv } from "@worker/types/hono-env";
import { buildCookieOptions, parseCookieHeaderAll } from "@worker/utils/cookie";
import {
  clearConflictingSessions,
  getClientInfo,
  handleApiError,
  readJsonBody,
  resolveTargetApp,
} from "@worker/utils/runtime";
import type { Context } from "hono";
import { setCookie } from "hono/cookie";
import * as v from "valibot";

export class AuthHandler {
  static async getDashboard(c: Context<HonoEnv>): Promise<Response> {
    try {
      const authService = c.get("authService");
      const appRepo = c.get("appRepo");
      const config = c.get("config");
      const logger = c.get("logger");
      const { ip, userAgent } = getClientInfo(c);
      const cookieHeader = c.req.header("Cookie") ?? "";

      const allApps = await appRepo.findAll();
      const apps: DashboardAppStatus[] = [];
      const userHasPasswordCache = new Map<string, boolean>();
      let hasAnySession = false;

      const resolveHasPassword = async (userId: string): Promise<boolean> => {
        const cached = userHasPasswordCache.get(userId);
        if (cached !== undefined) {
          return cached;
        }
        const user = await authService.getUser(userId);
        const hasPassword = user ? !user.phash.startsWith("OAUTH:") : true;
        userHasPasswordCache.set(userId, hasPassword);
        return hasPassword;
      };

      // Verify session_sso candidates at most once and reuse across apps that allow logins
      const ssoAppRecord = allApps.find((entry) => entry.id === "sso");
      const ssoSessionIds = parseCookieHeaderAll(cookieHeader, "session_sso");
      let verifiedSsoSession: Session | null = null;

      if (ssoAppRecord && ssoAppRecord.allow_logins === 1) {
        for (const ssoSessionId of ssoSessionIds) {
          try {
            verifiedSsoSession = await authService.verifySession(ssoSessionId, "sso", ip, userAgent);
            break;
          } catch (error: unknown) {
            if (error instanceof Error) {
              logger.debug(`SSO session verification failed: ${error.message}`);
            }
          }
        }
      }

      for (const appRecord of allApps) {
        const appId = appRecord.id;
        let verifiedSession: Session | null = null;
        let isSsoFallback = false;

        if (appId === "sso") {
          verifiedSession = verifiedSsoSession;
        } else {
          const directSessionIds = parseCookieHeaderAll(cookieHeader, `session_${appId}`);
          if (appRecord.allow_logins === 1) {
            for (const directSessionId of directSessionIds) {
              try {
                verifiedSession = await authService.verifySession(directSessionId, appId, ip, userAgent);
                break;
              } catch (error: unknown) {
                if (error instanceof Error) {
                  logger.debug(`Direct session verification failed for ${appId}: ${error.message}`);
                }
              }
            }
          }

          if (!verifiedSession && verifiedSsoSession && appRecord.allow_logins === 1) {
            verifiedSession = verifiedSsoSession;
            isSsoFallback = true;
          }
        }

        let summary: PublicSessionSummary | null = null;
        if (verifiedSession) {
          hasAnySession = true;
          const hasPassword = await resolveHasPassword(verifiedSession.userId);
          summary = {
            userId: verifiedSession.userId,
            email: verifiedSession.email,
            appId: verifiedSession.appId,
            createdAt: verifiedSession.createdAt,
            hasPassword,
          };
        }

        const appUrl = config.APP_ENV === "development" ? appRecord.dev_url : appRecord.prod_url;

        apps.push({
          config: {
            id: appRecord.id,
            name: appRecord.name,
            description: appRecord.description || "",
            icon: appRecord.icon || null,
            url: appUrl,
            allowSignups: appRecord.allow_signups === 1,
            allowLogins: appRecord.allow_logins === 1,
          },
          session: summary,
          isSsoFallback,
        });
      }

      const response: ApiResponse<DashboardData> = {
        success: true,
        data: {
          appName: config.APP_NAME,
          apps,
          hasAnySession,
        },
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async getAuthContext(c: Context<HonoEnv>): Promise<Response> {
    try {
      const config = c.get("config");
      const resolved = await resolveTargetApp(
        c.get("appRepo"),
        c.req.query("app_id"),
        c.req.query("redirect"),
        config.APP_ENV,
      );

      const response: ApiResponse<AuthContextData> = {
        success: true,
        data: {
          appName: config.APP_NAME,
          appId: resolved.appId,
          targetAppName: resolved.appName,
          redirect: resolved.redirect,
          allowSignups: resolved.app.allow_signups === 1,
          allowLogins: resolved.app.allow_logins === 1,
          providers: {
            github: Boolean(config.GITHUB_CLIENT_ID && config.GITHUB_CLIENT_SECRET),
            google: Boolean(config.GOOGLE_CLIENT_ID && config.GOOGLE_CLIENT_SECRET),
          },
        },
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async login(c: Context<HonoEnv>): Promise<Response> {
    try {
      const body = await readJsonBody(c);
      const result = v.safeParse(LoginInputSchema, body);
      if (!result.success) {
        return validationError(c, result.issues[0]?.message ?? "Invalid login details.");
      }

      const config = c.get("config");
      const resolved = await resolveTargetApp(
        c.get("appRepo"),
        result.output.appId,
        result.output.redirect,
        config.APP_ENV,
        true,
      );
      const authService = c.get("authService");
      const { ip, userAgent } = getClientInfo(c);

      try {
        const loginResult = await authService.login(
          result.output.email,
          result.output.password,
          resolved.appId,
          ip,
          userAgent,
        );

        if (loginResult.requires2FA) {
          const response: ApiResponse<LoginResultData> = {
            success: true,
            data: {
              status: "requires_2fa",
              appId: resolved.appId,
              twoFactorToken: loginResult.twoFactorToken,
              redirect: resolved.redirect,
            },
          };
          return c.json(response, 200);
        }

        await clearConflictingSessions(c, loginResult.app);
        const cookieOpts = buildCookieOptions(config, 86400);
        setCookie(c, `session_${loginResult.app}`, loginResult.sessionId, cookieOpts);

        const response: ApiResponse<LoginResultData> = {
          success: true,
          data: {
            status: "authenticated",
            appId: loginResult.app,
            redirect: resolved.redirect,
          },
        };
        return c.json(response, 200);
      } catch (error: unknown) {
        if (error instanceof AppError && error.code === "EMAIL_NOT_VERIFIED") {
          await authService.requestNewVerification(
            result.output.email,
            resolved.appId,
            resolved.redirect,
            ip,
            userAgent,
          );
          const response: ApiResponse<LoginResultData> = {
            success: true,
            data: {
              status: "verification_required",
              appId: resolved.appId,
              redirect: resolved.redirect,
            },
          };
          return c.json(response, 200);
        }
        throw error;
      }
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async register(c: Context<HonoEnv>): Promise<Response> {
    try {
      const body = await readJsonBody(c);
      const result = v.safeParse(RegisterInputSchema, body);
      if (!result.success) {
        return validationError(c, result.issues[0]?.message ?? "Invalid registration details.");
      }

      const resolved = await resolveTargetApp(
        c.get("appRepo"),
        result.output.appId,
        result.output.redirect,
        c.get("config").APP_ENV,
        true,
      );
      const { ip, userAgent } = getClientInfo(c);

      await c
        .get("authService")
        .register(result.output.email, result.output.password, resolved.appId, resolved.redirect, ip, userAgent);

      const response: ApiResponse<RedirectResultData> = {
        success: true,
        data: { redirect: resolved.redirect },
      };
      return c.json(response, 201);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async verifyEmail(c: Context<HonoEnv>): Promise<Response> {
    try {
      const body = await readJsonBody(c);
      const result = v.safeParse(VerifyEmailInputSchema, body);
      if (!result.success) {
        return validationError(c, result.issues[0]?.message ?? "Verification token is required.");
      }

      const { ip, userAgent } = getClientInfo(c);
      await c.get("authService").verifyEmailToken(result.output.token, ip, userAgent);

      const response: ApiResponse<SuccessMessageData> = {
        success: true,
        data: { message: "Email verified successfully. You can now sign in." },
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }
}
