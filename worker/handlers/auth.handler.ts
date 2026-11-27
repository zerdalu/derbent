import {
  AppActionInputSchema,
  ChangePasswordInputSchema,
  ForgotPasswordInputSchema,
  LoginInputSchema,
  MagicLinkRequestInputSchema,
  RegisterInputSchema,
  ResetPasswordInputSchema,
  TwoFactorCodeInputSchema,
  TwoFactorVerifyInputSchema,
  VerifyEmailInputSchema,
  VerifyMagicLinkInputSchema,
  type AuthContextData,
  type DashboardAppStatus,
  type DashboardData,
  type LoginResultData,
  type PublicSessionSummary,
  type RedirectResultData,
  type ResetPasswordResultData,
  type Session,
  type SuccessMessageData,
  type TwoFactorSetupStateData,
} from "@shared/schemas/auth";
import type { ApiResponse } from "@shared/types/api-response";
import { AppError } from "@worker/types/errors";
import type { HonoEnv } from "@worker/types/hono-env";
import { buildCookieOptions } from "@worker/utils/cookie";
import {
  clearConflictingSessions,
  getClientInfo,
  handleApiError,
  readJsonBody,
  resolveTargetApp,
} from "@worker/utils/runtime";
import { generateSecret } from "@worker/utils/totp";
import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import * as v from "valibot";

function validationError(c: Context<HonoEnv>, message: string): Response {
  const response: ApiResponse<never> = {
    success: false,
    error: {
      code: "VALIDATION_ERROR",
      message,
    },
  };
  return c.json(response, 400);
}

async function getActiveSession(
  c: Context<HonoEnv>,
  preferredAppId?: string,
): Promise<{ readonly session: Session; readonly appId: string; readonly sessionId: string } | null> {
  const authService = c.get("authService");
  const appRepo = c.get("appRepo");
  const logger = c.get("logger");
  const { ip, userAgent } = getClientInfo(c);

  const normalizedPreferred = preferredAppId?.trim();
  let candidateCookieApps: readonly string[];

  if (normalizedPreferred) {
    candidateCookieApps = normalizedPreferred === "sso" ? ["sso"] : [normalizedPreferred, "sso"];
  } else {
    const allApps = await appRepo.findAll();
    candidateCookieApps = allApps.map((app) => app.id);
  }

  for (const cookieAppKey of candidateCookieApps) {
    const cookieVal = getCookie(c, `session_${cookieAppKey}`);
    if (!cookieVal) {
      continue;
    }

    const requiredAppId = normalizedPreferred || cookieAppKey;
    try {
      const session = await authService.verifySession(cookieVal, requiredAppId, ip, userAgent);
      return { session, appId: cookieAppKey, sessionId: cookieVal };
    } catch (error: unknown) {
      if (error instanceof Error) {
        logger.debug(`Session verification skipped for ${cookieAppKey}: ${error.message}`);
      }
    }
  }

  return null;
}

export class AuthHandler {
  static async getDashboard(c: Context<HonoEnv>): Promise<Response> {
    try {
      const authService = c.get("authService");
      const appRepo = c.get("appRepo");
      const config = c.get("config");
      const logger = c.get("logger");
      const { ip, userAgent } = getClientInfo(c);

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

      for (const appRecord of allApps) {
        const appId = appRecord.id;
        const directSessionId = getCookie(c, `session_${appId}`);
        const ssoSessionId = appId !== "sso" ? getCookie(c, "session_sso") : undefined;

        let verifiedSession: Session | null = null;
        let isSsoFallback = false;

        if (directSessionId) {
          try {
            verifiedSession = await authService.verifySession(directSessionId, appId, ip, userAgent);
          } catch (error: unknown) {
            if (error instanceof Error) {
              logger.debug(`Direct session verification failed for ${appId}: ${error.message}`);
            }
          }
        }

        if (!verifiedSession && ssoSessionId) {
          try {
            verifiedSession = await authService.verifySession(ssoSessionId, appId, ip, userAgent);
            isSsoFallback = true;
          } catch (error: unknown) {
            if (error instanceof Error) {
              logger.debug(`SSO fallback session verification failed for ${appId}: ${error.message}`);
            }
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

  static async logout(c: Context<HonoEnv>): Promise<Response> {
    try {
      const body = await readJsonBody(c);
      const result = v.safeParse(AppActionInputSchema, body);
      if (!result.success) {
        return validationError(c, result.issues[0]?.message ?? "Invalid logout payload.");
      }

      const config = c.get("config");
      const resolved = await resolveTargetApp(
        c.get("appRepo"),
        result.output.appId,
        result.output.redirect,
        config.APP_ENV,
      );
      const authService = c.get("authService");
      const cookieOptions = buildCookieOptions(config);

      const directSessionId = getCookie(c, `session_${resolved.appId}`);
      const ssoSessionId = resolved.appId !== "sso" ? getCookie(c, "session_sso") : undefined;

      if (directSessionId) {
        try {
          await authService.logout(directSessionId, resolved.appId);
        } catch (error: unknown) {
          if (error instanceof Error) {
            c.get("logger").warn(`Logout direct session revocation failed: ${error.message}`);
          }
        }
      }

      if (ssoSessionId && ssoSessionId !== directSessionId) {
        try {
          await authService.logout(ssoSessionId, resolved.appId);
        } catch (error: unknown) {
          if (error instanceof Error) {
            c.get("logger").warn(`Logout SSO session revocation failed: ${error.message}`);
          }
        }
      }

      deleteCookie(c, `session_${resolved.appId}`, cookieOptions);
      if (resolved.appId !== "sso") {
        deleteCookie(c, "session_sso", cookieOptions);
      }

      const response: ApiResponse<RedirectResultData> = {
        success: true,
        data: { redirect: resolved.redirect },
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async logoutAll(c: Context<HonoEnv>): Promise<Response> {
    try {
      const body = await readJsonBody(c);
      const result = v.safeParse(AppActionInputSchema, body);
      if (!result.success) {
        return validationError(c, result.issues[0]?.message ?? "Invalid payload.");
      }

      const config = c.get("config");
      const resolved = await resolveTargetApp(
        c.get("appRepo"),
        result.output.appId,
        result.output.redirect,
        config.APP_ENV,
      );
      const authService = c.get("authService");
      const { ip, userAgent } = getClientInfo(c);

      const active = await getActiveSession(c, resolved.appId);
      if (active) {
        try {
          await authService.logoutAll(active.session.userId, ip, userAgent);
        } catch (error: unknown) {
          if (error instanceof Error) {
            c.get("logger").warn(`Logout all sessions failed: ${error.message}`);
          }
        }
      }

      const directSessionId = getCookie(c, `session_${resolved.appId}`);
      const ssoSessionId = resolved.appId !== "sso" ? getCookie(c, "session_sso") : undefined;

      if (directSessionId) {
        try {
          await authService.logout(directSessionId, resolved.appId);
        } catch (error: unknown) {
          if (error instanceof Error) {
            c.get("logger").debug(`Direct session cleanup skipped: ${error.message}`);
          }
        }
      }

      if (ssoSessionId && ssoSessionId !== directSessionId) {
        try {
          await authService.logout(ssoSessionId, resolved.appId);
        } catch (error: unknown) {
          if (error instanceof Error) {
            c.get("logger").debug(`SSO session cleanup skipped: ${error.message}`);
          }
        }
      }

      const cookieOptions = buildCookieOptions(config);
      deleteCookie(c, `session_${resolved.appId}`, cookieOptions);
      if (resolved.appId !== "sso") {
        deleteCookie(c, "session_sso", cookieOptions);
      }

      const response: ApiResponse<RedirectResultData> = {
        success: true,
        data: { redirect: resolved.redirect },
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async logoutAllByEmail(c: Context<HonoEnv>): Promise<Response> {
    try {
      const body = await readJsonBody(c);
      const result = v.safeParse(AppActionInputSchema, body);
      if (!result.success) {
        return validationError(c, result.issues[0]?.message ?? "Invalid payload.");
      }

      const config = c.get("config");
      const resolved = await resolveTargetApp(
        c.get("appRepo"),
        result.output.appId,
        result.output.redirect,
        config.APP_ENV,
      );
      const authService = c.get("authService");
      const appRepo = c.get("appRepo");
      const logger = c.get("logger");
      const { ip, userAgent } = getClientInfo(c);

      const targetEmails = new Set<string>();
      const sessionIdsToPurge = new Set<string>();
      const allApps = await appRepo.findAll();

      for (const app of allApps) {
        const cookieVal = getCookie(c, `session_${app.id}`);
        if (!cookieVal) {
          continue;
        }

        sessionIdsToPurge.add(cookieVal);

        try {
          const session = await authService.verifySession(cookieVal, app.id, ip, userAgent);
          targetEmails.add(session.email);
        } catch (error: unknown) {
          if (error instanceof Error) {
            logger.debug(`Session verification failed for app ${app.id}: ${error.message}`);
          }
        }
      }

      for (const targetEmail of targetEmails) {
        try {
          await authService.logoutAllByEmail(targetEmail, ip, userAgent);
        } catch (error: unknown) {
          if (error instanceof Error) {
            logger.warn(`Logout all by email failed for ${targetEmail}: ${error.message}`);
          }
        }
      }

      for (const sessionId of sessionIdsToPurge) {
        try {
          await authService.logout(sessionId);
        } catch (error: unknown) {
          if (error instanceof Error) {
            logger.debug(`Session KV cleanup skipped: ${error.message}`);
          }
        }
      }

      const cookieOptions = buildCookieOptions(config);
      for (const app of allApps) {
        deleteCookie(c, `session_${app.id}`, cookieOptions);
      }

      const response: ApiResponse<RedirectResultData> = {
        success: true,
        data: { redirect: resolved.redirect },
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async forgotPassword(c: Context<HonoEnv>): Promise<Response> {
    try {
      const body = await readJsonBody(c);
      const result = v.safeParse(ForgotPasswordInputSchema, body);
      if (!result.success) {
        return validationError(c, result.issues[0]?.message ?? "Please enter a valid email address.");
      }

      const resolved = await resolveTargetApp(
        c.get("appRepo"),
        result.output.appId,
        "/",
        c.get("config").APP_ENV,
        true,
      );
      const { ip, userAgent } = getClientInfo(c);

      try {
        await c.get("authService").requestPasswordReset(result.output.email, resolved.appId, ip, userAgent);
      } catch (error: unknown) {
        if (error instanceof Error) {
          c.get("logger").warn(`Password reset request error: ${error.message}`);
        }
      }

      const response: ApiResponse<SuccessMessageData> = {
        success: true,
        data: {
          message: "If an account exists for that email, we've sent reset instructions to your inbox.",
        },
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async resetPassword(c: Context<HonoEnv>): Promise<Response> {
    try {
      const body = await readJsonBody(c);
      const result = v.safeParse(ResetPasswordInputSchema, body);
      if (!result.success) {
        return validationError(c, result.issues[0]?.message ?? "Invalid password reset details.");
      }

      const { ip, userAgent } = getClientInfo(c);
      const appId = await c
        .get("authService")
        .resetPassword(result.output.token, result.output.password, ip, userAgent);

      const response: ApiResponse<ResetPasswordResultData> = {
        success: true,
        data: { appId },
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async changePassword(c: Context<HonoEnv>): Promise<Response> {
    try {
      const active = await getActiveSession(c, c.req.query("app_id"));
      if (!active) {
        throw new AppError("Authentication required.", 401);
      }

      const body = await readJsonBody(c);
      const result = v.safeParse(ChangePasswordInputSchema, body);
      if (!result.success) {
        return validationError(c, result.issues[0]?.message ?? "Invalid password details.");
      }

      const authService = c.get("authService");
      const { ip, userAgent } = getClientInfo(c);
      await authService.changePassword(
        active.session.userId,
        result.output.currentPassword,
        result.output.newPassword,
        ip,
        userAgent,
      );

      try {
        await authService.logout(active.sessionId);
      } catch (error: unknown) {
        if (error instanceof Error) {
          c.get("logger").debug(`Session cleanup after password change skipped: ${error.message}`);
        }
      }

      const cookieOptions = buildCookieOptions(c.get("config"));
      deleteCookie(c, `session_${active.appId}`, cookieOptions);
      if (active.session.appId === "sso") {
        deleteCookie(c, "session_sso", cookieOptions);
      }

      const response: ApiResponse<SuccessMessageData> = {
        success: true,
        data: { message: "Password changed successfully. Please sign in again." },
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async requestMagicLink(c: Context<HonoEnv>): Promise<Response> {
    try {
      const body = await readJsonBody(c);
      const result = v.safeParse(MagicLinkRequestInputSchema, body);
      if (!result.success) {
        return validationError(c, result.issues[0]?.message ?? "Please enter a valid email address.");
      }

      const resolved = await resolveTargetApp(
        c.get("appRepo"),
        result.output.appId,
        result.output.redirect,
        c.get("config").APP_ENV,
        true,
      );
      const { ip, userAgent } = getClientInfo(c);

      try {
        await c
          .get("authService")
          .requestMagicLink(result.output.email, resolved.appId, resolved.redirect, ip, userAgent);
      } catch (error: unknown) {
        if (error instanceof AppError && error.status === 403) {
          throw error;
        }
        if (error instanceof Error) {
          c.get("logger").warn(`Magic link request error: ${error.message}`);
        }
      }

      const response: ApiResponse<SuccessMessageData> = {
        success: true,
        data: {
          message: "If an account exists, we've sent a magic link to your inbox.",
        },
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async verifyMagicLink(c: Context<HonoEnv>): Promise<Response> {
    try {
      const body = await readJsonBody(c);
      const result = v.safeParse(VerifyMagicLinkInputSchema, body);
      if (!result.success) {
        return validationError(c, result.issues[0]?.message ?? "Magic link token is required.");
      }

      const config = c.get("config");
      const resolved = await resolveTargetApp(
        c.get("appRepo"),
        result.output.appId,
        result.output.redirect,
        config.APP_ENV,
        true,
      );
      const { ip, userAgent } = getClientInfo(c);

      const loginResult = await c
        .get("authService")
        .verifyMagicLink(result.output.token, resolved.appId, ip, userAgent);

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
      return handleApiError(c, error);
    }
  }

  static async getTwoFactorSetup(c: Context<HonoEnv>): Promise<Response> {
    try {
      const active = await getActiveSession(c, c.req.query("app_id"));
      if (!active) {
        throw new AppError("Authentication required.", 401);
      }

      const authService = c.get("authService");
      const user = await authService.getUser(active.session.userId);
      if (!user) {
        throw new AppError("Authentication required.", 401);
      }

      if (user.two_factor_enabled === 1) {
        const response: ApiResponse<TwoFactorSetupStateData> = {
          success: true,
          data: { enabled: true },
        };
        return c.json(response, 200);
      }

      let secret = await authService.getTwoFactorSetupSecret(user.id);
      if (!secret) {
        secret = await generateSecret();
        await authService.saveTwoFactorSetupSecret(user.id, secret);
      }

      const appName = c.get("config").APP_NAME || "Derbent";
      const otpauthUrl = `otpauth://totp/${encodeURIComponent(appName)}:${encodeURIComponent(user.email)}?secret=${secret}&issuer=${encodeURIComponent(appName)}`;

      const response: ApiResponse<TwoFactorSetupStateData> = {
        success: true,
        data: {
          enabled: false,
          secret,
          otpauthUrl,
          email: user.email,
        },
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async enableTwoFactor(c: Context<HonoEnv>): Promise<Response> {
    try {
      const active = await getActiveSession(c, c.req.query("app_id"));
      if (!active) {
        throw new AppError("Authentication required.", 401);
      }

      const body = await readJsonBody(c);
      const result = v.safeParse(TwoFactorCodeInputSchema, body);
      if (!result.success) {
        return validationError(c, result.issues[0]?.message ?? "A 6-digit code is required.");
      }

      await c.get("authService").enableTwoFactor(active.session.userId, result.output.code);

      const response: ApiResponse<SuccessMessageData> = {
        success: true,
        data: { message: "Two-Factor Authentication was successfully enabled." },
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async disableTwoFactor(c: Context<HonoEnv>): Promise<Response> {
    try {
      const active = await getActiveSession(c, c.req.query("app_id"));
      if (!active) {
        throw new AppError("Authentication required.", 401);
      }

      const body = await readJsonBody(c);
      const result = v.safeParse(TwoFactorCodeInputSchema, body);
      if (!result.success) {
        return validationError(c, result.issues[0]?.message ?? "A 6-digit code is required.");
      }

      await c.get("authService").disableTwoFactor(active.session.userId, result.output.code);

      const response: ApiResponse<SuccessMessageData> = {
        success: true,
        data: { message: "Two-Factor Authentication was successfully disabled." },
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async verifyTwoFactorLogin(c: Context<HonoEnv>): Promise<Response> {
    try {
      const body = await readJsonBody(c);
      const result = v.safeParse(TwoFactorVerifyInputSchema, body);
      if (!result.success) {
        return validationError(c, result.issues[0]?.message ?? "Invalid two-factor verification request.");
      }

      const config = c.get("config");
      const resolved = await resolveTargetApp(
        c.get("appRepo"),
        result.output.appId,
        result.output.redirect,
        config.APP_ENV,
        true,
      );
      const { ip, userAgent } = getClientInfo(c);

      const loginResult = await c
        .get("authService")
        .verifyTwoFactorLogin(result.output.token, result.output.code, ip, userAgent, resolved.appId);

      await clearConflictingSessions(c, loginResult.app);
      const cookieOpts = buildCookieOptions(config, 86400);
      setCookie(c, `session_${loginResult.app}`, loginResult.sessionId, cookieOpts);

      const response: ApiResponse<RedirectResultData> = {
        success: true,
        data: { redirect: resolved.redirect },
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }
}
