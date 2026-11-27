import { AppActionInputSchema, type RedirectResultData } from "@shared/schemas/auth";
import type { ApiResponse } from "@shared/types/api-response";
import { getActiveSession, validationError } from "@worker/handlers/http.utils";
import type { HonoEnv } from "@worker/types/hono-env";
import { buildCookieOptions, parseCookieHeaderAll } from "@worker/utils/cookie";
import { getClientInfo, handleApiError, readJsonBody, resolveTargetApp } from "@worker/utils/runtime";
import type { Context } from "hono";
import { deleteCookie } from "hono/cookie";
import * as v from "valibot";

export class AuthSessionHandler {
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
      const cookieHeader = c.req.header("Cookie") ?? "";

      const candidateSessionIds = new Set<string>(parseCookieHeaderAll(cookieHeader, `session_${resolved.appId}`));
      if (resolved.appId !== "sso") {
        for (const ssoSessionId of parseCookieHeaderAll(cookieHeader, "session_sso")) {
          candidateSessionIds.add(ssoSessionId);
        }
      }

      for (const sessionId of candidateSessionIds) {
        try {
          await authService.logout(sessionId, resolved.appId);
        } catch (error: unknown) {
          if (error instanceof Error) {
            c.get("logger").warn(`Logout session revocation failed: ${error.message}`);
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
      const cookieHeader = c.req.header("Cookie") ?? "";

      const active = await getActiveSession(c, resolved.appId, true);
      if (active) {
        try {
          await authService.logoutAll(active.session.userId, ip, userAgent);
        } catch (error: unknown) {
          if (error instanceof Error) {
            c.get("logger").warn(`Logout all sessions failed: ${error.message}`);
          }
        }
      }

      const candidateSessionIds = new Set<string>(parseCookieHeaderAll(cookieHeader, `session_${resolved.appId}`));
      if (resolved.appId !== "sso") {
        for (const ssoSessionId of parseCookieHeaderAll(cookieHeader, "session_sso")) {
          candidateSessionIds.add(ssoSessionId);
        }
      }

      for (const sessionId of candidateSessionIds) {
        try {
          await authService.logout(sessionId, resolved.appId);
        } catch (error: unknown) {
          if (error instanceof Error) {
            c.get("logger").debug(`Session cleanup skipped: ${error.message}`);
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
      const cookieHeader = c.req.header("Cookie") ?? "";

      const targetEmails = new Set<string>();
      const sessionIdsToPurge = new Set<string>();
      const allApps = await appRepo.findAll();

      for (const app of allApps) {
        const cookieValues = parseCookieHeaderAll(cookieHeader, `session_${app.id}`);
        for (const cookieVal of cookieValues) {
          sessionIdsToPurge.add(cookieVal);

          try {
            const session = await authService.verifySession(cookieVal, app.id, ip, userAgent, {
              allowDisabledApp: true,
            });
            targetEmails.add(session.email);
          } catch (error: unknown) {
            if (error instanceof Error) {
              logger.debug(`Session verification failed for app ${app.id}: ${error.message}`);
            }
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
}
