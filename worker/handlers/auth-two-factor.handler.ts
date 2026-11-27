import {
  TwoFactorCodeInputSchema,
  TwoFactorVerifyInputSchema,
  type RedirectResultData,
  type SuccessMessageData,
  type TwoFactorSetupStateData,
} from "@shared/schemas/auth";
import type { ApiResponse } from "@shared/types/api-response";
import { getActiveSession, validationError } from "@worker/handlers/http.utils";
import { AppError } from "@worker/types/errors";
import type { HonoEnv } from "@worker/types/hono-env";
import { buildCookieOptions, buildHostCookieOptions } from "@worker/utils/cookie";
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

export const TWO_FACTOR_CHALLENGE_COOKIE = "two_factor_challenge";

export class AuthTwoFactorHandler {
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

      const { ip, userAgent } = getClientInfo(c);
      await c
        .get("authService")
        .enableTwoFactor(active.session.userId, result.output.code, ip, userAgent, active.sessionId);

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

      const { ip, userAgent } = getClientInfo(c);
      await c
        .get("authService")
        .disableTwoFactor(active.session.userId, result.output.code, ip, userAgent, active.sessionId);

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
      const cookieToken = getCookie(c, TWO_FACTOR_CHALLENGE_COOKIE)?.trim();
      const effectiveToken = result.output.token === "cookie" ? (cookieToken ?? "") : result.output.token;
      if (!effectiveToken) {
        throw new AppError("Session expired. Please log in again.", 401);
      }

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
        .verifyTwoFactorLogin(effectiveToken, result.output.code, ip, userAgent, resolved.appId);

      if (cookieToken) {
        deleteCookie(c, TWO_FACTOR_CHALLENGE_COOKIE, buildHostCookieOptions(config));
      }

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
