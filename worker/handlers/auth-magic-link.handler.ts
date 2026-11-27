import {
  MagicLinkRequestInputSchema,
  VerifyMagicLinkInputSchema,
  type LoginResultData,
  type SuccessMessageData,
} from "@shared/schemas/auth";
import type { ApiResponse } from "@shared/types/api-response";
import { validationError } from "@worker/handlers/http.utils";
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
import type { Context } from "hono";
import { setCookie } from "hono/cookie";
import * as v from "valibot";

export class AuthMagicLinkHandler {
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
}
