import {
  ChangePasswordInputSchema,
  ForgotPasswordInputSchema,
  ResetPasswordInputSchema,
  type ResetPasswordResultData,
  type SuccessMessageData,
} from "@shared/schemas/auth";
import type { ApiResponse } from "@shared/types/api-response";
import { getActiveSession, validationError } from "@worker/handlers/http.utils";
import { AppError } from "@worker/types/errors";
import type { HonoEnv } from "@worker/types/hono-env";
import { buildCookieOptions } from "@worker/utils/cookie";
import { getClientInfo, handleApiError, readJsonBody, resolveTargetApp } from "@worker/utils/runtime";
import type { Context } from "hono";
import { deleteCookie } from "hono/cookie";
import * as v from "valibot";

export class AuthPasswordHandler {
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
}
