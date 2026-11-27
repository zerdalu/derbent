import type { ApiResponse } from "@shared/types/api-response";
import type { HonoEnv } from "@worker/types/hono-env";
import { constantTimeEqual } from "@worker/utils/crypto";
import type { MiddlewareHandler } from "hono";

export const rateLimit = (): MiddlewareHandler<HonoEnv> => {
  return async (c, next) => {
    const ip = c.req.header("cf-connecting-ip") || "global";
    const { success } = await c.env.AUTH_LIMITER.limit({ key: ip });

    if (!success) {
      c.get("logger").warn(`Rate limit exceeded for IP: ${ip}`);
      const errorResponse: ApiResponse<never> = {
        success: false,
        error: {
          code: "TOO_MANY_REQUESTS",
          message: "Too many attempts in a short period. Please wait a minute and try again.",
        },
      };
      return c.json(errorResponse, 429);
    }

    await next();
  };
};

export const adminAuth = (): MiddlewareHandler<HonoEnv> => {
  return async (c, next) => {
    const secret = c.env.DERBENT_API_KEY;

    if (!secret) {
      c.get("logger").error("[ADMIN API] Missing DERBENT_API_KEY in environment variables.");
      const errorResponse: ApiResponse<never> = {
        success: false,
        error: {
          code: "INTERNAL_ERROR",
          message: "Admin API is not configured on this instance.",
        },
      };
      return c.json(errorResponse, 500);
    }

    const authHeader = c.req.header("Authorization");
    if (!authHeader) {
      const unauthorized: ApiResponse<never> = {
        success: false,
        error: {
          code: "UNAUTHORIZED",
          message: "Unauthorized",
        },
      };
      return c.json(unauthorized, 401);
    }

    const isAuthorized = await constantTimeEqual(authHeader, `Bearer ${secret}`);
    if (!isAuthorized) {
      const unauthorized: ApiResponse<never> = {
        success: false,
        error: {
          code: "UNAUTHORIZED",
          message: "Unauthorized",
        },
      };
      return c.json(unauthorized, 401);
    }

    await next();
  };
};
