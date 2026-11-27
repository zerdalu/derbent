import type { ApiResponse } from "@shared/types/api-response";
import type { HonoEnv } from "@worker/types/hono-env";
import { constantTimeEqual } from "@worker/utils/crypto";
import type { MiddlewareHandler } from "hono";

const ADMIN_AUTH_BLOCK_TTL_SECONDS = 60;

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

    const ip = c.req.header("cf-connecting-ip") || "global";
    const blockKey = `admin_auth_blocked:${ip}`;
    const isBlocked = (await c.env.KV.get(blockKey)) !== null;

    if (isBlocked) {
      c.get("logger").warn(`[ADMIN API] Blocked rate-limited IP: ${ip}`);
      const rateLimited: ApiResponse<never> = {
        success: false,
        error: {
          code: "TOO_MANY_REQUESTS",
          message: "Too many failed authentication attempts. Please wait a minute and try again.",
        },
      };
      return c.json(rateLimited, 429);
    }

    const authHeader = c.req.header("Authorization");
    const isAuthorized = Boolean(authHeader) && (await constantTimeEqual(authHeader ?? "", `Bearer ${secret}`));

    if (!isAuthorized) {
      const { success } = await c.env.AUTH_LIMITER.limit({ key: `admin_auth_fail:${ip}` });
      if (!success) {
        await c.env.KV.put(blockKey, "1", { expirationTtl: ADMIN_AUTH_BLOCK_TTL_SECONDS });
        c.get("logger").warn(`[ADMIN API] Failed auth rate limit exceeded for IP: ${ip}`);
        const rateLimited: ApiResponse<never> = {
          success: false,
          error: {
            code: "TOO_MANY_REQUESTS",
            message: "Too many failed authentication attempts. Please wait a minute and try again.",
          },
        };
        return c.json(rateLimited, 429);
      }

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
