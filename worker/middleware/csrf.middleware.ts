import type { ApiResponse } from "@shared/types/api-response";
import type { HonoEnv } from "@worker/types/hono-env";
import type { MiddlewareHandler } from "hono";

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function isSameOriginAllowed(candidateOrigin: string, baseUrl: string, requestUrl: string, isDev: boolean): boolean {
  try {
    const parsedCandidate = new URL(candidateOrigin);
    if (baseUrl) {
      try {
        if (parsedCandidate.origin === new URL(baseUrl).origin) {
          return true;
        }
      } catch {
        // Ignore malformed BASE_URL
      }
    }

    const parsedRequest = new URL(requestUrl);
    if (parsedCandidate.origin === parsedRequest.origin) {
      return true;
    }

    if (isDev && (parsedCandidate.hostname === "localhost" || parsedCandidate.hostname === "127.0.0.1")) {
      return true;
    }

    return false;
  } catch {
    return false;
  }
}

/**
 * Protects state-changing SPA JSON API endpoints against Cross-Site Request Forgery
 * using Fetch Metadata, Origin verification, and strict JSON Content-Type enforcement.
 */
export const csrfProtection = (): MiddlewareHandler<HonoEnv> => {
  return async (c, next) => {
    if (!MUTATING_METHODS.has(c.req.method.toUpperCase())) {
      await next();
      return;
    }

    const config = c.get("config");
    const isDev = config.APP_ENV === "development";
    const fetchSite = c.req.header("Sec-Fetch-Site");

    if (fetchSite === "cross-site") {
      const errorResponse: ApiResponse<never> = {
        success: false,
        error: {
          code: "FORBIDDEN",
          message: "Cross-site state-changing requests are forbidden.",
        },
      };
      return c.json(errorResponse, 403);
    }

    const originHeader = c.req.header("Origin");
    if (originHeader && !isSameOriginAllowed(originHeader, config.BASE_URL, c.req.url, isDev)) {
      const errorResponse: ApiResponse<never> = {
        success: false,
        error: {
          code: "FORBIDDEN",
          message: "Request origin is not authorized.",
        },
      };
      return c.json(errorResponse, 403);
    }

    const refererHeader = c.req.header("Referer");
    if (!originHeader && refererHeader && !isSameOriginAllowed(refererHeader, config.BASE_URL, c.req.url, isDev)) {
      const errorResponse: ApiResponse<never> = {
        success: false,
        error: {
          code: "FORBIDDEN",
          message: "Request referer is not authorized.",
        },
      };
      return c.json(errorResponse, 403);
    }

    const contentType = c.req.header("Content-Type") ?? "";
    if (!contentType.toLowerCase().includes("application/json")) {
      const errorResponse: ApiResponse<never> = {
        success: false,
        error: {
          code: "UNSUPPORTED_MEDIA_TYPE",
          message: "Requests must use application/json.",
        },
      };
      return c.json(errorResponse, 415);
    }

    await next();
  };
};
