import type { Session } from "@shared/schemas/auth";
import type { ApiResponse } from "@shared/types/api-response";
import type { HonoEnv } from "@worker/types/hono-env";
import { parseCookieHeaderAll } from "@worker/utils/cookie";
import { getClientInfo } from "@worker/utils/runtime";
import type { Context } from "hono";

export interface ActiveSessionContext {
  readonly session: Session;
  readonly appId: string;
  readonly sessionId: string;
}

export function parsePositiveInt(raw: string | undefined, fallback: number, max?: number): number {
  const parsed = Number.parseInt(raw ?? "", 10);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    return fallback;
  }
  return max !== undefined ? Math.min(parsed, max) : parsed;
}

export function validationError(c: Context<HonoEnv>, message: string): Response {
  const response: ApiResponse<never> = {
    success: false,
    error: {
      code: "VALIDATION_ERROR",
      message,
    },
  };
  return c.json(response, 400);
}

export async function getActiveSession(
  c: Context<HonoEnv>,
  preferredAppId?: string,
  allowDisabledApp = false,
): Promise<ActiveSessionContext | null> {
  const authService = c.get("authService");
  const appRepo = c.get("appRepo");
  const logger = c.get("logger");
  const { ip, userAgent } = getClientInfo(c);
  const cookieHeader = c.req.header("Cookie") ?? "";

  const normalizedPreferred = preferredAppId?.trim();
  let candidateCookieApps: readonly string[];

  if (normalizedPreferred) {
    candidateCookieApps = normalizedPreferred === "sso" ? ["sso"] : [normalizedPreferred, "sso"];
  } else {
    const allApps = await appRepo.findAll();
    candidateCookieApps = allApps.map((app) => app.id);
  }

  for (const cookieAppKey of candidateCookieApps) {
    const cookieValues = parseCookieHeaderAll(cookieHeader, `session_${cookieAppKey}`);
    if (cookieValues.length === 0) {
      continue;
    }

    const requiredAppId = normalizedPreferred || cookieAppKey;
    for (const cookieVal of cookieValues) {
      try {
        const session = await authService.verifySession(cookieVal, requiredAppId, ip, userAgent, {
          allowDisabledApp,
        });
        return { session, appId: cookieAppKey, sessionId: cookieVal };
      } catch (error: unknown) {
        if (error instanceof Error) {
          logger.debug(`Session verification skipped for ${cookieAppKey}: ${error.message}`);
        }
      }
    }
  }

  return null;
}
