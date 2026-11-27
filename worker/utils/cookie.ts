import type { DerbentConfig } from "@worker/types/models";
import type { CookieOptions } from "hono/utils/cookie";

export function buildCookieOptions(config: DerbentConfig, maxAge?: number): CookieOptions {
  const isProd = config.APP_ENV === "production";

  const options: CookieOptions = {
    path: "/",
    httpOnly: true,
    sameSite: "Lax",
    secure: isProd,
  };

  if (isProd && config.COOKIE_DOMAIN) {
    options.domain = config.COOKIE_DOMAIN;
  }

  if (maxAge !== undefined) {
    options.maxAge = maxAge;
  }

  return options;
}

export function parseCookieHeader(cookieHeader: string, targetName: string): string | null {
  if (!cookieHeader) {
    return null;
  }

  const pairs = cookieHeader.split(";");
  for (const pair of pairs) {
    const eqIndex = pair.indexOf("=");
    if (eqIndex === -1) {
      continue;
    }

    const rawName = pair.slice(0, eqIndex).trim();
    if (rawName !== targetName) {
      continue;
    }

    const rawValue = pair.slice(eqIndex + 1).trim();
    if (!rawValue) {
      return null;
    }

    try {
      return decodeURIComponent(rawValue);
    } catch {
      return rawValue;
    }
  }

  return null;
}
