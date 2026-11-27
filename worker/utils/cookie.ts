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

export function parseCookieHeaderAll(cookieHeader: string, targetName: string): readonly string[] {
  if (!cookieHeader) {
    return [];
  }

  const values: string[] = [];
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
      continue;
    }

    let decoded = rawValue;
    try {
      decoded = decodeURIComponent(rawValue);
    } catch {
      decoded = rawValue;
    }

    if (!values.includes(decoded)) {
      values.push(decoded);
    }
  }

  return values;
}

export function parseCookieHeader(cookieHeader: string, targetName: string): string | null {
  const matches = parseCookieHeaderAll(cookieHeader, targetName);
  return matches[0] ?? null;
}
