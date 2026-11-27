import { SettingsRepository } from "@worker/repositories/settings.repository";
import type { HonoEnv } from "@worker/types/hono-env";
import type { DerbentConfig } from "@worker/types/models";
import type { MiddlewareHandler } from "hono";

function mergeConfig(base: DerbentConfig, dynamic: Record<string, string>): DerbentConfig {
  return {
    APP_ENV: dynamic.APP_ENV?.trim() || base.APP_ENV,
    LOG_LEVEL: dynamic.LOG_LEVEL?.trim() || base.LOG_LEVEL,
    APP_NAME: dynamic.APP_NAME?.trim() || base.APP_NAME,
    BASE_URL: dynamic.BASE_URL?.trim() || base.BASE_URL,
    COOKIE_DOMAIN: dynamic.COOKIE_DOMAIN?.trim() || base.COOKIE_DOMAIN,
    RESEND_DOMAIN: dynamic.RESEND_DOMAIN?.trim() || base.RESEND_DOMAIN,
    RESEND_API_KEY: dynamic.RESEND_API_KEY?.trim() || base.RESEND_API_KEY,
    GITHUB_CLIENT_ID: dynamic.GITHUB_CLIENT_ID?.trim() || base.GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET: dynamic.GITHUB_CLIENT_SECRET?.trim() || base.GITHUB_CLIENT_SECRET,
    GOOGLE_CLIENT_ID: dynamic.GOOGLE_CLIENT_ID?.trim() || base.GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET: dynamic.GOOGLE_CLIENT_SECRET?.trim() || base.GOOGLE_CLIENT_SECRET,
    PBKDF2_ITERATIONS: dynamic.PBKDF2_ITERATIONS?.trim() || base.PBKDF2_ITERATIONS,
    AUDIT_LOG_RETENTION_DAYS: dynamic.AUDIT_LOG_RETENTION_DAYS?.trim() || base.AUDIT_LOG_RETENTION_DAYS,
  };
}

export async function resolveEffectiveConfig(env: CloudflareBindings): Promise<DerbentConfig> {
  const baseConfig: DerbentConfig = {
    APP_ENV: env.APP_ENV || "production",
    LOG_LEVEL: env.LOG_LEVEL || "info",
    APP_NAME: env.APP_NAME || "Derbent",
    BASE_URL: env.BASE_URL,
    COOKIE_DOMAIN: env.COOKIE_DOMAIN,
    RESEND_DOMAIN: env.RESEND_DOMAIN,
    RESEND_API_KEY: env.RESEND_API_KEY,
    GITHUB_CLIENT_ID: env.GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET: env.GITHUB_CLIENT_SECRET,
    GOOGLE_CLIENT_ID: env.GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET: env.GOOGLE_CLIENT_SECRET,
    PBKDF2_ITERATIONS: env.PBKDF2_ITERATIONS || "100000",
    AUDIT_LOG_RETENTION_DAYS: env.AUDIT_LOG_RETENTION_DAYS || "30",
  };

  if (env.USE_DYNAMIC_CONFIG !== "true") {
    return baseConfig;
  }

  const masterKey = env.DERBENT_API_KEY;
  if (!masterKey) {
    console.warn("[Config] USE_DYNAMIC_CONFIG is enabled, but DERBENT_API_KEY is missing.");
    return baseConfig;
  }

  const settingsRepo = new SettingsRepository(env.DB, env.KV);
  let dynamicConfig = await settingsRepo.getCachedConfig(masterKey);

  if (!dynamicConfig) {
    dynamicConfig = await settingsRepo.buildAndCacheConfig(masterKey);
  }

  return mergeConfig(baseConfig, dynamicConfig);
}

export const configMiddleware = (): MiddlewareHandler<HonoEnv> => {
  return async (c, next) => {
    const effectiveConfig = await resolveEffectiveConfig(c.env);
    c.set("config", effectiveConfig);
    await next();
  };
};
