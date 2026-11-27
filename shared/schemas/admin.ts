import { PasswordSchema } from "@shared/schemas/auth";
import { JsonObjectSchema } from "@shared/types/json";
import { isSafeSvg } from "@shared/utils/svg";
import * as v from "valibot";

const MAX_SVG_ICON_LENGTH = 16384;
const MAX_METADATA_BYTES = 8192;
const MAX_APP_NAME_LENGTH = 100;

export const SettingKeys = {
  AppEnv: "APP_ENV",
  LogLevel: "LOG_LEVEL",
  AppName: "APP_NAME",
  BaseUrl: "BASE_URL",
  CookieDomain: "COOKIE_DOMAIN",
  ResendDomain: "RESEND_DOMAIN",
  ResendApiKey: "RESEND_API_KEY",
  GithubClientId: "GITHUB_CLIENT_ID",
  GithubClientSecret: "GITHUB_CLIENT_SECRET",
  GoogleClientId: "GOOGLE_CLIENT_ID",
  GoogleClientSecret: "GOOGLE_CLIENT_SECRET",
  Pbkdf2Iterations: "PBKDF2_ITERATIONS",
  AuditLogRetentionDays: "AUDIT_LOG_RETENTION_DAYS",
} as const;

export type SettingKey = (typeof SettingKeys)[keyof typeof SettingKeys];

export const SECRET_SETTING_KEYS: readonly SettingKey[] = [
  SettingKeys.ResendApiKey,
  SettingKeys.GithubClientSecret,
  SettingKeys.GoogleClientSecret,
];

function isIntegerInRange(raw: string, min: number, max: number): boolean {
  if (raw === "") {
    return true;
  }
  if (!/^[0-9]+$/.test(raw)) {
    return false;
  }
  const parsed = Number.parseInt(raw, 10);
  return Number.isSafeInteger(parsed) && parsed >= min && parsed <= max;
}

function isHttpOrHttpsUrl(raw: string): boolean {
  try {
    const parsed = new URL(raw);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function isValidCookieDomain(raw: string): boolean {
  const trimmed = raw.trim();
  if (trimmed === "") {
    return true;
  }
  if (trimmed.length > 253) {
    return false;
  }
  if (trimmed === "localhost") {
    return true;
  }
  const domainPattern = /^\.?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;
  return domainPattern.test(trimmed);
}

function isValidResendDomain(raw: string): boolean {
  const trimmed = raw.trim();
  if (trimmed === "") {
    return true;
  }
  if (trimmed.length > 253) {
    return false;
  }
  const domainPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;
  return domainPattern.test(trimmed);
}

function isValidAppName(raw: string): boolean {
  const trimmed = raw.trim();
  if (trimmed.length > MAX_APP_NAME_LENGTH) {
    return false;
  }
  for (let i = 0; i < raw.length; i++) {
    const code = raw.charCodeAt(i);
    if (code <= 31 || code === 127) {
      return false;
    }
  }
  return !/[<>"]/.test(raw);
}

const NullableOptionalUrlSchema = v.optional(
  v.nullable(
    v.union([
      v.literal(""),
      v.pipe(
        v.string(),
        v.url("BASE_URL must be a valid URL."),
        v.check(isHttpOrHttpsUrl, "BASE_URL must use http:// or https://."),
      ),
    ]),
  ),
);

export const AdminUpdateUserSchema = v.object({
  metadata: v.optional(
    v.pipe(
      JsonObjectSchema,
      v.check(
        (val) => new TextEncoder().encode(JSON.stringify(val)).byteLength <= MAX_METADATA_BYTES,
        "Metadata JSON must not exceed 8 KB.",
      ),
    ),
  ),
  email_verified: v.optional(v.union([v.literal(0), v.literal(1)])),
  app: v.optional(v.pipe(v.string(), v.minLength(1))),
});
export type AdminUpdateUserInput = v.InferOutput<typeof AdminUpdateUserSchema>;

export const AdminForcePasswordSchema = v.object({
  newPassword: PasswordSchema,
});
export type AdminForcePasswordInput = v.InferOutput<typeof AdminForcePasswordSchema>;

export const AdminLockAccountSchema = v.object({
  locked: v.boolean("Locked status must be a boolean."),
});
export type AdminLockAccountInput = v.InferOutput<typeof AdminLockAccountSchema>;

export const AdminCreateAppSchema = v.object({
  id: v.pipe(
    v.string(),
    v.minLength(1, "App ID is required."),
    v.regex(/^[a-z0-9-]+$/, "App ID must be lowercase, alphanumeric, or dashes."),
  ),
  name: v.pipe(v.string(), v.minLength(1, "App name is required.")),
  description: v.optional(v.nullable(v.string())),
  icon: v.optional(
    v.nullable(
      v.pipe(
        v.string(),
        v.maxLength(MAX_SVG_ICON_LENGTH, "Icon SVG must not exceed 16 KB."),
        v.check(
          (val) => val.trim() === "" || isSafeSvg(val),
          "Icon must be valid, safe SVG markup without scripts or handlers.",
        ),
      ),
    ),
  ),
  prod_url: v.pipe(
    v.string(),
    v.url("Production URL must be a valid URL."),
    v.check(isHttpOrHttpsUrl, "Production URL must use http:// or https://."),
  ),
  dev_url: v.pipe(
    v.string(),
    v.url("Development URL must be a valid URL."),
    v.check(isHttpOrHttpsUrl, "Development URL must use http:// or https://."),
  ),
  allow_signups: v.union([v.literal(0), v.literal(1)]),
  allow_logins: v.union([v.literal(0), v.literal(1)]),
});
export type AdminCreateAppInput = v.InferOutput<typeof AdminCreateAppSchema>;

export const AdminUpdateAppSchema = v.partial(v.omit(AdminCreateAppSchema, ["id"]));
export type AdminUpdateAppInput = v.InferOutput<typeof AdminUpdateAppSchema>;

export const AdminUpdateSettingsSchema = v.strictObject({
  LOG_LEVEL: v.optional(v.nullable(v.picklist(["", "debug", "info", "warn", "error", "silent"]))),
  APP_NAME: v.optional(
    v.nullable(
      v.pipe(
        v.string(),
        v.check(
          isValidAppName,
          "APP_NAME must not exceed 100 characters or contain control characters, quotes, or angle brackets.",
        ),
      ),
    ),
  ),
  BASE_URL: NullableOptionalUrlSchema,
  COOKIE_DOMAIN: v.optional(
    v.nullable(
      v.pipe(v.string(), v.check(isValidCookieDomain, "COOKIE_DOMAIN must be a valid domain name or localhost.")),
    ),
  ),
  RESEND_DOMAIN: v.optional(
    v.nullable(v.pipe(v.string(), v.check(isValidResendDomain, "RESEND_DOMAIN must be a valid domain name."))),
  ),
  RESEND_API_KEY: v.optional(v.nullable(v.string())),
  GITHUB_CLIENT_ID: v.optional(v.nullable(v.string())),
  GITHUB_CLIENT_SECRET: v.optional(v.nullable(v.string())),
  GOOGLE_CLIENT_ID: v.optional(v.nullable(v.string())),
  GOOGLE_CLIENT_SECRET: v.optional(v.nullable(v.string())),
  PBKDF2_ITERATIONS: v.optional(
    v.nullable(
      v.pipe(
        v.string(),
        v.check(
          (val) => isIntegerInRange(val, 10000, 100000),
          "PBKDF2_ITERATIONS must be an integer between 10000 and 100000.",
        ),
      ),
    ),
  ),
  AUDIT_LOG_RETENTION_DAYS: v.optional(
    v.nullable(
      v.pipe(
        v.string(),
        v.check(
          (val) => isIntegerInRange(val, 1, 3650),
          "AUDIT_LOG_RETENTION_DAYS must be an integer between 1 and 3650.",
        ),
      ),
    ),
  ),
});
export type AdminUpdateSettingsInput = v.InferOutput<typeof AdminUpdateSettingsSchema>;

export interface SettingEntry {
  readonly value: string;
  readonly source: "database" | "env";
  readonly is_secret: boolean;
}

export type AdminSettingsMap = Partial<Record<SettingKey, SettingEntry>>;

export interface AdminUserView {
  readonly id: string;
  readonly app: string;
  readonly email: string;
  readonly email_verified: 0 | 1;
  readonly token_version: number;
  readonly metadata: string;
  readonly two_factor_enabled: 0 | 1;
  readonly is_locked: 0 | 1;
  readonly has_password: boolean;
  readonly created_at: string;
  readonly updated_at: string;
}

export interface AdminAppView {
  readonly id: string;
  readonly name: string;
  readonly description: string | null;
  readonly icon: string | null;
  readonly prod_url: string;
  readonly dev_url: string;
  readonly allow_signups: 0 | 1;
  readonly allow_logins: 0 | 1;
  readonly created_at: string;
  readonly updated_at: string;
}

export interface AdminAuditLogView {
  readonly id: number;
  readonly user_id: string | null;
  readonly action: string;
  readonly email: string | null;
  readonly ip: string | null;
  readonly user_agent: string | null;
  readonly details: string | null;
  readonly created_at: string;
}

export interface AdminStatsData {
  readonly users: {
    readonly total: number;
    readonly newLast7Days: number;
    readonly mfaEnabled: number;
    readonly mfaPercentage: number;
    readonly locked: number;
  };
  readonly activity: {
    readonly failedLogins24h: number;
    readonly lockouts24h: number;
    readonly pwdResets24h: number;
  };
  readonly trends: {
    readonly signups: readonly { readonly date: string; readonly count: number }[];
    readonly logins: readonly { readonly date: string; readonly success: number; readonly failed: number }[];
  };
}

export interface PaginatedResult<T> {
  readonly items: readonly T[];
  readonly total: number;
  readonly page: number;
  readonly limit: number;
}
