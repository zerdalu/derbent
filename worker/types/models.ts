import type { JsonObject } from "@shared/types/json";

export interface UserRecord {
  readonly id: string;
  readonly app: string;
  readonly email: string;
  readonly email_verified: 0 | 1;
  readonly phash: string;
  readonly token_version: number;
  readonly metadata: string;
  readonly two_factor_secret: string | null;
  readonly two_factor_enabled: 0 | 1;
  readonly is_locked: 0 | 1;
  readonly created_at: string;
  readonly updated_at: string;
}

export interface AppRecord {
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

export interface SettingRecord {
  readonly key: string;
  readonly value: string | null;
  readonly is_secret: 0 | 1;
}

export interface AuditLogEntry {
  readonly userId?: string | null;
  readonly action: string;
  readonly email?: string;
  readonly ip?: string;
  readonly userAgent?: string;
  readonly details?: JsonObject;
}

export interface AuditLogRecord {
  readonly id: number;
  readonly user_id: string | null;
  readonly action: string;
  readonly email: string | null;
  readonly ip: string | null;
  readonly user_agent: string | null;
  readonly details: string | null;
  readonly created_at: string;
}

export interface DerbentConfig {
  readonly APP_ENV: string;
  readonly LOG_LEVEL: string;
  readonly APP_NAME: string;
  readonly BASE_URL: string;
  readonly COOKIE_DOMAIN?: string;
  readonly RESEND_DOMAIN?: string;
  readonly RESEND_API_KEY?: string;
  readonly GITHUB_CLIENT_ID?: string;
  readonly GITHUB_CLIENT_SECRET?: string;
  readonly GOOGLE_CLIENT_ID?: string;
  readonly GOOGLE_CLIENT_SECRET?: string;
  readonly PBKDF2_ITERATIONS: string;
  readonly AUDIT_LOG_RETENTION_DAYS: string;
}

export interface LoginSuccessResult {
  readonly requires2FA: false;
  readonly sessionId: string;
  readonly app: string;
}

export interface LoginRequires2FAResult {
  readonly requires2FA: true;
  readonly twoFactorToken: string;
  readonly app: string;
}

export type LoginResult = LoginSuccessResult | LoginRequires2FAResult;

export type EmailQueueMessage =
  | {
      readonly type: "verify_email";
      readonly to: string;
      readonly token: string;
      readonly appId?: string;
      readonly redirect?: string;
    }
  | {
      readonly type: "reset_password";
      readonly to: string;
      readonly token: string;
    }
  | {
      readonly type: "magic_link";
      readonly to: string;
      readonly token: string;
      readonly appId: string;
      readonly redirect: string;
    };
