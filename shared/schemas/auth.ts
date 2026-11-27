import { JsonObjectSchema, type JsonObject } from "@shared/types/json";
import * as v from "valibot";

export const EmailSchema = v.pipe(
  v.string("Email is required."),
  v.transform((value) => value.trim().toLowerCase()),
  v.minLength(1, "Email is required."),
  v.maxLength(254, "Email address is too long."),
  v.email("Please enter a valid email address."),
);

export const PasswordSchema = v.pipe(
  v.string("Password is required."),
  v.minLength(8, "Password must be at least 8 characters long."),
  v.maxLength(128, "Password must not exceed 128 characters."),
);

export const TotpCodeSchema = v.pipe(
  v.string("Code is required."),
  v.transform((value) => value.trim()),
  v.regex(/^[0-9]{6}$/, "Code must be a 6-digit number."),
);

export const AppIdFieldSchema = v.optional(
  v.pipe(
    v.string(),
    v.transform((value) => value.trim()),
  ),
  "sso",
);

export const RedirectFieldSchema = v.optional(v.string(), "/");

export const LoginInputSchema = v.object({
  email: EmailSchema,
  password: PasswordSchema,
  appId: AppIdFieldSchema,
  redirect: RedirectFieldSchema,
});
export type LoginInput = v.InferOutput<typeof LoginInputSchema>;

export const RegisterInputSchema = v.pipe(
  v.object({
    email: EmailSchema,
    password: PasswordSchema,
    confirmPassword: v.string("Please confirm your password."),
    appId: AppIdFieldSchema,
    redirect: RedirectFieldSchema,
  }),
  v.check((input) => input.password === input.confirmPassword, "Passwords do not match."),
);
export type RegisterInput = v.InferOutput<typeof RegisterInputSchema>;

export const ForgotPasswordInputSchema = v.object({
  email: EmailSchema,
  appId: AppIdFieldSchema,
});
export type ForgotPasswordInput = v.InferOutput<typeof ForgotPasswordInputSchema>;

export const ResetPasswordInputSchema = v.pipe(
  v.object({
    token: v.pipe(v.string("Reset token is required."), v.minLength(1, "Reset token is required.")),
    password: PasswordSchema,
    confirmPassword: v.string("Please confirm your password."),
  }),
  v.check((input) => input.password === input.confirmPassword, "Passwords do not match."),
);
export type ResetPasswordInput = v.InferOutput<typeof ResetPasswordInputSchema>;

export const ChangePasswordInputSchema = v.pipe(
  v.object({
    currentPassword: v.pipe(
      v.string("Current password is required."),
      v.minLength(1, "Current password is required."),
      v.maxLength(128, "Password must not exceed 128 characters."),
    ),
    newPassword: PasswordSchema,
    confirmNewPassword: v.string("Please confirm your new password."),
  }),
  v.check((input) => input.newPassword === input.confirmNewPassword, "New passwords do not match."),
);
export type ChangePasswordInput = v.InferOutput<typeof ChangePasswordInputSchema>;

export const MagicLinkRequestInputSchema = v.object({
  email: EmailSchema,
  appId: AppIdFieldSchema,
  redirect: RedirectFieldSchema,
});
export type MagicLinkRequestInput = v.InferOutput<typeof MagicLinkRequestInputSchema>;

export const VerifyEmailInputSchema = v.object({
  token: v.pipe(v.string("Verification token is required."), v.minLength(1, "Verification token is required.")),
});
export type VerifyEmailInput = v.InferOutput<typeof VerifyEmailInputSchema>;

export const VerifyMagicLinkInputSchema = v.object({
  token: v.pipe(v.string("Magic link token is required."), v.minLength(1, "Magic link token is required.")),
  appId: AppIdFieldSchema,
  redirect: RedirectFieldSchema,
});
export type VerifyMagicLinkInput = v.InferOutput<typeof VerifyMagicLinkInputSchema>;

export const TwoFactorVerifyInputSchema = v.object({
  token: v.pipe(v.string("Session token is required."), v.minLength(1, "Session token is required.")),
  code: TotpCodeSchema,
  appId: AppIdFieldSchema,
  redirect: RedirectFieldSchema,
});
export type TwoFactorVerifyInput = v.InferOutput<typeof TwoFactorVerifyInputSchema>;

export const TwoFactorCodeInputSchema = v.object({
  code: TotpCodeSchema,
});
export type TwoFactorCodeInput = v.InferOutput<typeof TwoFactorCodeInputSchema>;

export const AppActionInputSchema = v.object({
  appId: AppIdFieldSchema,
  redirect: RedirectFieldSchema,
});
export type AppActionInput = v.InferOutput<typeof AppActionInputSchema>;

export const SessionSchema = v.object({
  userId: v.string(),
  email: v.string(),
  appId: v.string(),
  createdAt: v.number(),
  ip: v.string(),
  userAgent: v.string(),
  tokenVersion: v.number(),
  data: JsonObjectSchema,
});

export type Session<T = JsonObject> = Omit<v.InferOutput<typeof SessionSchema>, "data"> & {
  readonly data: T;
};

export const AppViewConfigSchema = v.object({
  id: v.string(),
  name: v.string(),
  description: v.string(),
  icon: v.nullable(v.string()),
  url: v.string(),
  allowSignups: v.boolean(),
  allowLogins: v.boolean(),
});
export type AppViewConfig = v.InferOutput<typeof AppViewConfigSchema>;

export const PublicSessionSummarySchema = v.object({
  userId: v.string(),
  email: v.string(),
  appId: v.string(),
  createdAt: v.number(),
  hasPassword: v.optional(v.boolean(), true),
});
export type PublicSessionSummary = v.InferOutput<typeof PublicSessionSummarySchema>;

export const DashboardAppStatusSchema = v.object({
  config: AppViewConfigSchema,
  session: v.nullable(PublicSessionSummarySchema),
  isSsoFallback: v.boolean(),
});
export type DashboardAppStatus = v.InferOutput<typeof DashboardAppStatusSchema>;

export const DashboardDataSchema = v.object({
  appName: v.string(),
  apps: v.array(DashboardAppStatusSchema),
  hasAnySession: v.boolean(),
});
export type DashboardData = v.InferOutput<typeof DashboardDataSchema>;

export const AuthContextDataSchema = v.object({
  appName: v.string(),
  appId: v.string(),
  targetAppName: v.string(),
  redirect: v.string(),
  allowSignups: v.boolean(),
  allowLogins: v.boolean(),
  providers: v.object({
    github: v.boolean(),
    google: v.boolean(),
  }),
});
export type AuthContextData = v.InferOutput<typeof AuthContextDataSchema>;

export const LoginResultDataSchema = v.variant("status", [
  v.object({
    status: v.literal("authenticated"),
    appId: v.string(),
    redirect: v.string(),
  }),
  v.object({
    status: v.literal("requires_2fa"),
    appId: v.string(),
    twoFactorToken: v.string(),
    redirect: v.string(),
  }),
  v.object({
    status: v.literal("verification_required"),
    appId: v.string(),
    redirect: v.string(),
  }),
]);
export type LoginResultData = v.InferOutput<typeof LoginResultDataSchema>;

export const RedirectResultDataSchema = v.object({
  redirect: v.string(),
});
export type RedirectResultData = v.InferOutput<typeof RedirectResultDataSchema>;

export const SuccessMessageDataSchema = v.object({
  message: v.string(),
});
export type SuccessMessageData = v.InferOutput<typeof SuccessMessageDataSchema>;

export const ResetPasswordResultDataSchema = v.object({
  appId: v.string(),
});
export type ResetPasswordResultData = v.InferOutput<typeof ResetPasswordResultDataSchema>;

export const TwoFactorSetupStateDataSchema = v.variant("enabled", [
  v.object({
    enabled: v.literal(true),
  }),
  v.object({
    enabled: v.literal(false),
    secret: v.string(),
    otpauthUrl: v.string(),
    email: v.string(),
  }),
]);
export type TwoFactorSetupStateData = v.InferOutput<typeof TwoFactorSetupStateDataSchema>;

export const HealthDataSchema = v.object({
  status: v.string(),
  service: v.string(),
});
export type HealthData = v.InferOutput<typeof HealthDataSchema>;

export type RpcVerifyResult =
  | { readonly ok: true; readonly session: Session }
  | { readonly ok: false; readonly status: 400 | 401 | 403 | 500; readonly code: string; readonly message: string };

export type RpcLogoutResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly status: 400 | 401 | 403 | 500; readonly code: string; readonly message: string };
