import { AppError } from "@worker/types/errors";
import type { HonoEnv } from "@worker/types/hono-env";
import { buildCookieOptions } from "@worker/utils/cookie";
import { decodeBase64UrlUtf8, encodeBase64UrlUtf8 } from "@worker/utils/crypto";
import { clearConflictingSessions, getAllowedAppOrigins, getClientInfo, resolveTargetApp } from "@worker/utils/runtime";
import { sanitizeRedirect } from "@worker/utils/url";
import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import * as v from "valibot";

const OAUTH_FETCH_TIMEOUT_MS = 10000;

const OAuthStateSchema = v.object({
  appId: v.optional(v.string(), "sso"),
  redirect: v.optional(v.string(), "/"),
  nonce: v.string(),
});

type OAuthState = v.InferOutput<typeof OAuthStateSchema>;

const GitHubTokenResponseSchema = v.object({
  access_token: v.string(),
  token_type: v.optional(v.string()),
  scope: v.optional(v.string()),
});

const GitHubEmailsResponseSchema = v.array(
  v.object({
    email: v.pipe(v.string(), v.email()),
    primary: v.boolean(),
    verified: v.boolean(),
  }),
);

const GoogleTokenResponseSchema = v.object({
  access_token: v.string(),
  token_type: v.optional(v.string()),
  expires_in: v.optional(v.number()),
  scope: v.optional(v.string()),
  id_token: v.optional(v.string()),
});

const GoogleUserInfoSchema = v.object({
  id: v.string(),
  email: v.pipe(v.string(), v.email()),
  verified_email: v.boolean(),
  name: v.optional(v.string()),
  picture: v.optional(v.string()),
});

function decodeOAuthState(c: Context<HonoEnv>, rawState: string | undefined): OAuthState {
  const fallback: OAuthState = { appId: "sso", redirect: "/", nonce: "" };
  if (!rawState) {
    return fallback;
  }

  try {
    const decodedJson = decodeBase64UrlUtf8(rawState);
    const parsed: unknown = JSON.parse(decodedJson);
    const result = v.safeParse(OAuthStateSchema, parsed);
    return result.success ? result.output : fallback;
  } catch (error: unknown) {
    if (error instanceof Error) {
      c.get("logger").warn(`Failed to parse OAuth state: ${error.message}`);
    }
    return fallback;
  }
}

export class OAuthHandler {
  static async handleGitHubLogin(c: Context<HonoEnv>): Promise<Response> {
    const config = c.get("config");
    const resolved = await resolveTargetApp(
      c.get("appRepo"),
      c.req.query("app_id"),
      c.req.query("redirect"),
      config.APP_ENV,
    );

    if (!config.GITHUB_CLIENT_ID) {
      const qs = new URLSearchParams({
        app_id: resolved.appId,
        redirect: resolved.redirect,
        error: "github_not_configured",
      }).toString();
      return c.redirect(`/login?${qs}`);
    }

    const nonce = crypto.randomUUID();
    const cookieOpts = buildCookieOptions(config, 600);
    setCookie(c, "github_oauth_state", nonce, cookieOpts);

    const state = encodeBase64UrlUtf8(JSON.stringify({ appId: resolved.appId, redirect: resolved.redirect, nonce }));
    const redirectUri = `${config.BASE_URL.replace(/\/+$/, "")}/auth/github/callback`;
    const authParams = new URLSearchParams({
      client_id: config.GITHUB_CLIENT_ID,
      redirect_uri: redirectUri,
      scope: "user:email",
      state,
    }).toString();

    return c.redirect(`https://github.com/login/oauth/authorize?${authParams}`);
  }

  static async handleGitHubCallback(c: Context<HonoEnv>): Promise<Response> {
    const config = c.get("config");
    const appRepo = c.get("appRepo");
    const code = c.req.query("code");
    const state = c.req.query("state");
    const { ip, userAgent } = getClientInfo(c);

    const storedNonce = getCookie(c, "github_oauth_state");
    deleteCookie(c, "github_oauth_state", buildCookieOptions(config));

    const parsedState = decodeOAuthState(c, state);
    const appId = parsedState.appId || "sso";
    const targetApp = await appRepo.findById(appId);
    const allowedOrigins: readonly string[] = targetApp ? getAllowedAppOrigins(targetApp, config.APP_ENV) : [];
    const redirect = sanitizeRedirect(parsedState.redirect, allowedOrigins);

    if (!config.GITHUB_CLIENT_ID || !config.GITHUB_CLIENT_SECRET) {
      const qs = new URLSearchParams({ app_id: appId, redirect, error: "github_not_configured" }).toString();
      return c.redirect(`/login?${qs}`);
    }

    if (!code || !state) {
      const qs = new URLSearchParams({ app_id: appId, redirect }).toString();
      return c.redirect(`/login?${qs}`);
    }

    if (!storedNonce || !parsedState.nonce || storedNonce !== parsedState.nonce) {
      const qs = new URLSearchParams({ app_id: appId, redirect, error: "github_failed" }).toString();
      return c.redirect(`/login?${qs}`);
    }

    try {
      const redirectUri = `${config.BASE_URL.replace(/\/+$/, "")}/auth/github/callback`;
      const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({
          client_id: config.GITHUB_CLIENT_ID,
          client_secret: config.GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: redirectUri,
        }),
        signal: AbortSignal.timeout(OAUTH_FETCH_TIMEOUT_MS),
      });

      if (!tokenRes.ok) {
        throw new AppError(`GitHub token exchange failed with status ${tokenRes.status}`, 401);
      }

      const rawTokenData: unknown = await tokenRes.json();
      const tokenResult = v.safeParse(GitHubTokenResponseSchema, rawTokenData);
      if (!tokenResult.success || !tokenResult.output.access_token) {
        throw new AppError("GitHub token exchange failed", 401);
      }

      const emailRes = await fetch("https://api.github.com/user/emails", {
        headers: {
          Authorization: `Bearer ${tokenResult.output.access_token}`,
          "User-Agent": "Derbent-Auth",
          Accept: "application/json",
        },
        signal: AbortSignal.timeout(OAUTH_FETCH_TIMEOUT_MS),
      });

      if (!emailRes.ok) {
        throw new AppError(`GitHub email lookup failed with status ${emailRes.status}`, 502);
      }

      const rawEmails: unknown = await emailRes.json();
      const emailsResult = v.safeParse(GitHubEmailsResponseSchema, rawEmails);
      if (!emailsResult.success) {
        throw new AppError("Failed to parse GitHub email response", 500);
      }

      const verifiedPrimary = emailsResult.output.find((entry) => entry.primary && entry.verified);
      const verifiedSecondary = emailsResult.output.find((entry) => entry.verified);
      const primaryEmail = verifiedPrimary?.email ?? verifiedSecondary?.email;

      if (!primaryEmail) {
        throw new AppError("No verified email found on GitHub account", 400);
      }

      const loginResult = await c.get("authService").loginWithOAuth(primaryEmail, "github", appId, ip, userAgent);

      if (loginResult.requires2FA) {
        const qs = new URLSearchParams({
          token: loginResult.twoFactorToken,
          app_id: appId,
          redirect,
        }).toString();
        return c.redirect(`/2fa/verify?${qs}`);
      }

      await clearConflictingSessions(c, loginResult.app);
      setCookie(c, `session_${loginResult.app}`, loginResult.sessionId, buildCookieOptions(config, 86400));

      return c.redirect(redirect);
    } catch (error: unknown) {
      if (error instanceof Error) {
        c.get("logger").error(`GitHub authentication callback error: ${error.message}`, error);
      }
      const qs = new URLSearchParams({ app_id: appId, redirect, error: "github_failed" }).toString();
      return c.redirect(`/login?${qs}`);
    }
  }

  static async handleGoogleLogin(c: Context<HonoEnv>): Promise<Response> {
    const config = c.get("config");
    const resolved = await resolveTargetApp(
      c.get("appRepo"),
      c.req.query("app_id"),
      c.req.query("redirect"),
      config.APP_ENV,
    );

    if (!config.GOOGLE_CLIENT_ID) {
      const qs = new URLSearchParams({
        app_id: resolved.appId,
        redirect: resolved.redirect,
        error: "google_not_configured",
      }).toString();
      return c.redirect(`/login?${qs}`);
    }

    const nonce = crypto.randomUUID();
    setCookie(c, "google_oauth_state", nonce, buildCookieOptions(config, 600));

    const state = encodeBase64UrlUtf8(JSON.stringify({ appId: resolved.appId, redirect: resolved.redirect, nonce }));
    const redirectUri = `${config.BASE_URL.replace(/\/+$/, "")}/auth/google/callback`;
    const authParams = new URLSearchParams({
      client_id: config.GOOGLE_CLIENT_ID,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: "email profile",
      state,
    }).toString();

    return c.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${authParams}`);
  }

  static async handleGoogleCallback(c: Context<HonoEnv>): Promise<Response> {
    const config = c.get("config");
    const appRepo = c.get("appRepo");
    const code = c.req.query("code");
    const state = c.req.query("state");
    const { ip, userAgent } = getClientInfo(c);

    const storedNonce = getCookie(c, "google_oauth_state");
    deleteCookie(c, "google_oauth_state", buildCookieOptions(config));

    const parsedState = decodeOAuthState(c, state);
    const appId = parsedState.appId || "sso";
    const targetApp = await appRepo.findById(appId);
    const allowedOrigins: readonly string[] = targetApp ? getAllowedAppOrigins(targetApp, config.APP_ENV) : [];
    const redirect = sanitizeRedirect(parsedState.redirect, allowedOrigins);

    if (!config.GOOGLE_CLIENT_ID || !config.GOOGLE_CLIENT_SECRET) {
      const qs = new URLSearchParams({ app_id: appId, redirect, error: "google_not_configured" }).toString();
      return c.redirect(`/login?${qs}`);
    }

    if (!code || !state) {
      const qs = new URLSearchParams({ app_id: appId, redirect }).toString();
      return c.redirect(`/login?${qs}`);
    }

    if (!storedNonce || !parsedState.nonce || storedNonce !== parsedState.nonce) {
      const qs = new URLSearchParams({ app_id: appId, redirect, error: "google_failed" }).toString();
      return c.redirect(`/login?${qs}`);
    }

    try {
      const redirectUri = `${config.BASE_URL.replace(/\/+$/, "")}/auth/google/callback`;
      const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: config.GOOGLE_CLIENT_ID,
          client_secret: config.GOOGLE_CLIENT_SECRET,
          code,
          grant_type: "authorization_code",
          redirect_uri: redirectUri,
        }).toString(),
        signal: AbortSignal.timeout(OAUTH_FETCH_TIMEOUT_MS),
      });

      if (!tokenRes.ok) {
        throw new AppError(`Google token exchange failed with status ${tokenRes.status}`, 401);
      }

      const rawTokenData: unknown = await tokenRes.json();
      const tokenResult = v.safeParse(GoogleTokenResponseSchema, rawTokenData);
      if (!tokenResult.success || !tokenResult.output.access_token) {
        throw new AppError("Google token exchange failed", 401);
      }

      const userRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
        headers: { Authorization: `Bearer ${tokenResult.output.access_token}` },
        signal: AbortSignal.timeout(OAUTH_FETCH_TIMEOUT_MS),
      });

      if (!userRes.ok) {
        throw new AppError(`Google userinfo lookup failed with status ${userRes.status}`, 502);
      }

      const rawUserData: unknown = await userRes.json();
      const userResult = v.safeParse(GoogleUserInfoSchema, rawUserData);
      if (!userResult.success) {
        throw new AppError("Failed to parse Google user response", 500);
      }

      if (!userResult.output.verified_email) {
        throw new AppError("Google email is not verified", 400);
      }

      const loginResult = await c
        .get("authService")
        .loginWithOAuth(userResult.output.email, "google", appId, ip, userAgent);

      if (loginResult.requires2FA) {
        const qs = new URLSearchParams({
          token: loginResult.twoFactorToken,
          app_id: appId,
          redirect,
        }).toString();
        return c.redirect(`/2fa/verify?${qs}`);
      }

      await clearConflictingSessions(c, loginResult.app);
      setCookie(c, `session_${loginResult.app}`, loginResult.sessionId, buildCookieOptions(config, 86400));

      return c.redirect(redirect);
    } catch (error: unknown) {
      if (error instanceof Error) {
        c.get("logger").error(`Google authentication callback error: ${error.message}`, error);
      }
      const qs = new URLSearchParams({ app_id: appId, redirect, error: "google_failed" }).toString();
      return c.redirect(`/login?${qs}`);
    }
  }
}
