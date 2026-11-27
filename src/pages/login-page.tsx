import { AuthAlert, AuthShell } from "@/components/auth-shell";
import { apiGet, apiPost } from "@/utils/api-client";
import { buildAuthQuery, navigate, useRouterLocation } from "@/utils/router";
import { SignInIcon } from "@phosphor-icons/react";
import {
  AuthContextDataSchema,
  LoginInputSchema,
  LoginResultDataSchema,
  type AuthContextData,
} from "@shared/schemas/auth";
import { Button, ButtonVariants, Field, FieldLabel, Input, Separator } from "@ui/index";
import { useEffect, useState, type FormEvent, type MouseEvent, type ReactElement } from "react";
import * as v from "valibot";

interface LoadedAuthContext {
  readonly key: string;
  readonly data: AuthContextData;
}

function resolveQueryError(errorParam: string | null): string | null {
  switch (errorParam) {
    case "github_failed":
      return "GitHub authentication failed. Please try again.";
    case "github_not_configured":
      return "GitHub login is not enabled on this instance.";
    case "google_failed":
      return "Google authentication failed. Please try again.";
    case "google_not_configured":
      return "Google login is not enabled on this instance.";
    case "account_locked":
      return "This account has been locked. Please contact support.";
    case "signups_disabled":
      return "Registrations are currently closed for this application.";
    case "logins_disabled":
      return "Logins are currently disabled for this application.";
    case "account_conflict":
      return "An app-specific account already exists for this email address.";
    default:
      return null;
  }
}

function resolveQuerySuccess(successParam: string | null): string | null {
  switch (successParam) {
    case "password_reset":
      return "Password reset successful. You can now sign in.";
    case "password_changed":
      return "Password changed successfully. Please sign in again.";
    case "email_verified":
      return "Email verified successfully. You can now sign in.";
    case "2fa_enabled":
      return "Two-Factor Authentication was successfully enabled.";
    case "2fa_disabled":
      return "Two-Factor Authentication was successfully disabled.";
    default:
      return null;
  }
}

export function LoginPage(): ReactElement {
  const location = useRouterLocation();
  const params = new URLSearchParams(location.search);
  const appId = params.get("app_id")?.trim() || "sso";
  const rawRedirect = params.get("redirect") || "/";
  const contextKey = `${appId}:${rawRedirect}`;
  const queryError = resolveQueryError(params.get("error"));
  const querySuccess = resolveQuerySuccess(params.get("success"));

  const [loadedContext, setLoadedContext] = useState<LoadedAuthContext | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const loadContext = async (): Promise<void> => {
      const qs = new URLSearchParams({ app_id: appId, redirect: rawRedirect }).toString();
      const result = await apiGet(`/api/auth/context?${qs}`, AuthContextDataSchema);
      if (!cancelled && result.ok) {
        setLoadedContext({ key: contextKey, data: result.data });
      }
    };
    void loadContext();
    return () => {
      cancelled = true;
    };
  }, [appId, rawRedirect, contextKey]);

  const context = loadedContext?.key === contextKey ? loadedContext.data : null;
  const effectiveAppId = context?.appId ?? appId;
  const effectiveTargetName = context?.targetAppName ?? (appId === "sso" ? "Single sign-on" : appId);
  const effectiveRedirect = context?.redirect ?? rawRedirect;
  const qs = buildAuthQuery(effectiveAppId, effectiveRedirect);
  const activeError = formError ?? queryError;

  const handleSpaNavigation = (event: MouseEvent<HTMLAnchorElement>, path: string): void => {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0) {
      return;
    }
    event.preventDefault();
    navigate(path);
  };

  const submitLogin = async (): Promise<void> => {
    setFormError(null);
    const parsed = v.safeParse(LoginInputSchema, {
      email,
      password,
      appId: effectiveAppId,
      redirect: effectiveRedirect,
    });

    if (!parsed.success) {
      setFormError(parsed.issues[0]?.message ?? "Please check your credentials.");
      return;
    }

    setIsSubmitting(true);
    const res = await apiPost("/api/auth/login", parsed.output, LoginResultDataSchema);
    setIsSubmitting(false);

    if (!res.ok) {
      setFormError(res.message);
      return;
    }

    switch (res.data.status) {
      case "authenticated":
        navigate(res.data.redirect);
        break;
      case "requires_2fa": {
        const verifyQs = new URLSearchParams({
          token: res.data.twoFactorToken,
          app_id: res.data.appId,
          redirect: res.data.redirect,
        }).toString();
        navigate(`/2fa/verify?${verifyQs}`);
        break;
      }
      case "verification_required":
        navigate(`/verify-pending?${buildAuthQuery(res.data.appId, res.data.redirect)}`);
        break;
      default: {
        const _exhaustive: never = res.data;
        throw new Error(`Unhandled login status: ${JSON.stringify(_exhaustive)}`);
      }
    }
  };

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void submitLogin();
  };

  const showOAuth = Boolean(context && (context.providers.google || context.providers.github));
  const loginsDisabled = context !== null && !context.allowLogins;

  return (
    <AuthShell
      appName={context?.appName}
      title="Sign in"
      subtitle={
        <>
          Continue to <span className="font-ui text-text-primary">{effectiveTargetName}</span>
        </>
      }
    >
      {querySuccess ? <AuthAlert tone="success">{querySuccess}</AuthAlert> : null}
      {activeError ? <AuthAlert tone="danger">{activeError}</AuthAlert> : null}
      {loginsDisabled ? <AuthAlert tone="danger">Logins are currently disabled for this application.</AuthAlert> : null}

      {showOAuth && context ? (
        <div className="flex flex-col gap-4">
          <div className="flex flex-col gap-2.5 sm:flex-row">
            {context.providers.google ? (
              <a
                href={`/auth/google?${qs}`}
                className="inline-flex h-control-md min-h-hit min-w-hit flex-1 items-center justify-center gap-2 rounded-control border border-border-default bg-surface-300 px-control-px-md font-mono text-xs font-ui tracking-ui text-text-primary shadow-control focus-ring transition-control duration-control ease-ui hover:border-border-strong hover:bg-surface-hover active:scale-press active:bg-surface-active"
              >
                <svg aria-hidden="true" className="size-4.5 shrink-0">
                  <use href="/icons.svg#google-icon" />
                </svg>
                <span>Google</span>
              </a>
            ) : null}

            {context.providers.github ? (
              <a
                href={`/auth/github?${qs}`}
                className="inline-flex h-control-md min-h-hit min-w-hit flex-1 items-center justify-center gap-2 rounded-control border border-border-default bg-surface-300 px-control-px-md font-mono text-xs font-ui tracking-ui text-text-primary shadow-control focus-ring transition-control duration-control ease-ui hover:border-border-strong hover:bg-surface-hover active:scale-press active:bg-surface-active"
              >
                <svg aria-hidden="true" className="size-4.5 shrink-0">
                  <use href="/icons.svg#github-icon" />
                </svg>
                <span>GitHub</span>
              </a>
            ) : null}
          </div>

          <div className="relative flex items-center gap-3">
            <Separator className="flex-1" />
            <span className="font-mono text-xs tracking-mono text-text-muted uppercase">or</span>
            <Separator className="flex-1" />
          </div>
        </div>
      ) : null}

      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <Field>
          <FieldLabel htmlFor="login-email">Email address</FieldLabel>
          <Input
            id="login-email"
            type="email"
            autoComplete="email"
            placeholder="name@example.com"
            value={email}
            onChange={(event) => {
              setEmail(event.target.value);
            }}
            required
          />
        </Field>

        <Field>
          <div className="flex items-center justify-between gap-2">
            <FieldLabel htmlFor="login-password">Password</FieldLabel>
            <a
              href={`/forgot-password?${qs}`}
              onClick={(event) => {
                handleSpaNavigation(event, `/forgot-password?${qs}`);
              }}
              className="inline-flex min-h-hit items-center rounded-control px-1 font-sans text-xs font-ui text-text-secondary focus-ring hover:text-text-primary hover:underline"
            >
              Forgot password?
            </a>
          </div>
          <Input
            id="login-password"
            type="password"
            autoComplete="current-password"
            placeholder="••••••••"
            value={password}
            onChange={(event) => {
              setPassword(event.target.value);
            }}
            required
          />
        </Field>

        <Button
          type="submit"
          variant={ButtonVariants.Primary}
          disabled={isSubmitting || loginsDisabled}
          className="w-full"
        >
          <SignInIcon aria-hidden="true" className="size-4.5" />
          <span>{isSubmitting ? "Signing in..." : "Sign in"}</span>
        </Button>
      </form>

      <div className="flex flex-col gap-2 text-center font-sans text-xs text-text-secondary">
        <p>
          Or{" "}
          <a
            href={`/magic-link?${qs}`}
            onClick={(event) => {
              handleSpaNavigation(event, `/magic-link?${qs}`);
            }}
            className="inline-flex min-h-hit items-center rounded-control px-1 font-ui text-text-primary focus-ring hover:underline"
          >
            sign in with a Magic Link
          </a>
        </p>

        {context?.allowSignups === true ? (
          <p>
            Don&apos;t have an account?{" "}
            <a
              href={`/register?${qs}`}
              onClick={(event) => {
                handleSpaNavigation(event, `/register?${qs}`);
              }}
              className="inline-flex min-h-hit items-center rounded-control px-1 font-ui text-text-primary focus-ring hover:underline"
            >
              Sign up
            </a>
          </p>
        ) : null}
      </div>
    </AuthShell>
  );
}
