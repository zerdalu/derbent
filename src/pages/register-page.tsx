import { AuthAlert, AuthShell } from "@/components/auth-shell";
import { apiGet, apiPost } from "@/utils/api-client";
import { buildAuthQuery, navigate, useRouterLocation } from "@/utils/router";
import { UserPlusIcon } from "@phosphor-icons/react";
import {
  AuthContextDataSchema,
  RedirectResultDataSchema,
  RegisterInputSchema,
  type AuthContextData,
} from "@shared/schemas/auth";
import { Button, ButtonVariants, Field, FieldLabel, Input } from "@ui/index";
import { useEffect, useState, type FormEvent, type MouseEvent, type ReactElement } from "react";
import * as v from "valibot";

interface LoadedAuthContext {
  readonly key: string;
  readonly data: AuthContextData;
}

export function RegisterPage(): ReactElement {
  const location = useRouterLocation();
  const params = new URLSearchParams(location.search);
  const appId = params.get("app_id")?.trim() || "sso";
  const rawRedirect = params.get("redirect") || "/";
  const contextKey = `${appId}:${rawRedirect}`;

  const [loadedContext, setLoadedContext] = useState<LoadedAuthContext | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
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
  const signupsDisabled = context !== null && !context.allowSignups;

  const handleLoginNav = (event: MouseEvent<HTMLAnchorElement>): void => {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0) {
      return;
    }
    event.preventDefault();
    navigate(`/login?${qs}`);
  };

  const submitRegistration = async (): Promise<void> => {
    setError(null);
    const parsed = v.safeParse(RegisterInputSchema, {
      email,
      password,
      confirmPassword,
      appId: effectiveAppId,
      redirect: effectiveRedirect,
    });

    if (!parsed.success) {
      setError(parsed.issues[0]?.message ?? "Please check your registration details.");
      return;
    }

    setIsSubmitting(true);
    const res = await apiPost("/api/auth/register", parsed.output, RedirectResultDataSchema);
    setIsSubmitting(false);

    if (!res.ok) {
      setError(res.message);
      return;
    }

    navigate(`/verify-pending?${buildAuthQuery(effectiveAppId, res.data.redirect)}`);
  };

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void submitRegistration();
  };

  return (
    <AuthShell
      appName={context?.appName}
      title="Create account"
      subtitle={
        effectiveAppId === "sso" ? (
          "Create a global account to access all services"
        ) : (
          <>
            Create an account to access <span className="font-ui text-text-primary">{effectiveTargetName}</span>
          </>
        )
      }
    >
      {error ? <AuthAlert tone="danger">{error}</AuthAlert> : null}
      {signupsDisabled ? (
        <AuthAlert tone="danger">Registrations are currently closed for this application.</AuthAlert>
      ) : null}

      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <Field>
          <FieldLabel htmlFor="register-email">Email address</FieldLabel>
          <Input
            id="register-email"
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
          <FieldLabel htmlFor="register-password">Password</FieldLabel>
          <Input
            id="register-password"
            type="password"
            autoComplete="new-password"
            placeholder="Minimum 8 characters"
            value={password}
            onChange={(event) => {
              setPassword(event.target.value);
            }}
            minLength={8}
            required
          />
        </Field>

        <Field>
          <FieldLabel htmlFor="register-confirm-password">Confirm password</FieldLabel>
          <Input
            id="register-confirm-password"
            type="password"
            autoComplete="new-password"
            placeholder="••••••••"
            value={confirmPassword}
            onChange={(event) => {
              setConfirmPassword(event.target.value);
            }}
            minLength={8}
            required
          />
        </Field>

        <Button
          type="submit"
          variant={ButtonVariants.Primary}
          disabled={isSubmitting || signupsDisabled}
          className="w-full"
        >
          <UserPlusIcon aria-hidden="true" className="size-4.5" />
          <span>{isSubmitting ? "Creating account..." : `Register for ${effectiveTargetName}`}</span>
        </Button>
      </form>

      <p className="text-center font-sans text-xs text-text-secondary">
        Already have an account?{" "}
        <a
          href={`/login?${qs}`}
          onClick={handleLoginNav}
          className="inline-flex min-h-hit items-center rounded-control px-1 font-ui text-text-primary focus-ring hover:underline"
        >
          Sign in
        </a>
      </p>
    </AuthShell>
  );
}
