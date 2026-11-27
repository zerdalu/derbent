import { AuthAlert, AuthShell } from "@/components/auth-shell";
import { apiGet, apiPost } from "@/utils/api-client";
import { buildAuthQuery, navigate, useRouterLocation } from "@/utils/router";
import { KeyIcon } from "@phosphor-icons/react";
import {
  ChangePasswordInputSchema,
  DashboardDataSchema,
  ForgotPasswordInputSchema,
  ResetPasswordInputSchema,
  ResetPasswordResultDataSchema,
  SuccessMessageDataSchema,
} from "@shared/schemas/auth";
import { Button, ButtonVariants, Field, FieldLabel, Input, Progress } from "@ui/index";
import { useEffect, useState, type FormEvent, type MouseEvent, type ReactElement } from "react";
import * as v from "valibot";

type ChangePasswordGateState =
  | { readonly kind: "ready"; readonly appId: string; readonly hasPassword: boolean }
  | { readonly kind: "error"; readonly appId: string; readonly message: string };

export function ForgotPasswordPage(): ReactElement {
  const location = useRouterLocation();
  const params = new URLSearchParams(location.search);
  const appId = params.get("app_id")?.trim() || "sso";
  const redirect = params.get("redirect") || "/";
  const qs = buildAuthQuery(appId, redirect);

  const [email, setEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleBackClick = (event: MouseEvent<HTMLAnchorElement>): void => {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0) {
      return;
    }
    event.preventDefault();
    navigate(`/login?${qs}`);
  };

  const submitForgot = async (): Promise<void> => {
    setError(null);
    const parsed = v.safeParse(ForgotPasswordInputSchema, { email, appId });
    if (!parsed.success) {
      setError(parsed.issues[0]?.message ?? "Please enter a valid email address.");
      return;
    }

    setIsSubmitting(true);
    const res = await apiPost("/api/auth/forgot-password", parsed.output, SuccessMessageDataSchema);
    setIsSubmitting(false);

    if (!res.ok) {
      setError(res.message);
      return;
    }

    setSuccessMessage(res.data.message);
  };

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void submitForgot();
  };

  if (successMessage) {
    return (
      <AuthShell title="Reset link sent" subtitle="Check your email inbox for instructions.">
        <AuthAlert tone="success">{successMessage}</AuthAlert>
        <Button
          type="button"
          variant={ButtonVariants.Secondary}
          className="w-full"
          onClick={() => {
            navigate(`/login?${qs}`);
          }}
        >
          Return to sign in
        </Button>
      </AuthShell>
    );
  }

  return (
    <AuthShell title="Reset password" subtitle="Enter your email and we'll send you a link to reset your password.">
      {error ? <AuthAlert tone="danger">{error}</AuthAlert> : null}

      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <Field>
          <FieldLabel htmlFor="forgot-email">Email address</FieldLabel>
          <Input
            id="forgot-email"
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

        <Button type="submit" variant={ButtonVariants.Primary} disabled={isSubmitting} className="w-full">
          <KeyIcon aria-hidden="true" className="size-4.5" />
          <span>{isSubmitting ? "Sending..." : "Send Reset Link"}</span>
        </Button>
      </form>

      <p className="text-center font-sans text-xs text-text-secondary">
        <a
          href={`/login?${qs}`}
          onClick={handleBackClick}
          className="inline-flex min-h-hit items-center rounded-control px-1 font-ui text-text-primary focus-ring hover:underline"
        >
          Back to sign in
        </a>
      </p>
    </AuthShell>
  );
}

export function ResetPasswordPage(): ReactElement {
  const location = useRouterLocation();
  const params = new URLSearchParams(location.search);

  const [capturedToken] = useState<string>(() => params.get("token")?.trim() || "");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Scrub the password reset token from the browser URL bar and session history
  useEffect(() => {
    const currentParams = new URLSearchParams(window.location.search);
    if (!currentParams.has("token")) {
      return;
    }
    currentParams.delete("token");
    const nextSearch = currentParams.toString();
    const nextUrl = `${window.location.pathname}${nextSearch ? `?${nextSearch}` : ""}`;
    window.history.replaceState(null, "", nextUrl);
  }, []);

  const submitReset = async (): Promise<void> => {
    setError(null);
    const parsed = v.safeParse(ResetPasswordInputSchema, {
      token: capturedToken,
      password,
      confirmPassword,
    });

    if (!parsed.success) {
      setError(parsed.issues[0]?.message ?? "Please check your new password.");
      return;
    }

    setIsSubmitting(true);
    const res = await apiPost("/api/auth/reset-password", parsed.output, ResetPasswordResultDataSchema);
    setIsSubmitting(false);

    if (!res.ok) {
      setError(res.message);
      return;
    }

    const loginQs = new URLSearchParams({
      app_id: res.data.appId,
      redirect: "/",
      success: "password_reset",
    }).toString();
    navigate(`/login?${loginQs}`);
  };

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void submitReset();
  };

  if (!capturedToken) {
    return (
      <AuthShell title="Invalid reset link" subtitle="No password reset token was found in the URL.">
        <AuthAlert tone="danger">Please request a new password reset link.</AuthAlert>
        <Button
          type="button"
          variant={ButtonVariants.Secondary}
          className="w-full"
          onClick={() => {
            navigate("/forgot-password");
          }}
        >
          Request new reset link
        </Button>
      </AuthShell>
    );
  }

  return (
    <AuthShell title="Set new password" subtitle="Please enter your new password below.">
      {error ? <AuthAlert tone="danger">{error}</AuthAlert> : null}

      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <Field>
          <FieldLabel htmlFor="reset-password">New Password</FieldLabel>
          <Input
            id="reset-password"
            type="password"
            autoComplete="new-password"
            placeholder="Minimum 8 characters"
            value={password}
            onChange={(event) => {
              setPassword(event.target.value);
            }}
            minLength={8}
            maxLength={128}
            required
          />
        </Field>

        <Field>
          <FieldLabel htmlFor="reset-confirm-password">Confirm New Password</FieldLabel>
          <Input
            id="reset-confirm-password"
            type="password"
            autoComplete="new-password"
            placeholder="••••••••"
            value={confirmPassword}
            onChange={(event) => {
              setConfirmPassword(event.target.value);
            }}
            minLength={8}
            maxLength={128}
            required
          />
        </Field>

        <Button type="submit" variant={ButtonVariants.Primary} disabled={isSubmitting} className="w-full">
          {isSubmitting ? "Resetting..." : "Reset Password"}
        </Button>
      </form>
    </AuthShell>
  );
}

export function ChangePasswordPage(): ReactElement {
  const location = useRouterLocation();
  const params = new URLSearchParams(location.search);
  const appId = params.get("app_id")?.trim() || "sso";

  const [gateState, setGateState] = useState<ChangePasswordGateState | null>(null);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmNewPassword, setConfirmNewPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const checkSession = async (): Promise<void> => {
      const res = await apiGet("/api/auth/dashboard", DashboardDataSchema);
      if (cancelled) {
        return;
      }

      if (!res.ok) {
        setGateState({ kind: "error", appId, message: res.message });
        return;
      }

      const targetEntry = res.data.apps.find((entry) => entry.config.id === appId);
      const ssoEntry = res.data.apps.find((entry) => entry.config.id === "sso");
      const activeSession = targetEntry?.session ?? (appId !== "sso" ? ssoEntry?.session : null) ?? null;

      if (!activeSession) {
        const endpointQs = new URLSearchParams({ app_id: appId }).toString();
        const returnUrl = `/change-password?${endpointQs}`;
        navigate(`/login?${buildAuthQuery(appId, returnUrl)}`, { replace: true });
        return;
      }

      setGateState({
        kind: "ready",
        appId,
        hasPassword: activeSession.hasPassword,
      });
    };
    void checkSession();
    return () => {
      cancelled = true;
    };
  }, [appId]);

  const activeGate = gateState?.appId === appId ? gateState : null;

  const handleBackClick = (event: MouseEvent<HTMLAnchorElement>): void => {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0) {
      return;
    }
    event.preventDefault();
    navigate("/");
  };

  const submitChange = async (): Promise<void> => {
    setError(null);
    const parsed = v.safeParse(ChangePasswordInputSchema, {
      currentPassword,
      newPassword,
      confirmNewPassword,
    });

    if (!parsed.success) {
      setError(parsed.issues[0]?.message ?? "Please check your password entries.");
      return;
    }

    const endpointQs = new URLSearchParams({ app_id: appId }).toString();
    setIsSubmitting(true);
    const res = await apiPost(`/api/auth/change-password?${endpointQs}`, parsed.output, SuccessMessageDataSchema);
    setIsSubmitting(false);

    if (!res.ok) {
      if (res.status === 401) {
        const returnUrl = `/change-password?${endpointQs}`;
        navigate(`/login?${buildAuthQuery(appId, returnUrl)}`);
        return;
      }
      setError(res.message);
      return;
    }

    const loginQs = new URLSearchParams({
      app_id: appId,
      redirect: "/",
      success: "password_changed",
    }).toString();
    navigate(`/login?${loginQs}`);
  };

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void submitChange();
  };

  return (
    <AuthShell title="Change password" subtitle="Update your password to keep your account secure.">
      {activeGate?.kind === "error" ? <AuthAlert tone="danger">{activeGate.message}</AuthAlert> : null}
      {error ? <AuthAlert tone="danger">{error}</AuthAlert> : null}

      {activeGate === null ? (
        <div className="py-3">
          <Progress value={null} label="Checking session..." />
        </div>
      ) : null}

      {activeGate?.kind === "ready" && !activeGate.hasPassword ? (
        <AuthAlert tone="info">Password changes are not available for OAuth-only accounts.</AuthAlert>
      ) : null}

      {activeGate?.kind === "ready" && activeGate.hasPassword ? (
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <Field>
            <FieldLabel htmlFor="current-password">Current Password</FieldLabel>
            <Input
              id="current-password"
              type="password"
              autoComplete="current-password"
              value={currentPassword}
              onChange={(event) => {
                setCurrentPassword(event.target.value);
              }}
              maxLength={128}
              required
            />
          </Field>

          <Field>
            <FieldLabel htmlFor="new-password">New Password</FieldLabel>
            <Input
              id="new-password"
              type="password"
              autoComplete="new-password"
              placeholder="Minimum 8 characters"
              value={newPassword}
              onChange={(event) => {
                setNewPassword(event.target.value);
              }}
              minLength={8}
              maxLength={128}
              required
            />
          </Field>

          <Field>
            <FieldLabel htmlFor="confirm-new-password">Confirm New Password</FieldLabel>
            <Input
              id="confirm-new-password"
              type="password"
              autoComplete="new-password"
              value={confirmNewPassword}
              onChange={(event) => {
                setConfirmNewPassword(event.target.value);
              }}
              minLength={8}
              maxLength={128}
              required
            />
          </Field>

          <Button type="submit" variant={ButtonVariants.Primary} disabled={isSubmitting} className="w-full">
            {isSubmitting ? "Updating..." : "Update Password"}
          </Button>
        </form>
      ) : null}

      <p className="text-center font-sans text-xs text-text-secondary">
        <a
          href="/"
          onClick={handleBackClick}
          className="inline-flex min-h-hit items-center rounded-control px-1 font-ui text-text-primary focus-ring hover:underline"
        >
          Back to Dashboard
        </a>
      </p>
    </AuthShell>
  );
}
