import { AuthAlert, AuthShell } from "@/components/auth-shell";
import { QrCode } from "@/components/qr-code";
import { apiGet, apiPost } from "@/utils/api-client";
import { buildAuthQuery, navigate, useRouterLocation } from "@/utils/router";
import { ShieldCheckIcon } from "@phosphor-icons/react";
import {
  RedirectResultDataSchema,
  SuccessMessageDataSchema,
  TwoFactorCodeInputSchema,
  TwoFactorSetupStateDataSchema,
  TwoFactorVerifyInputSchema,
  type TwoFactorSetupStateData,
} from "@shared/schemas/auth";
import { Badge, BadgeVariants, Button, ButtonVariants, Field, FieldLabel, Input, Progress } from "@ui/index";
import { useEffect, useState, type FormEvent, type MouseEvent, type ReactElement } from "react";
import * as v from "valibot";

type SetupFetchState =
  | { readonly kind: "loaded"; readonly appId: string; readonly data: TwoFactorSetupStateData }
  | { readonly kind: "error"; readonly appId: string; readonly message: string };

export function TwoFactorVerifyPage(): ReactElement {
  const location = useRouterLocation();
  const params = new URLSearchParams(location.search);
  const appId = params.get("app_id")?.trim() || "sso";
  const redirect = params.get("redirect") || "/";
  const qs = buildAuthQuery(appId, redirect);

  const [capturedToken] = useState<string>(() => params.get("token")?.trim() || "");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Scrub the two-factor challenge token from the browser URL bar and session history
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

  const handleBackClick = (event: MouseEvent<HTMLAnchorElement>): void => {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0) {
      return;
    }
    event.preventDefault();
    navigate(`/login?${qs}`);
  };

  const submitVerify = async (): Promise<void> => {
    setError(null);
    const parsed = v.safeParse(TwoFactorVerifyInputSchema, {
      token: capturedToken,
      code,
      appId,
      redirect,
    });
    if (!parsed.success) {
      setError(parsed.issues[0]?.message ?? "Please enter a valid 6-digit code.");
      return;
    }

    setIsSubmitting(true);
    const res = await apiPost("/api/auth/2fa/verify", parsed.output, RedirectResultDataSchema);
    setIsSubmitting(false);

    if (!res.ok) {
      setError(res.message);
      return;
    }

    navigate(res.data.redirect);
  };

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void submitVerify();
  };

  if (!capturedToken) {
    return (
      <AuthShell title="Two-factor authentication" subtitle="Your verification challenge is missing or expired.">
        <AuthAlert tone="danger">Please sign in again to start a new two-factor verification.</AuthAlert>
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
    <AuthShell
      title="Two-factor authentication"
      subtitle="Enter the 6-digit code from your authenticator app to continue."
    >
      {error ? <AuthAlert tone="danger">{error}</AuthAlert> : null}

      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <Field>
          <FieldLabel htmlFor="twofa-verify-code">6-digit code</FieldLabel>
          <Input
            id="twofa-verify-code"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]{6}"
            maxLength={6}
            placeholder="123456"
            value={code}
            onChange={(event) => {
              setCode(event.target.value.replace(/[^0-9]/g, ""));
            }}
            className="text-center font-mono text-sm tracking-widest tabular-nums"
            required
          />
        </Field>

        <Button type="submit" variant={ButtonVariants.Primary} disabled={isSubmitting} className="w-full">
          <ShieldCheckIcon aria-hidden="true" className="size-4.5" />
          <span>{isSubmitting ? "Verifying..." : "Verify"}</span>
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

export function TwoFactorSetupPage(): ReactElement {
  const location = useRouterLocation();
  const params = new URLSearchParams(location.search);
  const appId = params.get("app_id")?.trim() || "sso";

  const [fetchState, setFetchState] = useState<SetupFetchState | null>(null);
  const [code, setCode] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const load = async (): Promise<void> => {
      const qs = new URLSearchParams({ app_id: appId }).toString();
      const res = await apiGet(`/api/auth/2fa/setup?${qs}`, TwoFactorSetupStateDataSchema);
      if (cancelled) {
        return;
      }

      if (!res.ok) {
        if (res.status === 401) {
          const returnUrl = `/2fa/setup?${qs}`;
          navigate(`/login?${buildAuthQuery(appId, returnUrl)}`, { replace: true });
          return;
        }
        setFetchState({ kind: "error", appId, message: res.message });
        return;
      }

      setFetchState({ kind: "loaded", appId, data: res.data });
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, [appId]);

  const activeFetchState = fetchState?.appId === appId ? fetchState : null;
  const setupState = activeFetchState?.kind === "loaded" ? activeFetchState.data : null;
  const loadError = activeFetchState?.kind === "error" ? activeFetchState.message : null;

  const handleBackClick = (event: MouseEvent<HTMLAnchorElement>): void => {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0) {
      return;
    }
    event.preventDefault();
    navigate("/");
  };

  const submitToggle = async (endpoint: string, successParam: string): Promise<void> => {
    setSubmitError(null);
    const parsed = v.safeParse(TwoFactorCodeInputSchema, { code });
    if (!parsed.success) {
      setSubmitError(parsed.issues[0]?.message ?? "Please enter a valid 6-digit code.");
      return;
    }

    const qs = new URLSearchParams({ app_id: appId }).toString();
    setIsSubmitting(true);
    const res = await apiPost(`${endpoint}?${qs}`, parsed.output, SuccessMessageDataSchema);
    setIsSubmitting(false);

    if (!res.ok) {
      if (res.status === 401) {
        const returnUrl = `/2fa/setup?${qs}`;
        navigate(`/login?${buildAuthQuery(appId, returnUrl)}`, { replace: true });
        return;
      }
      setSubmitError(res.message);
      return;
    }

    navigate(`/?success=${successParam}`);
  };

  const handleEnableSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void submitToggle("/api/auth/2fa/enable", "2fa_enabled");
  };

  const handleDisableSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void submitToggle("/api/auth/2fa/disable", "2fa_disabled");
  };

  const formattedSecret =
    setupState && !setupState.enabled ? (setupState.secret.match(/.{1,4}/g)?.join(" ") ?? setupState.secret) : "";

  return (
    <AuthShell
      title={setupState?.enabled ? "Manage Two-Factor Auth" : "Set up Two-Factor Auth"}
      subtitle={
        setupState?.enabled
          ? "Two-factor authentication protects your account with a time-based code."
          : "Scan the QR code below with your authenticator app."
      }
    >
      {loadError ? <AuthAlert tone="danger">{loadError}</AuthAlert> : null}
      {submitError ? <AuthAlert tone="danger">{submitError}</AuthAlert> : null}

      {!loadError && !setupState ? (
        <div className="py-3">
          <Progress value={null} label="Preparing authenticator setup..." />
        </div>
      ) : null}

      {setupState && !setupState.enabled ? (
        <>
          <div className="flex flex-col items-center gap-4 rounded-panel border border-border-subtle bg-surface-sunken/70 p-panel-sm">
            <QrCode value={setupState.otpauthUrl} />

            <div className="w-full text-center">
              <p className="mb-1.5 font-sans text-xs text-text-secondary">Or enter this setup key manually:</p>
              <code className="block rounded-control border border-border-default bg-surface-100 px-3 py-2 font-mono text-xs font-ui tracking-widest text-text-primary tabular-nums select-all">
                {formattedSecret}
              </code>
            </div>
          </div>

          <form onSubmit={handleEnableSubmit} className="flex flex-col gap-4">
            <Field>
              <FieldLabel htmlFor="twofa-setup-code">Enter the 6-digit code from your app</FieldLabel>
              <Input
                id="twofa-setup-code"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]{6}"
                maxLength={6}
                placeholder="123456"
                value={code}
                onChange={(event) => {
                  setCode(event.target.value.replace(/[^0-9]/g, ""));
                }}
                className="text-center font-mono text-sm tracking-widest tabular-nums"
                required
              />
            </Field>

            <Button type="submit" variant={ButtonVariants.Primary} disabled={isSubmitting} className="w-full">
              {isSubmitting ? "Enabling..." : "Verify and Enable"}
            </Button>
          </form>
        </>
      ) : null}

      {setupState && setupState.enabled ? (
        <div className="flex flex-col gap-4">
          <div className="flex items-center justify-between rounded-control border border-border-subtle bg-surface-sunken/60 px-control-px-md py-2.5">
            <span className="font-sans text-xs text-text-secondary">Current status</span>
            <Badge variant={BadgeVariants.Success}>Enabled</Badge>
          </div>

          <form onSubmit={handleDisableSubmit} className="flex flex-col gap-4">
            <Field>
              <FieldLabel htmlFor="twofa-disable-code">Enter an authenticator code to disable 2FA</FieldLabel>
              <Input
                id="twofa-disable-code"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]{6}"
                maxLength={6}
                placeholder="123456"
                value={code}
                onChange={(event) => {
                  setCode(event.target.value.replace(/[^0-9]/g, ""));
                }}
                className="text-center font-mono text-sm tracking-widest tabular-nums"
                required
              />
            </Field>

            <Button type="submit" variant={ButtonVariants.Danger} disabled={isSubmitting} className="w-full">
              {isSubmitting ? "Disabling..." : "Disable 2FA"}
            </Button>
          </form>
        </div>
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
