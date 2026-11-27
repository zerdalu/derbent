import { AuthAlert, AuthShell } from "@/components/auth-shell";
import { apiPost } from "@/utils/api-client";
import { buildAuthQuery, navigate, useRouterLocation } from "@/utils/router";
import { CheckCircleIcon, EnvelopeSimpleIcon } from "@phosphor-icons/react";
import { SuccessMessageDataSchema } from "@shared/schemas/auth";
import { Button, ButtonVariants } from "@ui/index";
import { useEffect, useState, type ReactElement } from "react";

export function VerifyPendingPage(): ReactElement {
  const location = useRouterLocation();
  const params = new URLSearchParams(location.search);
  const appId = params.get("app_id")?.trim() || "sso";
  const redirect = params.get("redirect") || "/";
  const qs = buildAuthQuery(appId, redirect);

  return (
    <AuthShell title="Check your inbox" subtitle="We've sent a verification link to your email address.">
      <div className="flex flex-col items-center gap-4 text-center">
        <div className="inline-flex size-control-lg items-center justify-center rounded-control border border-border-default bg-surface-sunken text-accent-primary">
          <EnvelopeSimpleIcon aria-hidden="true" className="size-4.5" />
        </div>

        <p className="font-sans text-xs leading-relaxed text-text-secondary">
          Click the verification link in your inbox to activate your account. The link will expire in{" "}
          <span className="font-mono font-ui text-text-primary tabular-nums">15</span> minutes.
        </p>

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
      </div>
    </AuthShell>
  );
}

export function VerifyEmailPage(): ReactElement {
  const location = useRouterLocation();
  const params = new URLSearchParams(location.search);
  const appId = params.get("app_id")?.trim() || "sso";
  const redirect = params.get("redirect") || "/";
  const qs = buildAuthQuery(appId, redirect);

  const [capturedToken] = useState<string>(() => params.get("token")?.trim() || "");
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Scrub the one-time verification token from the browser URL bar and session history
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

  const handleVerify = async (): Promise<void> => {
    if (!capturedToken) {
      return;
    }

    setError(null);
    setIsSubmitting(true);
    const result = await apiPost("/api/auth/verify-email", { token: capturedToken }, SuccessMessageDataSchema);
    setIsSubmitting(false);

    if (!result.ok) {
      setError(result.message);
      return;
    }

    setSuccessMessage(result.data.message);
  };

  const isMissingToken = capturedToken.length === 0;
  const isVerified = successMessage !== null;

  return (
    <AuthShell title="Email verification" subtitle="Confirm to activate your email address.">
      {isMissingToken ? <AuthAlert tone="danger">No verification token was provided.</AuthAlert> : null}
      {successMessage ? <AuthAlert tone="success">{successMessage}</AuthAlert> : null}
      {error ? <AuthAlert tone="danger">{error}</AuthAlert> : null}

      {!isMissingToken && !isVerified ? (
        <Button
          type="button"
          variant={ButtonVariants.Primary}
          disabled={isSubmitting}
          className="w-full"
          onClick={() => {
            void handleVerify();
          }}
        >
          <CheckCircleIcon aria-hidden="true" className="size-4.5" />
          <span>{isSubmitting ? "Verifying..." : "Verify Email Address"}</span>
        </Button>
      ) : null}

      <Button
        type="button"
        variant={isVerified ? ButtonVariants.Primary : ButtonVariants.Secondary}
        className="w-full"
        onClick={() => {
          navigate(`/login?${qs}`);
        }}
      >
        Continue to sign in
      </Button>
    </AuthShell>
  );
}
