import { AuthAlert, AuthShell } from "@/components/auth-shell";
import { apiPost } from "@/utils/api-client";
import { buildAuthQuery, navigate, useRouterLocation } from "@/utils/router";
import { MagicWandIcon, SignInIcon } from "@phosphor-icons/react";
import { LoginResultDataSchema, MagicLinkRequestInputSchema, SuccessMessageDataSchema } from "@shared/schemas/auth";
import { Button, ButtonVariants, Field, FieldLabel, Input } from "@ui/index";
import { useEffect, useState, type FormEvent, type MouseEvent, type ReactElement } from "react";
import * as v from "valibot";

export function MagicLinkPage(): ReactElement {
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

  const submitRequest = async (): Promise<void> => {
    setError(null);
    const parsed = v.safeParse(MagicLinkRequestInputSchema, { email, appId, redirect });
    if (!parsed.success) {
      setError(parsed.issues[0]?.message ?? "Please enter a valid email address.");
      return;
    }

    setIsSubmitting(true);
    const res = await apiPost("/api/auth/magic-link/request", parsed.output, SuccessMessageDataSchema);
    setIsSubmitting(false);

    if (!res.ok) {
      setError(res.message);
      return;
    }

    setSuccessMessage(res.data.message);
  };

  const handleSubmit = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    void submitRequest();
  };

  if (successMessage) {
    return (
      <AuthShell title="Check your inbox" subtitle="A one-time sign-in link is on the way.">
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
    <AuthShell
      title="Magic link sign in"
      subtitle="Enter your email and we'll send you a secure link to sign in instantly."
    >
      {error ? <AuthAlert tone="danger">{error}</AuthAlert> : null}

      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <Field>
          <FieldLabel htmlFor="magic-email">Email address</FieldLabel>
          <Input
            id="magic-email"
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
          <MagicWandIcon aria-hidden="true" className="size-4.5" />
          <span>{isSubmitting ? "Sending..." : "Send Magic Link"}</span>
        </Button>
      </form>

      <p className="text-center font-sans text-xs text-text-secondary">
        <a
          href={`/login?${qs}`}
          onClick={handleBackClick}
          className="inline-flex min-h-hit items-center rounded-control px-1 font-ui text-text-primary focus-ring hover:underline"
        >
          Back to password sign in
        </a>
      </p>
    </AuthShell>
  );
}

export function VerifyMagicLinkPage(): ReactElement {
  const location = useRouterLocation();
  const params = new URLSearchParams(location.search);
  const appId = params.get("app_id")?.trim() || "sso";
  const redirect = params.get("redirect") || "/";
  const qs = buildAuthQuery(appId, redirect);

  const [capturedToken] = useState<string>(() => params.get("token")?.trim() || "");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Scrub the one-time token from the browser URL bar and session history
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

  const handleConfirm = async (): Promise<void> => {
    if (!capturedToken) {
      return;
    }

    setError(null);
    setIsSubmitting(true);
    const result = await apiPost(
      "/api/auth/magic-link/verify",
      { token: capturedToken, appId, redirect },
      LoginResultDataSchema,
    );
    setIsSubmitting(false);

    if (!result.ok) {
      setError(result.message);
      return;
    }

    switch (result.data.status) {
      case "authenticated":
        navigate(result.data.redirect, { replace: true });
        return;
      case "requires_2fa": {
        const verifyQs = new URLSearchParams({
          token: result.data.twoFactorToken,
          app_id: result.data.appId,
          redirect: result.data.redirect,
        }).toString();
        navigate(`/2fa/verify?${verifyQs}`, { replace: true });
        return;
      }
      case "verification_required":
        navigate(`/verify-pending?${buildAuthQuery(result.data.appId, result.data.redirect)}`, {
          replace: true,
        });
        return;
      default: {
        const _exhaustive: never = result.data;
        throw new Error(`Unhandled magic link status: ${JSON.stringify(_exhaustive)}`);
      }
    }
  };

  const isMissingToken = capturedToken.length === 0;

  return (
    <AuthShell title="Magic link sign in" subtitle="Confirm to complete your one-time sign-in.">
      {isMissingToken ? <AuthAlert tone="danger">No magic link token was provided.</AuthAlert> : null}
      {error ? <AuthAlert tone="danger">{error}</AuthAlert> : null}

      {!isMissingToken ? (
        <Button
          type="button"
          variant={ButtonVariants.Primary}
          disabled={isSubmitting}
          className="w-full"
          onClick={() => {
            void handleConfirm();
          }}
        >
          <SignInIcon aria-hidden="true" className="size-4.5" />
          <span>{isSubmitting ? "Signing in..." : "Continue to sign in"}</span>
        </Button>
      ) : null}

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
