import { AuthAlert, AuthShell } from "@/components/auth-shell";
import { apiPost, type ApiClientResult } from "@/utils/api-client";
import { buildAuthQuery, navigate, useRouterLocation } from "@/utils/router";
import { EnvelopeSimpleIcon } from "@phosphor-icons/react";
import { SuccessMessageDataSchema, type SuccessMessageData } from "@shared/schemas/auth";
import { Button, ButtonVariants, Progress } from "@ui/index";
import { useEffect, useState, type ReactElement } from "react";

const verificationRequests = new Map<string, Promise<ApiClientResult<SuccessMessageData>>>();

function verifyEmailOnce(token: string): Promise<ApiClientResult<SuccessMessageData>> {
  const existing = verificationRequests.get(token);
  if (existing) {
    return existing;
  }

  const request = apiPost("/api/auth/verify-email", { token }, SuccessMessageDataSchema).then((res) => {
    if (!res.ok && (res.status === 0 || res.status === 429 || res.status >= 500)) {
      verificationRequests.delete(token);
    }
    return res;
  });
  verificationRequests.set(token, request);
  return request;
}

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

interface VerificationOutcome {
  readonly token: string;
  readonly result: ApiClientResult<SuccessMessageData>;
}

export function VerifyEmailPage(): ReactElement {
  const location = useRouterLocation();
  const params = new URLSearchParams(location.search);
  const token = params.get("token")?.trim() || "";
  const appId = params.get("app_id")?.trim() || "sso";
  const redirect = params.get("redirect") || "/";
  const qs = buildAuthQuery(appId, redirect);

  const [outcome, setOutcome] = useState<VerificationOutcome | null>(null);

  useEffect(() => {
    if (!token) {
      return;
    }

    let cancelled = false;
    const run = async (): Promise<void> => {
      const result = await verifyEmailOnce(token);
      if (!cancelled) {
        setOutcome({ token, result });
      }
    };
    void run();

    return () => {
      cancelled = true;
    };
  }, [token]);

  const activeOutcome = outcome && outcome.token === token ? outcome.result : null;
  const isMissingToken = token.length === 0;
  const isVerifying = !isMissingToken && activeOutcome === null;

  return (
    <AuthShell title="Email verification" subtitle="Confirming your verification token.">
      {isMissingToken ? <AuthAlert tone="danger">No verification token was provided.</AuthAlert> : null}

      {isVerifying ? (
        <div className="flex flex-col gap-3 py-2">
          <Progress value={null} label="Verifying email address..." />
        </div>
      ) : null}

      {activeOutcome?.ok ? <AuthAlert tone="success">{activeOutcome.data.message}</AuthAlert> : null}

      {activeOutcome && !activeOutcome.ok ? <AuthAlert tone="danger">{activeOutcome.message}</AuthAlert> : null}

      <Button
        type="button"
        variant={activeOutcome?.ok ? ButtonVariants.Primary : ButtonVariants.Secondary}
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
