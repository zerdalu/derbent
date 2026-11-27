import { AuthAlert, AuthShell } from "@/components/auth-shell";
import { apiPost, type ApiClientResult } from "@/utils/api-client";
import { buildAuthQuery, navigate, useRouterLocation } from "@/utils/router";
import { MagicWandIcon } from "@phosphor-icons/react";
import {
  LoginResultDataSchema,
  MagicLinkRequestInputSchema,
  SuccessMessageDataSchema,
  type LoginResultData,
} from "@shared/schemas/auth";
import { Button, ButtonVariants, Field, FieldLabel, Input, Progress } from "@ui/index";
import { useEffect, useState, type FormEvent, type MouseEvent, type ReactElement } from "react";
import * as v from "valibot";

const MAGIC_LINK_DEDUP_TTL_MS = 5000;
const magicLinkRequests = new Map<string, Promise<ApiClientResult<LoginResultData>>>();

function verifyMagicLinkOnce(
  token: string,
  appId: string,
  redirect: string,
): Promise<ApiClientResult<LoginResultData>> {
  const cacheKey = `${token}:${appId}:${redirect}`;
  const existing = magicLinkRequests.get(cacheKey);
  if (existing) {
    return existing;
  }

  const request = apiPost("/api/auth/magic-link/verify", { token, appId, redirect }, LoginResultDataSchema).then(
    (res) => {
      if (!res.ok && (res.status === 0 || res.status === 429 || res.status >= 500)) {
        magicLinkRequests.delete(cacheKey);
      } else {
        window.setTimeout(() => {
          if (magicLinkRequests.get(cacheKey) === request) {
            magicLinkRequests.delete(cacheKey);
          }
        }, MAGIC_LINK_DEDUP_TTL_MS);
      }
      return res;
    },
  );
  magicLinkRequests.set(cacheKey, request);
  return request;
}

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

interface MagicLinkOutcome {
  readonly token: string;
  readonly result: ApiClientResult<LoginResultData>;
}

export function VerifyMagicLinkPage(): ReactElement {
  const location = useRouterLocation();
  const params = new URLSearchParams(location.search);
  const token = params.get("token")?.trim() || "";
  const appId = params.get("app_id")?.trim() || "sso";
  const redirect = params.get("redirect") || "/";
  const qs = buildAuthQuery(appId, redirect);

  const [outcome, setOutcome] = useState<MagicLinkOutcome | null>(null);

  useEffect(() => {
    if (!token) {
      return;
    }

    let cancelled = false;
    const run = async (): Promise<void> => {
      const result = await verifyMagicLinkOnce(token, appId, redirect);
      if (cancelled) {
        return;
      }

      if (result.ok) {
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
      }

      setOutcome({ token, result });
    };
    void run();

    return () => {
      cancelled = true;
    };
  }, [token, appId, redirect]);

  const activeOutcome = outcome && outcome.token === token ? outcome.result : null;
  const isMissingToken = token.length === 0;
  const isPending = !isMissingToken && activeOutcome === null;

  return (
    <AuthShell title="Magic link sign in" subtitle="Validating your one-time sign-in link.">
      {isMissingToken ? <AuthAlert tone="danger">No magic link token was provided.</AuthAlert> : null}

      {isPending ? (
        <div className="py-2">
          <Progress value={null} label="Signing you in..." />
        </div>
      ) : null}

      {activeOutcome && !activeOutcome.ok ? <AuthAlert tone="danger">{activeOutcome.message}</AuthAlert> : null}

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
