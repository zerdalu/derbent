import { AppIcon } from "@/components/app-icon";
import { AuthAlert, AuthShell } from "@/components/auth-shell";
import { apiGet, apiPost } from "@/utils/api-client";
import { navigate, useRouterLocation } from "@/utils/router";
import {
  ArrowUpRightIcon,
  DotsThreeIcon,
  KeyIcon,
  ShieldCheckIcon,
  SignInIcon,
  SignOutIcon,
} from "@phosphor-icons/react";
import {
  DashboardDataSchema,
  RedirectResultDataSchema,
  type DashboardAppStatus,
  type DashboardData,
} from "@shared/schemas/auth";
import {
  Badge,
  BadgeVariants,
  Button,
  ButtonSizes,
  ButtonVariants,
  Menu,
  MenuContent,
  MenuItem,
  MenuSeparator,
  MenuTrigger,
  Progress,
  Separator,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@ui/index";
import { cn } from "cn";
import { useEffect, useState, type ReactElement } from "react";

function resolveSuccessMessage(successParam: string | null): string | null {
  switch (successParam) {
    case "2fa_enabled":
      return "Two-Factor Authentication was successfully enabled.";
    case "2fa_disabled":
      return "Two-Factor Authentication was successfully disabled.";
    default:
      return successParam;
  }
}

interface AppRowProps {
  readonly app: DashboardAppStatus;
  readonly isLoggedInAsSso: boolean;
  readonly isThisRowSso: boolean;
  readonly isBusy: boolean;
  readonly onLogout: (appId: string) => void;
  readonly onLogoutAllDevices: (appId: string) => void;
}

function AppRow({
  app,
  isLoggedInAsSso,
  isThisRowSso,
  isBusy,
  onLogout,
  onLogoutAllDevices,
}: AppRowProps): ReactElement {
  const isLoggedIn = app.session !== null;
  const hasPassword = app.session?.hasPassword !== false;
  const showAccountMenu = (isThisRowSso && isLoggedInAsSso) || (!isThisRowSso && !isLoggedInAsSso && isLoggedIn);
  const showQuickOpen = !isThisRowSso && isLoggedIn;

  return (
    <div
      className={cn(
        "flex items-center justify-between gap-3 py-3.5 transition-opacity duration-control ease-ui",
        isLoggedIn ? "opacity-100" : "opacity-85",
      )}
    >
      <div className="flex min-w-0 items-center gap-3.5">
        <div
          className={cn(
            "relative flex size-11 shrink-0 items-center justify-center rounded-control border transition-control duration-control ease-ui",
            isLoggedIn
              ? "border-accent-border bg-surface-sunken text-text-primary shadow-recessed-capsule"
              : "border-border-default bg-surface-sunken/60 text-text-secondary",
          )}
        >
          <AppIcon iconSvg={app.config.icon} className="size-5" />
          {isLoggedIn ? (
            <span
              aria-hidden="true"
              className="absolute -top-1 -right-1 size-2 rounded-track bg-connector-active shadow-photonic-bar"
            />
          ) : null}
        </div>

        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="truncate font-display text-sm font-heading tracking-heading text-text-primary">
              {app.config.name}
            </span>
            {isThisRowSso ? <Badge variant={BadgeVariants.Accent}>SSO</Badge> : null}
          </div>
          <p className="truncate font-sans text-xs text-text-secondary">
            {app.session ? app.session.email : app.config.description || "Sign in to access application"}
          </p>
        </div>
      </div>

      <div className="flex shrink-0 items-center gap-2">
        {showAccountMenu ? (
          <Menu>
            <MenuTrigger
              render={
                <Button
                  type="button"
                  variant={ButtonVariants.Secondary}
                  size={ButtonSizes.IconMd}
                  aria-label={`Account actions for ${app.config.name}`}
                  disabled={isBusy}
                />
              }
            >
              <DotsThreeIcon weight="bold" aria-hidden="true" className="size-4.5" />
            </MenuTrigger>
            <MenuContent align="end">
              {hasPassword ? (
                <MenuItem
                  onClick={() => {
                    navigate(`/change-password?app_id=${app.config.id}`);
                  }}
                >
                  <span className="flex items-center gap-2">
                    <KeyIcon aria-hidden="true" className="size-4.5 text-text-muted" />
                    <span>Change Password</span>
                  </span>
                </MenuItem>
              ) : null}
              <MenuItem
                onClick={() => {
                  navigate(`/2fa/setup?app_id=${app.config.id}`);
                }}
              >
                <span className="flex items-center gap-2">
                  <ShieldCheckIcon aria-hidden="true" className="size-4.5 text-text-muted" />
                  <span>2FA Settings</span>
                </span>
              </MenuItem>
              {!isThisRowSso ? (
                <MenuItem
                  onClick={() => {
                    window.open(app.config.url, "_blank", "noopener,noreferrer");
                  }}
                >
                  <span className="flex items-center gap-2">
                    <ArrowUpRightIcon aria-hidden="true" className="size-4.5 text-text-muted" />
                    <span>Open App</span>
                  </span>
                </MenuItem>
              ) : null}
              <MenuSeparator />
              <MenuItem
                onClick={() => {
                  onLogoutAllDevices(app.config.id);
                }}
              >
                <span className="flex items-center gap-2">
                  <SignOutIcon aria-hidden="true" className="size-4.5 text-text-muted" />
                  <span>Sign Out All Devices</span>
                </span>
              </MenuItem>
              <MenuItem
                danger
                onClick={() => {
                  onLogout(app.config.id);
                }}
              >
                <span className="flex items-center gap-2">
                  <SignOutIcon aria-hidden="true" className="size-4.5" />
                  <span>Sign Out</span>
                </span>
              </MenuItem>
            </MenuContent>
          </Menu>
        ) : null}

        {showQuickOpen ? (
          <Tooltip>
            <TooltipTrigger
              render={
                <a
                  href={app.config.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  aria-label={`Open ${app.config.name}`}
                  className="inline-flex size-control-md min-h-hit min-w-hit items-center justify-center rounded-control border border-border-default bg-surface-300 text-text-primary shadow-control focus-ring transition-control duration-control ease-ui hover:border-border-strong hover:bg-surface-hover active:scale-press active:bg-surface-active"
                />
              }
            >
              <ArrowUpRightIcon aria-hidden="true" className="size-4.5" />
            </TooltipTrigger>
            <TooltipContent>Open {app.config.name}</TooltipContent>
          </Tooltip>
        ) : null}

        {!isLoggedIn ? (
          <Button
            type="button"
            variant={ButtonVariants.Primary}
            size={ButtonSizes.Sm}
            disabled={!app.config.allowLogins}
            onClick={() => {
              navigate(`/login?app_id=${app.config.id}&redirect=/`);
            }}
          >
            <SignInIcon aria-hidden="true" className="size-4.5" />
            <span>Sign In</span>
          </Button>
        ) : null}
      </div>
    </div>
  );
}

export function DashboardPage(): ReactElement {
  const location = useRouterLocation();
  const params = new URLSearchParams(location.search);
  const successMessage = resolveSuccessMessage(params.get("success"));

  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isActionBusy, setIsActionBusy] = useState(false);

  const fetchDashboard = async (): Promise<void> => {
    const res = await apiGet("/api/auth/dashboard", DashboardDataSchema);
    setIsLoading(false);
    if (!res.ok) {
      setError(res.message);
      return;
    }
    setError(null);
    setDashboard(res.data);
  };

  useEffect(() => {
    let cancelled = false;
    const load = async (): Promise<void> => {
      const res = await apiGet("/api/auth/dashboard", DashboardDataSchema);
      if (cancelled) {
        return;
      }
      setIsLoading(false);
      if (!res.ok) {
        setError(res.message);
        return;
      }
      setError(null);
      setDashboard(res.data);
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  const handleLogout = async (endpoint: string, appId: string): Promise<void> => {
    setIsActionBusy(true);
    setError(null);
    const res = await apiPost(endpoint, { appId, redirect: "/" }, RedirectResultDataSchema);
    if (!res.ok) {
      setIsActionBusy(false);
      setError(res.message);
      return;
    }
    await fetchDashboard();
    setIsActionBusy(false);
  };

  const ssoApp = dashboard?.apps.find((entry) => entry.config.id === "sso") ?? null;
  const regularApps = dashboard?.apps.filter((entry) => entry.config.id !== "sso") ?? [];
  const isLoggedInAsSso = Boolean(ssoApp?.session);

  return (
    <AuthShell
      appName={dashboard?.appName}
      title="Identity & Access"
      subtitle="Manage your identity and access across connected applications."
    >
      {successMessage ? <AuthAlert tone="success">{successMessage}</AuthAlert> : null}
      {error ? <AuthAlert tone="danger">{error}</AuthAlert> : null}

      {isLoading ? (
        <div className="py-3">
          <Progress value={null} label="Loading session status..." />
        </div>
      ) : null}

      {!isLoading && dashboard ? (
        <div className="flex flex-col divide-y divide-border-subtle">
          {ssoApp ? (
            <AppRow
              app={ssoApp}
              isLoggedInAsSso={isLoggedInAsSso}
              isThisRowSso
              isBusy={isActionBusy}
              onLogout={(id) => {
                void handleLogout("/api/auth/logout", id);
              }}
              onLogoutAllDevices={(id) => {
                void handleLogout("/api/auth/logout-all", id);
              }}
            />
          ) : null}

          {regularApps.map((app) => (
            <AppRow
              key={app.config.id}
              app={app}
              isLoggedInAsSso={isLoggedInAsSso}
              isThisRowSso={false}
              isBusy={isActionBusy}
              onLogout={(id) => {
                void handleLogout("/api/auth/logout", id);
              }}
              onLogoutAllDevices={(id) => {
                void handleLogout("/api/auth/logout-all", id);
              }}
            />
          ))}
        </div>
      ) : null}

      {!isLoading && dashboard?.hasAnySession ? (
        <>
          <Separator />
          <div className="flex items-center justify-end">
            <Button
              type="button"
              variant={ButtonVariants.Ghost}
              size={ButtonSizes.Xs}
              disabled={isActionBusy}
              onClick={() => {
                void handleLogout("/api/auth/logout-all-email", "sso");
              }}
            >
              <SignOutIcon aria-hidden="true" className="size-4.5" />
              <span>Sign out of all accounts</span>
            </Button>
          </div>
        </>
      ) : null}
    </AuthShell>
  );
}
