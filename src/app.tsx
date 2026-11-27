import { AuthAlert, AuthShell } from "@/components/auth-shell";
import { DashboardPage } from "@/pages/dashboard-page";
import { LoginPage } from "@/pages/login-page";
import { MagicLinkPage, VerifyMagicLinkPage } from "@/pages/magic-link-pages";
import { ChangePasswordPage, ForgotPasswordPage, ResetPasswordPage } from "@/pages/password-pages";
import { RegisterPage } from "@/pages/register-page";
import { TwoFactorSetupPage, TwoFactorVerifyPage } from "@/pages/two-factor-pages";
import { VerifyEmailPage, VerifyPendingPage } from "@/pages/verify-pages";
import { navigate, useRouterLocation } from "@/utils/router";
import { Button, ButtonVariants } from "@ui/index";
import type { ReactElement } from "react";

function normalizePathname(rawPathname: string): string {
  if (rawPathname === "/" || rawPathname.length === 0) {
    return "/";
  }
  return rawPathname.replace(/\/+$/, "") || "/";
}

export function App(): ReactElement {
  const location = useRouterLocation();
  const pathname = normalizePathname(location.pathname);

  switch (pathname) {
    case "/":
      return <DashboardPage />;
    case "/login":
      return <LoginPage key={location.search} />;
    case "/register":
      return <RegisterPage key={location.search} />;
    case "/verify-pending":
      return <VerifyPendingPage />;
    case "/verify-email":
      return <VerifyEmailPage />;
    case "/forgot-password":
      return <ForgotPasswordPage key={location.search} />;
    case "/reset-password":
      return <ResetPasswordPage key={location.search} />;
    case "/change-password":
      return <ChangePasswordPage key={location.search} />;
    case "/magic-link":
      return <MagicLinkPage key={location.search} />;
    case "/verify-magic-link":
      return <VerifyMagicLinkPage />;
    case "/2fa/verify":
      return <TwoFactorVerifyPage key={location.search} />;
    case "/2fa/setup":
      return <TwoFactorSetupPage key={location.search} />;
    default:
      return (
        <AuthShell title="Page not found" subtitle="The requested page could not be found.">
          <AuthAlert tone="danger">No route matches {pathname}.</AuthAlert>
          <Button
            type="button"
            variant={ButtonVariants.Secondary}
            className="w-full"
            onClick={() => {
              navigate("/");
            }}
          >
            Return to Dashboard
          </Button>
        </AuthShell>
      );
  }
}

export default App;
