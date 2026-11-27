import derbentIconUrl from "@/assets/icon.svg";
import { NodeFrame, type NodePort } from "@/components/node-frame";
import { ThemeToggle } from "@/components/theme-toggle";
import { navigate } from "@/utils/router";
import { NodePortSides, NodePortTones } from "@/variants";
import { CheckCircleIcon, WarningCircleIcon } from "@phosphor-icons/react";
import { Separator } from "@ui/index";
import { cn } from "cn";
import type { CSSProperties, MouseEvent, ReactElement, ReactNode } from "react";

const DERBENT_ICON_MASK_STYLE: CSSProperties = {
  maskImage: `url("${derbentIconUrl}")`,
  maskPosition: "center",
  maskRepeat: "no-repeat",
  maskSize: "contain",
  WebkitMaskImage: `url("${derbentIconUrl}")`,
  WebkitMaskPosition: "center",
  WebkitMaskRepeat: "no-repeat",
  WebkitMaskSize: "contain",
};

const SHELL_PORTS: readonly NodePort[] = [
  { side: NodePortSides.Top, tone: NodePortTones.Active, id: "shell-top" },
  { side: NodePortSides.Bottom, tone: NodePortTones.Active, id: "shell-bottom" },
];

export interface AuthAlertProps {
  readonly tone: "success" | "danger" | "info";
  readonly children: ReactNode;
  readonly className?: string;
}

export function AuthAlert({ tone, children, className }: AuthAlertProps): ReactElement {
  const toneClasses =
    tone === "success"
      ? "border-status-success-border bg-status-success-bg text-status-success-text"
      : tone === "danger"
        ? "border-status-danger-border bg-status-danger-bg text-status-danger-text"
        : "border-status-info-border bg-status-info-bg text-status-info-text";

  return (
    <output
      className={cn(
        "flex items-start gap-2.5 rounded-control border px-control-px-md py-2.5 font-sans text-xs",
        toneClasses,
        className,
      )}
    >
      {tone === "danger" ? (
        <WarningCircleIcon aria-hidden="true" className="mt-0.5 size-4.5 shrink-0" />
      ) : (
        <CheckCircleIcon aria-hidden="true" className="mt-0.5 size-4.5 shrink-0" />
      )}
      <span className="min-w-0 flex-1 leading-relaxed">{children}</span>
    </output>
  );
}

export interface AuthShellProps {
  readonly appName?: string;
  readonly title: string;
  readonly subtitle?: ReactNode;
  readonly children: ReactNode;
}

export function AuthShell({ appName = "Derbent", title, subtitle, children }: AuthShellProps): ReactElement {
  const handleHomeClick = (event: MouseEvent<HTMLAnchorElement>): void => {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0) {
      return;
    }
    event.preventDefault();
    navigate("/");
  };

  return (
    <div className="relative flex min-h-dvh flex-col overflow-hidden text-text-primary">
      {/* Concentric Stepped Diamond Contours (Echoing Reference Vault Architecture) */}
      <div
        aria-hidden="true"
        className="pointer-events-none fixed inset-0 -z-10 flex items-center justify-center overflow-hidden"
      >
        <div className="size-vault-ring-lg rotate-45 rounded-vault-diamond border border-border-subtle opacity-35" />
        <div className="absolute size-vault-ring-md rotate-45 rounded-vault-diamond border border-border-subtle bg-node-step-outer/25 opacity-55 shadow-bezel-step" />
        <div className="absolute size-vault-ring-sm rotate-45 rounded-vault-diamond border border-border-default bg-node-step-inner/35 opacity-70" />
      </div>

      <header className="mx-auto flex w-full max-w-4xl items-center justify-between gap-3 px-6 pt-5 pb-3.5 vt-auth-header md:px-10 md:pt-6">
        <a
          href="/"
          onClick={handleHomeClick}
          className="group inline-flex min-h-hit min-w-hit items-center gap-2.5 rounded-badge border border-border-default bg-surface-sunken/90 px-3.5 py-1.5 shadow-recessed-capsule focus-ring transition-control duration-control ease-ui hover:border-border-strong"
        >
          <span
            aria-hidden="true"
            style={DERBENT_ICON_MASK_STYLE}
            className="inline-block size-5 shrink-0 bg-accent-primary"
          />
          <span className="h-3.5 w-px bg-border-default" />
          <span className="font-mono text-xs font-heading tracking-widest text-text-primary uppercase">{appName}</span>
        </a>

        <ThemeToggle />
      </header>

      <div className="mx-auto w-full max-w-4xl px-6 md:px-10">
        <Separator />
      </div>

      <main className="mx-auto flex w-full flex-1 flex-col items-center justify-center px-6 py-8 md:px-10">
        <div className="w-full max-w-md">
          <NodeFrame
            active
            ports={SHELL_PORTS}
            className="vt-auth-shell"
            contentClassName="flex flex-col gap-5 p-panel"
          >
            <div className="flex flex-col items-center gap-1.5 text-center">
              <h1 className="font-display text-lg font-heading tracking-heading text-text-primary">{title}</h1>
              {subtitle ? (
                <div className="font-sans text-xs leading-relaxed text-text-secondary">{subtitle}</div>
              ) : null}
            </div>

            <Separator />

            {children}
          </NodeFrame>

          <footer className="mt-6 flex items-center justify-center gap-2.5 font-mono text-xs tracking-widest text-text-muted uppercase vt-auth-footer">
            <span className="h-px w-6 bg-border-default" />
            <span>Security with care and ease</span>
            <span className="h-px w-6 bg-border-default" />
          </footer>
        </div>
      </main>
    </div>
  );
}
