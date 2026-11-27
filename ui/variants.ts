import { cn } from "cn";

export const ButtonVariants = {
  Primary: "primary",
  Secondary: "secondary",
  Outline: "outline",
  Ghost: "ghost",
  Danger: "danger",
} as const;

export type ButtonVariant = (typeof ButtonVariants)[keyof typeof ButtonVariants];

export const ButtonSizes = {
  Xs: "xs",
  Sm: "sm",
  Md: "md",
  Lg: "lg",
  IconXs: "icon-xs",
  IconSm: "icon-sm",
  IconMd: "icon-md",
  IconLg: "icon-lg",
} as const;

export type ButtonSize = (typeof ButtonSizes)[keyof typeof ButtonSizes];

export const InputSizes = {
  Xs: "xs",
  Sm: "sm",
  Md: "md",
  Lg: "lg",
} as const;

export type InputSize = (typeof InputSizes)[keyof typeof InputSizes];

export const BadgeVariants = {
  Default: "default",
  Accent: "accent",
  Success: "success",
  Warning: "warning",
  Danger: "danger",
  Info: "info",
  Outline: "outline",
} as const;

export type BadgeVariant = (typeof BadgeVariants)[keyof typeof BadgeVariants];

export const StatusVariants = {
  Default: "default",
  Success: "success",
  Warning: "warning",
  Danger: "danger",
  Info: "info",
} as const;

export type StatusVariant = (typeof StatusVariants)[keyof typeof StatusVariants];

const buttonVariantClasses: Record<ButtonVariant, string> = {
  primary:
    "bg-accent-primary text-text-on-accent border-transparent shadow-control hover:bg-accent-primary-hover active:bg-accent-primary-active",
  secondary:
    "bg-surface-300 text-text-primary border-border-default shadow-control hover:bg-surface-hover hover:border-border-strong active:bg-surface-active",
  outline:
    "bg-transparent text-text-primary border-border-default hover:bg-surface-hover hover:border-border-strong active:bg-surface-active",
  ghost:
    "bg-transparent text-text-secondary border-transparent hover:bg-surface-hover hover:text-text-primary active:bg-surface-active",
  danger:
    "bg-status-danger-bg text-status-danger-text border-status-danger-border shadow-control hover:bg-status-danger hover:text-text-on-accent hover:border-transparent active:bg-status-danger-active active:text-text-on-accent active:border-transparent",
};

const buttonSizeClasses: Record<ButtonSize, string> = {
  xs: "h-control-xs px-control-px-xs text-xs gap-1.5",
  sm: "h-control-sm px-control-px-sm text-xs gap-1.5",
  md: "h-control-md px-control-px-md text-xs gap-2",
  lg: "h-control-lg px-control-px-lg text-sm gap-2.5",
  "icon-xs": "size-control-xs p-0",
  "icon-sm": "size-control-sm p-0",
  "icon-md": "size-control-md p-0",
  "icon-lg": "size-control-lg p-0",
};

export interface ButtonClassOptions {
  readonly variant?: ButtonVariant;
  readonly size?: ButtonSize;
  readonly className?: string;
}

export function getButtonClasses({
  variant = ButtonVariants.Primary,
  size = ButtonSizes.Md,
  className,
}: ButtonClassOptions = {}): string {
  return cn(
    "inline-flex shrink-0 cursor-pointer items-center justify-center border font-mono font-ui tracking-ui whitespace-nowrap select-none",
    "min-h-hit min-w-hit rounded-control transition-control duration-control ease-ui",
    "active:scale-press",
    "focus-ring",
    "disabled:pointer-events-none disabled:opacity-disabled data-disabled:pointer-events-none data-disabled:opacity-disabled",
    buttonVariantClasses[variant],
    buttonSizeClasses[size],
    className,
  );
}
