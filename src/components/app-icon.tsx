import { GlobeIcon } from "@phosphor-icons/react";
import { sanitizeSvg } from "@shared/utils/svg";
import { cn } from "cn";
import type { ReactElement } from "react";

export interface AppIconProps {
  readonly iconSvg: string | null;
  readonly className?: string;
}

export function AppIcon({ iconSvg, className }: AppIconProps): ReactElement {
  const sanitized = sanitizeSvg(iconSvg);

  if (!sanitized) {
    return <GlobeIcon aria-hidden="true" className={cn("size-4.5 shrink-0", className)} />;
  }

  return (
    <span
      aria-hidden="true"
      className={cn("inline-flex shrink-0 items-center justify-center [&>svg]:size-full", className)}
      dangerouslySetInnerHTML={{ __html: sanitized }}
    />
  );
}
