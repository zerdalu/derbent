import { GlobeIcon } from "@phosphor-icons/react";
import { sanitizeSvg } from "@shared/utils/svg";
import { cn } from "cn";
import { useId, type ReactElement } from "react";

function namespaceSvgIds(svg: string, prefix: string): string {
  const ids = new Set<string>();
  const idAttrRegex = /\bid\s*=\s*(?:"([^"]+)"|'([^']+)')/gi;
  let match: RegExpExecArray | null = idAttrRegex.exec(svg);

  while (match !== null) {
    const idValue = match[1] ?? match[2];
    if (idValue) {
      ids.add(idValue);
    }
    match = idAttrRegex.exec(svg);
  }

  if (ids.size === 0) {
    return svg;
  }

  const withRenamedIds = svg.replace(
    /\bid(\s*=\s*)(?:"([^"]+)"|'([^']+)')/gi,
    (fullMatch: string, equalsPart: string, doubleVal: string | undefined, singleVal: string | undefined): string => {
      const value = doubleVal ?? singleVal ?? "";
      if (!ids.has(value)) {
        return fullMatch;
      }
      const quote = doubleVal !== undefined ? '"' : "'";
      return `id${equalsPart}${quote}${prefix}${value}${quote}`;
    },
  );

  return withRenamedIds.replace(
    /url\(\s*(['"]?)#([a-zA-Z0-9_.-]+)\1\s*\)/gi,
    (fullMatch: string, quote: string, targetId: string): string => {
      if (!ids.has(targetId)) {
        return fullMatch;
      }
      return `url(${quote}#${prefix}${targetId}${quote})`;
    },
  );
}

export interface AppIconProps {
  readonly iconSvg: string | null;
  readonly className?: string;
}

export function AppIcon({ iconSvg, className }: AppIconProps): ReactElement {
  const instanceId = useId();
  const sanitized = sanitizeSvg(iconSvg);

  if (!sanitized) {
    return <GlobeIcon aria-hidden="true" className={cn("size-4.5 shrink-0", className)} />;
  }

  const safePrefix = `app-icon-${instanceId.replace(/[^a-zA-Z0-9_-]/g, "")}-`;
  const namespacedSvg = namespaceSvgIds(sanitized, safePrefix);

  return (
    <span
      aria-hidden="true"
      className={cn("inline-flex shrink-0 items-center justify-center [&>svg]:size-full", className)}
      dangerouslySetInnerHTML={{ __html: namespacedSvg }}
    />
  );
}
