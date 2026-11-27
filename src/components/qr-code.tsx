import { encodeQrMatrix } from "@/utils/qr-code";
import { cn } from "cn";
import type { ReactElement } from "react";

export interface QrCodeProps {
  readonly value: string;
  readonly label?: string;
  readonly className?: string;
}

export function QrCode({ value, label = "Two-factor authenticator QR code", className }: QrCodeProps): ReactElement {
  const { size, modules } = encodeQrMatrix(value);
  const quietZone = 2;
  const viewBoxSize = size + quietZone * 2;

  const pathParts: string[] = [];
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (modules[r]?.[c]) {
        pathParts.push(`M${c + quietZone},${r + quietZone}h1v1h-1z`);
      }
    }
  }

  return (
    <div
      className={cn(
        "inline-flex items-center justify-center rounded-panel border border-border-default bg-white p-2 shadow-control",
        className,
      )}
    >
      <svg
        role="img"
        aria-label={label}
        viewBox={`0 0 ${viewBoxSize} ${viewBoxSize}`}
        shapeRendering="crispEdges"
        className="size-44"
      >
        <rect width={viewBoxSize} height={viewBoxSize} fill="#ffffff" />
        <path d={pathParts.join("")} fill="#18181b" />
      </svg>
    </div>
  );
}
