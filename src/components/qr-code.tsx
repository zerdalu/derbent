import { encodeQrMatrix, type QrCodeMatrix } from "@/utils/qr-code";
import { cn } from "cn";
import type { ReactElement } from "react";

export interface QrCodeProps {
  readonly value: string;
  readonly label?: string;
  readonly className?: string;
}

function tryEncodeQrMatrix(value: string): QrCodeMatrix | null {
  try {
    return encodeQrMatrix(value);
  } catch {
    return null;
  }
}

export function QrCode({ value, label = "Two-factor authenticator QR code", className }: QrCodeProps): ReactElement {
  const matrix = tryEncodeQrMatrix(value);

  if (!matrix) {
    return (
      <output
        aria-label={label}
        className={cn(
          "inline-flex size-48 items-center justify-center rounded-panel border border-border-default bg-surface-100 p-4 text-center font-sans text-xs text-text-secondary shadow-control",
          className,
        )}
      >
        QR code unavailable for this account length. Use the manual setup key below.
      </output>
    );
  }

  const { size, modules } = matrix;
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
