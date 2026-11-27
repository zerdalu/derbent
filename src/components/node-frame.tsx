import {
  NodeFrameVariants,
  NodePortTones,
  type NodeFrameVariant,
  type NodePortSide,
  type NodePortTone,
} from "@/variants";
import { cn } from "cn";
import type { HTMLAttributes, ReactElement, ReactNode } from "react";

export type { NodeFrameVariant, NodePortSide, NodePortTone };

export interface NodePort {
  readonly side: NodePortSide;
  readonly tone: NodePortTone;
  readonly id?: string;
}

export interface NodeFrameProps extends HTMLAttributes<HTMLDivElement> {
  readonly variant?: NodeFrameVariant;
  readonly active?: boolean;
  readonly ports?: readonly NodePort[];
  readonly contentClassName?: string;
  readonly children: ReactNode;
}

const portPositionClasses: Record<NodePortSide, string> = {
  top: "top-0 left-1/2 -translate-x-1/2 -translate-y-1/2 h-0.5 w-6",
  bottom: "bottom-0 left-1/2 -translate-x-1/2 translate-y-1/2 h-0.5 w-6",
  left: "left-0 top-1/2 -translate-x-1/2 -translate-y-1/2 w-0.5 h-10",
  right: "right-0 top-1/2 translate-x-1/2 -translate-y-1/2 w-0.5 h-10",
};

const portHaloClasses: Record<NodePortSide, string> = {
  top: "top-0 left-1/2 -translate-x-1/2 -translate-y-1/2 h-3.5 w-14",
  bottom: "bottom-0 left-1/2 -translate-x-1/2 translate-y-1/2 h-3.5 w-14",
  left: "left-0 top-1/2 -translate-x-1/2 -translate-y-1/2 w-4 h-16",
  right: "right-0 top-1/2 translate-x-1/2 -translate-y-1/2 w-4 h-16",
};

interface CornerLightBar {
  readonly id: string;
  readonly barClassName: string;
  readonly haloClassName: string;
}

const CORNER_LIGHT_BARS: readonly CornerLightBar[] = [
  {
    id: "top-left",
    barClassName: "top-0 left-8 -translate-y-1/2 h-0.5 w-12",
    haloClassName: "top-0 left-6 -translate-y-1/2 h-3.5 w-16",
  },
  {
    id: "top-right",
    barClassName: "top-0 right-8 -translate-y-1/2 h-0.5 w-12",
    haloClassName: "top-0 right-6 -translate-y-1/2 h-3.5 w-16",
  },
  {
    id: "bottom-left",
    barClassName: "bottom-0 left-8 translate-y-1/2 h-0.5 w-12",
    haloClassName: "bottom-0 left-6 translate-y-1/2 h-3.5 w-16",
  },
  {
    id: "bottom-right",
    barClassName: "bottom-0 right-8 translate-y-1/2 h-0.5 w-12",
    haloClassName: "bottom-0 right-6 translate-y-1/2 h-3.5 w-16",
  },
];

export function NodeFrame({
  variant = NodeFrameVariants.Default,
  active = false,
  ports = [],
  className,
  contentClassName,
  children,
  ...props
}: NodeFrameProps): ReactElement {
  const isFeatured = variant === NodeFrameVariants.Featured;
  const isHighlighted = isFeatured || active;

  return (
    <div className={cn("relative flex flex-col", className)} {...props}>
      {isHighlighted ? (
        <span
          aria-hidden="true"
          className="pointer-events-none absolute -inset-5 -z-10 rounded-node-frame bg-node-glow opacity-60 blur-2xl"
        />
      ) : null}

      {/* Outer Stepped Obsidian Bezel */}
      <div
        className={cn(
          "relative flex flex-1 flex-col rounded-node-frame border bg-node-step-outer p-2.5 shadow-bezel-step transition-node duration-overlay ease-ui",
          isHighlighted ? "border-node-frame-active" : "border-node-frame",
        )}
      >
        {/* Inner Recessed Bevel Channel */}
        <div
          className={cn(
            "relative flex flex-1 flex-col rounded-node-inner border bg-node-step-inner p-2 transition-node duration-overlay ease-ui",
            isHighlighted ? "border-node-frame-active" : "border-node-frame",
          )}
        >
          {/* Symmetrical Photonic Light Bars */}
          {isHighlighted
            ? CORNER_LIGHT_BARS.map((bar) => (
                <span key={bar.id} aria-hidden="true" className="pointer-events-none">
                  <span
                    className={cn(
                      "absolute z-10 rounded-track bg-connector-active shadow-photonic-bar",
                      bar.barClassName,
                    )}
                  />
                  <span
                    className={cn(
                      "absolute z-0 rounded-track bg-connector-active opacity-50 blur-md",
                      bar.haloClassName,
                    )}
                  />
                </span>
              ))
            : null}

          {/* Apex Polar Tick Bars & Side Ports */}
          {ports.map((port, index) => {
            const isPortActive = port.tone === NodePortTones.Active;
            const key = port.id ?? `${port.side}-${index}`;
            return (
              <span key={key} aria-hidden="true" className="pointer-events-none">
                <span
                  className={cn(
                    "absolute z-10 rounded-track transition-node duration-overlay ease-ui",
                    portPositionClasses[port.side],
                    isPortActive ? "bg-connector-active shadow-photonic-bar" : "bg-connector-muted",
                  )}
                />
                <span
                  className={cn(
                    "absolute z-0 rounded-track blur-md transition-node duration-overlay ease-ui",
                    portHaloClasses[port.side],
                    isPortActive ? "bg-connector-active opacity-50" : "bg-connector-muted opacity-25",
                  )}
                />
              </span>
            );
          })}

          {/* Inner Vault Chamber */}
          <div
            className={cn(
              "relative flex-1 rounded-panel border backdrop-blur-floating transition-node duration-overlay ease-ui",
              isFeatured
                ? "border-node-featured-border bg-node-featured text-node-featured-text shadow-node-featured"
                : cn(
                    "bg-node-glass text-text-primary shadow-panel",
                    active ? "border-node-frame-active" : "border-node-border",
                  ),
              contentClassName,
            )}
          >
            {children}
          </div>
        </div>
      </div>
    </div>
  );
}
