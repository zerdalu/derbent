import { cn } from "cn";
import type { ReactElement } from "react";

const GRID_SIZE = 9;
const GRID_CENTER = 4;

type RingIndex = 0 | 1 | 2 | 3 | 4;

interface MatrixCell {
  readonly id: string;
  readonly ring: RingIndex | null;
}

function resolveRingIndex(row: number, col: number): RingIndex | null {
  const dr = Math.abs(row - GRID_CENTER);
  const dc = Math.abs(col - GRID_CENTER);

  // Omit the four sharp corner cells so the rotated 45deg lattice mirrors the rounded diamond contours
  if (dr === GRID_CENTER && dc === GRID_CENTER) {
    return null;
  }

  const distance = Math.max(dr, dc);
  switch (distance) {
    case 0:
      return 0;
    case 1:
      return 1;
    case 2:
      return 2;
    case 3:
      return 3;
    default:
      return 4;
  }
}

const MATRIX_CELLS: readonly MatrixCell[] = Array.from({ length: GRID_SIZE * GRID_SIZE }, (_, index) => {
  const row = Math.floor(index / GRID_SIZE);
  const col = index % GRID_SIZE;
  return {
    id: `${row}-${col}`,
    ring: resolveRingIndex(row, col),
  };
});

const RING_ANIMATION_CLASSES: Record<RingIndex, string> = {
  0: "motion-safe:animate-diamond-dot-0 motion-reduce:opacity-100",
  1: "motion-safe:animate-diamond-dot-1 motion-reduce:opacity-75",
  2: "motion-safe:animate-diamond-dot-2 motion-reduce:opacity-55",
  3: "motion-safe:animate-diamond-dot-3 motion-reduce:opacity-40",
  4: "motion-safe:animate-diamond-dot-4 motion-reduce:opacity-25",
};

export interface DiamondDotMatrixProps {
  readonly label?: string;
  readonly className?: string;
}

export function DiamondDotMatrix({ label = "Loading", className }: DiamondDotMatrixProps): ReactElement {
  return (
    <output aria-label={label} className={cn("relative inline-flex items-center justify-center", className)}>
      <span
        aria-hidden="true"
        className="pointer-events-none absolute size-36 rotate-45 rounded-vault-diamond bg-node-glow opacity-55 blur-2xl"
      />
      <div aria-hidden="true" className="grid rotate-45 grid-cols-9 gap-3">
        {MATRIX_CELLS.map((cell) =>
          cell.ring === null ? (
            <span key={cell.id} className="size-1.5" />
          ) : (
            <span
              key={cell.id}
              className={cn(
                "shadow-dot-glow size-1.5 rounded-track bg-connector-active will-change-transform",
                RING_ANIMATION_CLASSES[cell.ring],
              )}
            />
          ),
        )}
      </div>
    </output>
  );
}
