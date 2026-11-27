import { Button as BaseButton } from "@base-ui/react/button";
import { ButtonSizes, type ButtonSize, ButtonVariants, type ButtonVariant, getButtonClasses } from "@ui/variants";
import type { ComponentProps, ReactElement } from "react";

export type { ButtonSize, ButtonVariant };

export interface ButtonProps extends ComponentProps<typeof BaseButton> {
  readonly variant?: ButtonVariant;
  readonly size?: ButtonSize;
}

export function Button({
  variant = ButtonVariants.Primary,
  size = ButtonSizes.Md,
  className,
  ...props
}: ButtonProps): ReactElement {
  const resolvedClassName: ComponentProps<typeof BaseButton>["className"] =
    typeof className === "function"
      ? (state) => getButtonClasses({ variant, size, className: className(state) })
      : getButtonClasses({ variant, size, className });

  return <BaseButton className={resolvedClassName} {...props} />;
}
