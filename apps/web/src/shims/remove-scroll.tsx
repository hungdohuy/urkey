/**
 * CSP-safe stand-in for `react-remove-scroll`, aliased in `vite.config.ts` (R-SEC-10).
 *
 * Radix modal dialogs and menus lock page scrolling with `react-remove-scroll`, which injects a
 * runtime `<style>` element. Our CSP (`style-src 'self'`, no `unsafe-inline`, no nonce) blocks
 * that, so this shim locks scrolling through the CSSOM (`element.style`), which CSP permits.
 * It accepts the props Radix passes (`as`, `shards`, `allowPinchZoom`, ...) and renders `as`
 * (Radix's Slot) with the children; outside-pointer blocking and focus trapping stay in Radix.
 */
import { forwardRef, useEffect, type ElementType, type ReactNode, type RefObject } from "react";

interface RemoveScrollProps {
  as?: ElementType;
  children?: ReactNode;
  enabled?: boolean;
  shards?: (RefObject<unknown> | HTMLElement)[];
  allowPinchZoom?: boolean;
  removeScrollBar?: boolean;
  inert?: boolean;
  noIsolation?: boolean;
  forwardProps?: boolean;
  noRelative?: boolean;
  gapMode?: string;
  sideCar?: unknown;
  className?: string;
}

let locks = 0;
let saved = "";

function lock(): () => void {
  if (locks++ === 0) {
    saved = document.body.style.overflow;
    document.body.style.overflow = "hidden";
  }
  return () => {
    if (--locks === 0) document.body.style.overflow = saved;
  };
}

export const RemoveScroll = forwardRef<unknown, RemoveScrollProps>(function RemoveScroll(props, ref) {
  // Only `className` is forwarded; the scroll-lock tuning props have no meaning for this shim.
  const { as: As = "div", children, enabled = true, className } = props;
  useEffect(() => (enabled ? lock() : undefined), [enabled]);
  return (
    <As ref={ref} className={className}>
      {children}
    </As>
  );
});

export default RemoveScroll;
