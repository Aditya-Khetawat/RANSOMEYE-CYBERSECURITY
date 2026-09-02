// RansomEye is light-mode only (see ThemeControl.tsx removal + this file) —
// no script needed at all, since there's no pre-hydration dark class to
// avoid flashing. Kept as a no-op component rather than deleted so
// app/(keep)/layout.tsx's <ThemeScript /> usage doesn't need touching.
export const ThemeScript = () => null;
