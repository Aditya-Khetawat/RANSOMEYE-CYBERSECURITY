"use client";

// Light-mode only — see ThemeScript.tsx (no-op) and ThemeControl's removal
// from UserInfo.tsx (no toggle exposed). Kept as a no-op component so
// app/(keep)/layout.tsx's <WatchUpdateTheme /> usage doesn't need touching.
export function WatchUpdateTheme() {
  return null;
}
