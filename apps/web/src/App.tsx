import { AppShell } from "./ui/AppShell";

/**
 * Application root. P0 renders the empty three-pane shell only; vault screens
 * arrive in roadmap P2 (docs/ux/screens.md).
 */
export function App() {
  return <AppShell />;
}
