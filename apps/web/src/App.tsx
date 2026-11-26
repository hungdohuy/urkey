import { useEffect, useMemo, useState } from "react";
import { AppProvider, useApp } from "./app/context";
import { createWorkerClient, type CoreClient } from "./core/client";
import { LockScreen, Revoked, Welcome } from "./screens/Onboarding";
import { Toasts } from "./ui/kit";
import { Vault } from "./vault/Vault";

function Root() {
  const { state, fatal } = useApp();
  // Keep the onboarding flow on screen until the Emergency Kit is confirmed, even though the
  // vault is already unlocked (screens.md §3.2 step 4).
  const [kitHold, setKitHold] = useState(false);
  useEffect(() => {
    const on = () => setKitHold(true);
    const off = () => setKitHold(false);
    window.addEventListener("urkey:kit-start", on);
    window.addEventListener("urkey:kit-done", off);
    window.addEventListener("urkey:kit-cancel", off);
    return () => {
      window.removeEventListener("urkey:kit-start", on);
      window.removeEventListener("urkey:kit-done", off);
      window.removeEventListener("urkey:kit-cancel", off);
    };
  }, []);
  useEffect(() => {
    document.title = state.phase === "unlocked" ? "urkey" : "urkey — Locked";
  }, [state.phase]);

  if (state.phase === "welcome" || (kitHold && state.phase === "unlocked")) return <Welcome key="onboarding" />;
  if (state.phase === "locked") return <LockScreen />;
  if (state.phase === "revoked") return <Revoked />;
  if (state.phase === "unlocked") return <Vault />;
  if (fatal)
    return (
      <div role="alert" style={{ padding: "var(--space-8)" }}>
        urkey couldn&apos;t start in this browser. It needs WebAssembly, IndexedDB and WebCrypto (Ed25519).
      </div>
    );
  return <div role="status" style={{ padding: "var(--space-8)" }}>Loading…</div>;
}

let defaultClient: CoreClient | null = null;

/** Application root. `client` is injectable for tests; the app uses one core worker per page. */
export function App({ client }: { client?: CoreClient }) {
  const c = useMemo(() => client ?? (defaultClient ??= createWorkerClient()), [client]);
  return (
    <AppProvider client={c}>
      <Root />
      <Toasts />
    </AppProvider>
  );
}
