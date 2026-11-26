/** App-wide state: the core client, worker state, sync status, item list, toasts, settings. */
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { CoreError, type CoreClient } from "../core/client";
import type { AppState, ItemSummary, Method, Methods, Settings, SyncStatus } from "../core/protocol";

export interface Toast {
  id: number;
  text: string;
  tone: "info" | "ok" | "error";
  action?: { label: string; run: () => void };
}

interface Ctx {
  call: <M extends Method>(method: M, params: Methods[M]["params"]) => Promise<Methods[M]["result"]>;
  state: AppState;
  sync: SyncStatus | null;
  items: ItemSummary[];
  refreshItems: () => Promise<void>;
  toast: (text: string, tone?: Toast["tone"], action?: Toast["action"]) => void;
  toasts: Toast[];
  dismiss: (id: number) => void;
  settings: Settings;
  saveSettings: (s: Settings) => Promise<void>;
  /** The core worker failed to start. */
  fatal: boolean;
}

const AppCtx = createContext<Ctx | null>(null);

export function useApp(): Ctx {
  const c = useContext(AppCtx);
  if (c === null) throw new Error("useApp outside provider");
  return c;
}

/** User-facing text for error codes from the core (never echoes data). */
export function errorText(e: unknown): string {
  const code = e instanceof CoreError ? e.code : "error";
  const map: Record<string, string> = {
    decrypt: "Couldn't unlock. Check your master password and try again.",
    network: "Can't reach the server. Check your connection and try again.",
    unauthorized: "The server refused the sign-in. Check your email, Secret Key and master password.",
    email_taken: "An account with this email already exists.",
    rate_limited: "Too many attempts. Wait a minute and try again.",
    device_revoked: "This device was removed from your account.",
    update_required: "This version of urkey is too old. Reload to update.",
    secret_key_missing: "This device no longer has your Secret Key. Sign in again.",
    vault_changed: "Your vault changed while preparing this. Try again.",
    read_only: "This item was made by a newer version of urkey and can't be edited here.",
    locked: "Your vault is locked.",
  };
  if (code.startsWith("invalid: ")) return code.slice(9).replace(/^./, (c) => c.toUpperCase()) + ".";
  return map[code] ?? "Something went wrong. Try again.";
}

const DEFAULT_SETTINGS: Settings = { autoLockMinutes: 10, theme: "system" };

export function AppProvider({ client, children }: { client: CoreClient; children: ReactNode }) {
  const [state, setState] = useState<AppState>({ phase: "loading", email: null, deviceName: null, apiOrigin: "", lockReason: null });
  const [sync, setSync] = useState<SyncStatus | null>(null);
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const [fatal, setFatal] = useState(false);
  const toastId = useRef(1);
  const phaseRef = useRef(state.phase);
  useEffect(() => {
    phaseRef.current = state.phase;
  }, [state.phase]);

  const refreshItems = useCallback(async () => {
    if (phaseRef.current !== "unlocked") return;
    try {
      setItems(await client.call("listItems", undefined));
    } catch {
      /* locked meanwhile */
    }
  }, [client]);

  useEffect(() => {
    const off = client.subscribe((n) => {
      if (n.notice === "state") {
        phaseRef.current = n.state.phase;
        setState(n.state);
        if (n.state.phase !== "unlocked") setItems([]);
        else void refreshItems();
      } else if (n.notice === "sync") setSync(n.status);
      else void refreshItems();
    });
    void client.call("init", undefined).then(async (s) => {
      phaseRef.current = s.phase;
      setState(s);
      setSettings(await client.call("getSettings", undefined));
      if (s.phase === "unlocked") await refreshItems();
    }).catch(() => {
      setFatal(true);
    });
    return off;
  }, [client, refreshItems]);

  useEffect(() => {
    const root = document.documentElement;
    if (settings.theme === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", settings.theme);
  }, [settings.theme]);

  const toast = useCallback((text: string, tone: Toast["tone"] = "info", action?: Toast["action"]) => {
    const id = toastId.current++;
    setToasts((t) => [...t, { id, text, tone, ...(action === undefined ? {} : { action }) }]);
    setTimeout(() => {
      setToasts((t) => t.filter((x) => x.id !== id));
    }, action === undefined ? 3500 : 10000);
  }, []);

  const value = useMemo<Ctx>(
    () => ({
      call: (m, p) => client.call(m, p),
      state,
      sync,
      items,
      refreshItems,
      toast,
      toasts,
      dismiss: (id) => {
        setToasts((t) => t.filter((x) => x.id !== id));
      },
      settings,
      fatal,
      saveSettings: async (s) => {
        await client.call("setSettings", s);
        setSettings(s);
      },
    }),
    [client, state, sync, items, refreshItems, toast, toasts, settings, fatal],
  );
  return <AppCtx.Provider value={value}>{children}</AppCtx.Provider>;
}
