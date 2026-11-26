/** In-memory CoreClient for component tests (no WASM, no network). Values are test-only. */
import { CoreError, type CoreClient } from "./core/client";
import type { AppState, ItemBody, ItemSummary, Methods, Notice } from "./core/protocol";

export function fakeClient(initial: Partial<AppState> = {}): CoreClient & { items: Map<string, ItemBody> } {
  let state: AppState = { phase: "welcome", email: null, deviceName: null, apiOrigin: "http://api.test", lockReason: null, ...initial };
  const listeners = new Set<(n: Notice) => void>();
  const items = new Map<string, ItemBody>();
  let n = 0;
  const emit = (x: Notice) => listeners.forEach((l) => l(x));
  const set = (p: Partial<AppState>) => {
    state = { ...state, ...p };
    emit({ notice: "state", state });
    return state;
  };
  const summary = (id: string, b: ItemBody): ItemSummary => ({
    id,
    type: b.type,
    title: b.title,
    subtitle: typeof b.fields["username"] === "string" ? b.fields["username"] : "",
    favorite: b.favorite === true,
    tags: b.tags ?? [],
    pending: false,
    conflict: false,
    editable: true,
    has_totp: false,
    host: "",
    updated_at: "2026-11-26T10:00:00Z",
  });
  const handlers: Partial<{ [M in keyof Methods]: (p: Methods[M]["params"]) => Methods[M]["result"] }> = {
    init: () => state,
    getSettings: () => ({ autoLockMinutes: 10, theme: "system" }),
    createAccount: ({ email }) => {
      set({ phase: "unlocked", email });
      return { secretKeyText: "UK1-AAAAAA-BBBBB-CCCCC-DDDDD-EEEEEZ", recoveryKeyText: "UKR1-AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH-JJJJ-KKKK-MMMM-NNNN-PQRS7" };
    },
    unlock: ({ password }) => {
      if (password !== "correct horse") throw new CoreError("decrypt");
      return set({ phase: "unlocked" });
    },
    lock: ({ reason }) => set({ phase: "locked", lockReason: reason }),
    listItems: () => [...items].map(([id, b]) => summary(id, b)),
    getItem: ({ id }) => {
      const b = items.get(id);
      if (b === undefined) throw new CoreError("invalid: unknown item");
      return { ...b, id, editable: true, fields: { ...b.fields, password: null, has_password: typeof b.fields["password"] === "string" && b.fields["password"] !== "" } };
    },
    getItemForEdit: ({ id }) => items.get(id) as ItemBody,
    reveal: ({ id, field }) => {
      const v = items.get(id)?.fields[field];
      return typeof v === "string" ? v : "";
    },
    saveItem: ({ id, item }) => {
      const key = id ?? `item${String(++n)}`;
      items.set(key, item);
      emit({ notice: "items_changed" });
      return key;
    },
    status: () => ({ pending: 0, conflicts: 0, quarantined: 0, failed: 0, rollback: false, unread_events: 0, state: "synced", lastSyncAt: null }),
    sync: () => ({ pending: 0, conflicts: 0, quarantined: 0, failed: 0, rollback: false, unread_events: 0, state: "synced", lastSyncAt: null }),
    generatePassword: () => ({ value: "Gen3rated-Passw0rd!", bits: 120 }),
    generatePassphrase: () => ({ value: "alpha-bravo-charlie-delta", bits: 51 }),
  };
  return {
    items,
    call(method, params) {
      const h = handlers[method] as ((p: unknown) => unknown) | undefined;
      if (h === undefined) return Promise.reject(new CoreError("unsupported"));
      try {
        return Promise.resolve(h(params) as never);
      } catch (e) {
        return Promise.reject(e instanceof Error ? e : new CoreError("error"));
      }
    },
    subscribe(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
  };
}
