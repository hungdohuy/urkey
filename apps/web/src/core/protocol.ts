/** Messages between the UI thread and the core worker (D-17). Only display data crosses. */

export type Phase = "loading" | "welcome" | "locked" | "unlocked" | "revoked";

export interface AppState {
  phase: Phase;
  email: string | null;
  deviceName: string | null;
  apiOrigin: string;
  /** Why the vault is locked, shown on the lock screen. */
  lockReason: "manual" | "idle" | "keys_changed" | "password_changed" | null;
}

export interface SyncStatus {
  pending: number;
  conflicts: number;
  quarantined: number;
  failed: number;
  rollback: boolean;
  unread_events: number;
  state: "synced" | "syncing" | "offline" | "error" | "update_required";
  lastSyncAt: number | null;
}

export interface ItemSummary {
  id: string;
  type: string;
  title: string;
  subtitle: string;
  favorite: boolean;
  tags: string[];
  pending: boolean;
  conflict: boolean;
  editable: boolean;
  has_totp: boolean;
  host: string;
  updated_at: string;
}

export interface DeviceRecord {
  device_id: string;
  name: string;
  platform: string;
  client_version: string;
  enrolled_via: string;
  created_at: number;
  last_seen_at: number;
  revoked_at: number | null;
}

export interface SecurityEvent {
  seq: number;
  event: { kind: string; device_id: string | null; created_at: number };
  acknowledged: boolean;
}

export interface Generated {
  value: string;
  bits: number;
}

export interface TotpCode {
  code: string;
  seconds_remaining: number;
  period: number;
}

/** Item JSON body (data-model §1); concealed values are null in display form. */
export type ItemBody = Record<string, unknown> & {
  schema: number;
  type: string;
  title: string;
  favorite?: boolean;
  tags?: string[];
  notes?: string | null;
  fields: Record<string, unknown>;
  custom_fields?: { id: string; label: string; kind: string; value: string | null }[];
  password_history?: { password: string | null; replaced_at: string }[];
  id?: string;
  editable?: boolean;
};

export interface Methods {
  init: { params: undefined; result: AppState };
  createAccount: { params: { email: string; password: string; deviceName: string }; result: { secretKeyText: string; recoveryKeyText: string } };
  signIn: { params: { email: string; secretKey: string; password: string; deviceName: string }; result: AppState };
  unlock: { params: { password: string }; result: AppState };
  lock: { params: { reason: AppState["lockReason"] }; result: AppState };
  sync: { params: undefined; result: SyncStatus };
  status: { params: undefined; result: SyncStatus };
  listItems: { params: undefined; result: ItemSummary[] };
  getItem: { params: { id: string }; result: ItemBody };
  getItemForEdit: { params: { id: string }; result: ItemBody };
  reveal: { params: { id: string; field: string }; result: string };
  saveItem: { params: { id: string | null; item: ItemBody }; result: string };
  deleteItem: { params: { id: string }; result: null };
  totp: { params: { id: string }; result: TotpCode };
  totpPreview: { params: { config: Record<string, unknown> }; result: TotpCode };
  parseOtpauth: { params: { uri: string }; result: Record<string, unknown> };
  generatePassword: { params: { length: number; digits: boolean; symbols: boolean; avoid_lookalikes: boolean }; result: Generated };
  generatePassphrase: { params: { words: number; separator: string; capitalize: boolean }; result: Generated };
  importSsh: { params: { pem: string; passphrase: string }; result: Record<string, unknown> };
  conflicts: { params: undefined; result: { id: string; reason: string }[] };
  openConflict: { params: { id: string }; result: { server: ItemBody | null; local: ItemBody | null; reason: string } };
  resolveConflict: { params: { id: string; choice: "server" | "local" | "both" }; result: null };
  events: { params: undefined; result: SecurityEvent[] };
  ackEvent: { params: { seq: number }; result: null };
  clearRollback: { params: undefined; result: null };
  account: { params: undefined; result: { account: Record<string, unknown>; devices: DeviceRecord[]; thisDevice: string } };
  changePassword: { params: { newPassword: string }; result: null };
  rotateSecretKey: { params: { password: string }; result: { secretKeyText: string } };
  replaceRecoveryKey: { params: undefined; result: { recoveryKeyText: string } };
  rotateVaultKey: { params: { password: string }; result: { recoveryKeyText: string } };
  revokeDevice: { params: { deviceId: string }; result: null };
  renameDevice: { params: { deviceId: string; name: string }; result: null };
  recoveryStart: { params: { email: string; recoveryKey: string; deviceName: string }; result: null };
  recoveryFinish: { params: { newPassword: string }; result: { secretKeyText: string; recoveryKeyText: string } };
  getSettings: { params: undefined; result: Settings };
  setSettings: { params: Settings; result: null };
  secretKeyText: { params: undefined; result: string };
  forget: { params: undefined; result: AppState };
}

export interface Settings {
  autoLockMinutes: number;
  theme: "system" | "light" | "dark";
}

export type Method = keyof Methods;

export interface Request<M extends Method = Method> {
  id: number;
  method: M;
  params: Methods[M]["params"];
}

export type Response = { id: number; ok: true; result: unknown } | { id: number; ok: false; error: string };

/** Unsolicited worker → UI notifications. */
export type Notice = { notice: "state"; state: AppState } | { notice: "sync"; status: SyncStatus } | { notice: "items_changed" };
