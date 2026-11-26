/** Settings (ux/screens.md §3.13; recovery.md §4; devices.md §4, §6). */
import { useCallback, useEffect, useState } from "react";
import { errorText, useApp } from "../app/context";
import type { DeviceRecord, SecurityEvent } from "../core/protocol";
import { KitStep } from "../screens/Onboarding";
import { installedRelease } from "../sw/register";
import { Actions, Banner, Button, Modal, PasswordField, StrengthMeter, TextField, css } from "../ui/kit";
import s from "./vault.module.css";

const EVENT_TEXT: Record<string, string> = {
  device_enrolled: "New device added",
  device_revoked: "Device removed",
  password_changed: "Master password changed",
  secret_key_rotated: "Secret Key changed",
  recovery_used: "Recovery Key used",
  recovery_key_rotated: "Recovery Key replaced",
  vmk_rotated: "Vault key changed",
};

type Dialog = null | "password" | "secretKey" | "recoveryKey" | "vaultKey" | "showSecretKey";

function SecurityTab() {
  const { call, settings, saveSettings, toast, state } = useApp();
  const [dialog, setDialog] = useState<Dialog>(null);
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [kit, setKit] = useState<{ secret?: string; recovery?: string } | null>(null);
  const close = () => {
    setDialog(null);
    setPw("");
    setPw2("");
    setError(null);
    setKit(null);
    setBusy(false);
  };
  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  const submit = (e: { preventDefault(): void }) => {
    e.preventDefault();
    void run(async () => {
      if (dialog === "password") {
        if (pw !== pw2) throw new Error("mismatch");
        await call("changePassword", { newPassword: pw });
        toast("Master password changed. Use it on all your devices.", "ok");
        close();
      } else if (dialog === "secretKey") {
        const r = await call("rotateSecretKey", { password: pw });
        setKit({ secret: r.secretKeyText });
      } else if (dialog === "recoveryKey") {
        const r = await call("replaceRecoveryKey", undefined);
        setKit({ recovery: r.recoveryKeyText });
      } else if (dialog === "vaultKey") {
        const r = await call("rotateVaultKey", { password: pw });
        setKit({ recovery: r.recoveryKeyText });
      } else if (dialog === "showSecretKey") {
        setKit({ secret: await call("secretKeyText", undefined) });
      }
    });
  };
  const DESC: Record<Exclude<Dialog, null>, string> = {
    password: "Your items are not re-encrypted. Other devices will ask for the new password after they sync.",
    secretKey: "You'll get a new Emergency Kit. Other devices will ask for the new Secret Key after they sync.",
    recoveryKey: "Your old Recovery Key stops working immediately. You'll get a new Emergency Kit.",
    vaultKey: "Every item is re-encrypted with a new key. Use this after removing a lost device. You'll also get a new Recovery Key.",
    showSecretKey: "Your Secret Key is stored on this device. You need it to sign in on a new one.",
  };
  const TITLE: Record<Exclude<Dialog, null>, string> = {
    password: "Change master password",
    secretKey: "Change Secret Key",
    recoveryKey: "Replace Recovery Key",
    vaultKey: "Change vault key",
    showSecretKey: "Your Secret Key",
  };
  return (
    <div className={s.section}>
      <label className={css.field}>
        <span className={css.label}>Lock automatically after</span>
        <select className={css.input} value={settings.autoLockMinutes} onChange={(e) => void saveSettings({ ...settings, autoLockMinutes: Number(e.target.value) })}>
          {[1, 5, 10, 30, 60].map((m) => (
            <option key={m} value={m}>
              {m === 60 ? "1 hour" : `${String(m)} minute${m === 1 ? "" : "s"}`}
            </option>
          ))}
        </select>
      </label>
      <div style={{ display: "flex", gap: "var(--space-2)", flexWrap: "wrap" }}>
        <Button onClick={() => setDialog("showSecretKey")}>Show Secret Key</Button>
        <Button onClick={() => setDialog("password")}>Change master password</Button>
        <Button onClick={() => setDialog("secretKey")}>Change Secret Key</Button>
        <Button onClick={() => setDialog("recoveryKey")}>Replace Recovery Key</Button>
        <Button onClick={() => setDialog("vaultKey")}>Change vault key</Button>
      </div>
      <Modal open={dialog !== null} onOpenChange={(o) => !o && close()} title={dialog === null ? "" : TITLE[dialog]} description={dialog === null ? "" : DESC[dialog]}>
        {kit !== null ? (
          <KitStep email={state.email ?? ""} {...(kit.secret === undefined ? {} : { secretKey: kit.secret })} {...(kit.recovery === undefined ? {} : { recoveryKey: kit.recovery })} onDone={close} doneLabel="Done" />
        ) : (
          <form onSubmit={submit} style={{ display: "grid", gap: "var(--space-3)" }}>
            {dialog === "password" && (
              <>
                <PasswordField label="New master password" value={pw} onChange={(e) => setPw(e.target.value)} autoFocus />
                <StrengthMeter password={pw} />
                <PasswordField label="Repeat it" value={pw2} onChange={(e) => setPw2(e.target.value)} />
              </>
            )}
            {(dialog === "secretKey" || dialog === "vaultKey") && <PasswordField label="Master password" value={pw} onChange={(e) => setPw(e.target.value)} autoFocus />}
            {error !== null && <Banner tone="danger">{error === "Something went wrong. Try again." && pw !== pw2 ? "The passwords don't match." : error}</Banner>}
            <Actions>
              <Button onClick={close}>Cancel</Button>
              <Button variant="primary" type="submit" disabled={busy}>
                {busy ? "Working…" : dialog === "showSecretKey" ? "Show" : "Continue"}
              </Button>
            </Actions>
          </form>
        )}
      </Modal>
    </div>
  );
}

function DevicesTab() {
  const { call, toast } = useApp();
  const [devices, setDevices] = useState<DeviceRecord[]>([]);
  const [me, setMe] = useState("");
  const [target, setTarget] = useState<DeviceRecord | null>(null);
  const [rename, setRename] = useState<DeviceRecord | null>(null);
  const [name, setName] = useState("");
  const load = useCallback(() => {
    void call("account", undefined)
      .then((a) => {
        setDevices(a.devices);
        setMe(a.thisDevice);
      })
      .catch((e: unknown) => toast(errorText(e), "error"));
  }, [call, toast]);
  useEffect(load, [load]);
  const [now] = useState(() => Date.now());
  const inactive = (d: DeviceRecord) => now - d.last_seen_at > 180 * 86_400_000;
  return (
    <div className={s.section}>
      <table className={s.table}>
        <thead>
          <tr>
            <th>Name</th>
            <th>Platform</th>
            <th>Added</th>
            <th>Last active</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {devices.map((d) => (
            <tr key={d.device_id}>
              <td>
                {d.name}
                {d.device_id === me && <strong> (this device)</strong>}
                {d.revoked_at !== null && " — removed"}
                {d.revoked_at === null && inactive(d) && " — inactive"}
              </td>
              <td>{d.platform}</td>
              <td>
                {new Date(d.created_at).toLocaleDateString()} ({d.enrolled_via === "login" ? "signed in" : d.enrolled_via === "recovery" ? "recovered" : "created"})
              </td>
              <td>{new Date(d.last_seen_at).toLocaleString()}</td>
              <td style={{ whiteSpace: "nowrap" }}>
                {d.revoked_at === null && (
                  <Button
                    variant="ghost"
                    onClick={() => {
                      setRename(d);
                      setName(d.name);
                    }}
                  >
                    Rename
                  </Button>
                )}
                {d.revoked_at === null && d.device_id !== me && (
                  <Button variant="ghost" className={css.danger} onClick={() => setTarget(d)}>
                    Remove
                  </Button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <Modal open={target !== null} onOpenChange={(o) => !o && setTarget(null)} title={`Remove "${target?.name ?? ""}"?`} description="It will be signed out and can't sync. Anything it already has stays on it. To protect future changes, also change your vault key (Security tab).">
        <Actions>
          <Button onClick={() => setTarget(null)}>Cancel</Button>
          <Button
            variant="primary"
            onClick={() => {
              if (target === null) return;
              void call("revokeDevice", { deviceId: target.device_id })
                .then(() => {
                  toast("Device removed. Consider changing your vault key.", "ok");
                  setTarget(null);
                  load();
                })
                .catch((e: unknown) => toast(errorText(e), "error"));
            }}
          >
            Remove device
          </Button>
        </Actions>
      </Modal>
      <Modal open={rename !== null} onOpenChange={(o) => !o && setRename(null)} title="Rename device">
        <TextField label="Name" value={name} maxLength={64} onChange={(e) => setName(e.target.value)} />
        <Actions>
          <Button onClick={() => setRename(null)}>Cancel</Button>
          <Button
            variant="primary"
            disabled={name.trim() === ""}
            onClick={() => {
              if (rename === null) return;
              void call("renameDevice", { deviceId: rename.device_id, name: name.trim() }).then(() => {
                setRename(null);
                load();
              });
            }}
          >
            Save
          </Button>
        </Actions>
      </Modal>
    </div>
  );
}

function ActivityTab() {
  const { call, sync } = useApp();
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const load = useCallback(() => void call("events", undefined).then((e) => setEvents([...e].reverse())), [call]);
  useEffect(load, [load, sync?.unread_events]);
  return (
    <div className={s.section}>
      {sync?.rollback === true && (
        <Banner tone="danger">
          The server returned older data than this device has seen, so syncing is paused. If you trust the server again,
          <Button variant="ghost" onClick={() => void call("clearRollback", undefined)}>
            resume syncing
          </Button>
        </Banner>
      )}
      {events.length === 0 ? (
        <p>No security events yet.</p>
      ) : (
        <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: "var(--space-2)" }}>
          {events.map((e) => (
            <li key={e.seq} style={{ display: "flex", gap: "var(--space-3)", alignItems: "center" }}>
              <span style={{ fontWeight: e.acknowledged ? 400 : 600 }}>{EVENT_TEXT[e.event.kind] ?? e.event.kind}</span>
              <span className={s.meta}>{new Date(e.event.created_at).toLocaleString()}</span>
              {!e.acknowledged && (
                <Button variant="ghost" onClick={() => void call("ackEvent", { seq: e.seq }).then(load)}>
                  Dismiss
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
      <p className={s.meta}>Don&apos;t recognise a new device? Remove it under Devices, then change your master password and vault key.</p>
    </div>
  );
}

function AppearanceTab() {
  const { settings, saveSettings } = useApp();
  return (
    <div className={s.section}>
      <label className={css.field}>
        <span className={css.label}>Theme</span>
        <select className={css.input} value={settings.theme} onChange={(e) => void saveSettings({ ...settings, theme: e.target.value as "system" | "light" | "dark" })}>
          <option value="system">System</option>
          <option value="light">Light</option>
          <option value="dark">Dark</option>
        </select>
      </label>
    </div>
  );
}

/** Encrypted export and restore (ADR 0017, roadmap P7). */
function BackupTab() {
  const { call, toast } = useApp();
  const [file, setFile] = useState<File | null>(null);
  const [pw, setPw] = useState("");
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const download = async () => {
    try {
      const json = await call("exportVault", undefined);
      const url = URL.createObjectURL(new Blob([json], { type: "application/json" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `urkey-export-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast("Encrypted export saved. It opens with your current master password and Secret Key.", "ok");
    } catch (e) {
      toast(errorText(e), "error");
    }
  };
  const restore = (e: { preventDefault(): void }) => {
    e.preventDefault();
    if (file === null) return;
    setBusy(true);
    setError(null);
    void (async () => {
      try {
        const added = await call("restoreExport", { json: await file.text(), password: pw, secretKey: secret });
        toast(`Restored ${String(added)} item${added === 1 ? "" : "s"} as new items.`, "ok");
        setPw("");
        setSecret("");
        setFile(null);
      } catch (err) {
        const text = errorText(err);
        setError(text.startsWith("Couldn't unlock") ? "Couldn't open the export. Check the master password and Secret Key it was made with." : text);
      } finally {
        setBusy(false);
      }
    })();
  };
  return (
    <div className={s.section}>
      <p style={{ margin: 0 }}>
        An export is an encrypted copy of your items. It opens only with the master password and Secret Key you have when you make it, so keep it with your Emergency Kit.
      </p>
      <div>
        <Button onClick={() => void download()}>Export encrypted copy</Button>
      </div>
      <form onSubmit={restore} style={{ display: "grid", gap: "var(--space-3)" }} aria-label="Restore from an export">
        <h2 style={{ margin: 0, fontSize: "var(--text-ml)" }}>Restore from an export</h2>
        <p className={s.meta} style={{ margin: 0 }}>
          Items from the export are added to this vault as new items. Nothing is replaced.
        </p>
        <label className={css.field}>
          <span className={css.label}>Export file</span>
          <input className={css.input} type="file" accept=".json,application/json" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        </label>
        <PasswordField label="Master password of the export" value={pw} onChange={(e) => setPw(e.target.value)} />
        <TextField label="Secret Key of the export" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="off" spellCheck={false} />
        {error !== null && <Banner tone="danger">{error}</Banner>}
        <Actions>
          <Button variant="primary" type="submit" disabled={busy || file === null || pw === "" || secret === ""}>
            {busy ? "Restoring…" : "Restore"}
          </Button>
        </Actions>
      </form>
    </div>
  );
}

function AboutTab() {
  const { state, call } = useApp();
  const [forget, setForget] = useState(false);
  const [release, setRelease] = useState("…");
  useEffect(() => {
    void installedRelease().then(setRelease);
  }, []);
  return (
    <div className={s.section}>
      <p style={{ margin: 0 }}>urkey web {__APP_VERSION__}</p>
      <p className={s.meta} style={{ margin: 0 }}>
        Release hash: <span className={css.mono} data-testid="release-hash">{release}</span> — compare it with the published hash of this release.
      </p>
      <p className={s.meta} style={{ margin: 0 }}>
        Server: {state.apiOrigin}
      </p>
      <p className={s.meta} style={{ margin: 0 }}>
        EFF Large Wordlist © Electronic Frontier Foundation, CC BY 3.0 US.
      </p>
      <Button className={css.danger} onClick={() => setForget(true)}>
        Sign out and remove data from this device
      </Button>
      <Modal open={forget} onOpenChange={setForget} title="Remove urkey from this device?" description="Encrypted data and keys stored in this browser are deleted. Unsynced changes are lost. Your account and other devices are not affected.">
        <Actions>
          <Button onClick={() => setForget(false)}>Cancel</Button>
          <Button variant="primary" onClick={() => void call("forget", undefined)}>
            Remove
          </Button>
        </Actions>
      </Modal>
    </div>
  );
}

const TABS: { id: string; label: string }[] = [
  { id: "security", label: "Security" },
  { id: "devices", label: "Devices" },
  { id: "activity", label: "Activity" },
  { id: "backup", label: "Backup" },
  { id: "appearance", label: "Appearance" },
  { id: "about", label: "About" },
];

export function SettingsPage({ tab, onTab }: { tab: string; onTab: (t: string) => void }) {
  return (
    <div className={s.editor}>
      <h1 className={s.detailTitle}>Settings</h1>
      <div className={s.tabs} role="tablist">
        {TABS.map((t) => (
          <button key={t.id} type="button" role="tab" aria-selected={tab === t.id} className={`${s.tab} ${tab === t.id ? s.tabActive : ""}`} onClick={() => onTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>
      {tab === "security" && <SecurityTab />}
      {tab === "devices" && <DevicesTab />}
      {tab === "activity" && <ActivityTab />}
      {tab === "backup" && <BackupTab />}
      {tab === "appearance" && <AppearanceTab />}
      {tab === "about" && <AboutTab />}
    </div>
  );
}
