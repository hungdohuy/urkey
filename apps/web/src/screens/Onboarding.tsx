/** Welcome, account creation with the Emergency Kit, sign-in and recovery (ux/screens.md §3.1–3.5). */
import { LoaderCircle, Printer, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { errorText, useApp } from "../app/context";
import { Actions, Banner, Button, PasswordField, StrengthMeter, TextField, estimateStrength } from "../ui/kit";
import s from "./screens.module.css";

function Shell({ children, wide }: { children: React.ReactNode; wide?: boolean }) {
  return (
    <main className={s.center}>
      <div className={`${s.card} ${wide === true ? s.wide : ""}`}>
        <div className={s.brand}>
          <ShieldCheck size={22} aria-hidden="true" /> urkey
        </div>
        {children}
      </div>
    </main>
  );
}

function defaultDeviceName(): string {
  const ua = navigator.userAgent;
  const browser = /Firefox\//.test(ua) ? "Firefox" : /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const os = /Mac OS X/.test(ua) ? "macOS" : /Windows/.test(ua) ? "Windows" : /iPhone|iPad/.test(ua) ? "iOS" : /Android/.test(ua) ? "Android" : /Linux/.test(ua) ? "Linux" : "this device";
  return `${browser} on ${os}`;
}

export function Welcome() {
  const [mode, setMode] = useState<"choose" | "create" | "signin" | "recover">("choose");
  if (mode === "create") return <CreateAccount onBack={() => setMode("choose")} />;
  if (mode === "signin") return <SignIn onBack={() => setMode("choose")} />;
  if (mode === "recover") return <Recover onBack={() => setMode("choose")} />;
  return (
    <Shell>
      <h1 className={s.title}>Your passwords, encrypted on your devices</h1>
      <p className={s.lead}>urkey encrypts everything before it leaves this device. The server only stores data it can't read.</p>
      <div className={s.choices}>
        <Button variant="primary" onClick={() => setMode("create")}>
          Create a new vault
        </Button>
        <Button onClick={() => setMode("signin")}>Sign in on this device</Button>
        <Button variant="ghost" onClick={() => setMode("recover")}>
          Use a Recovery Key
        </Button>
      </div>
    </Shell>
  );
}

export function EmergencyKit({ email, secretKey, recoveryKey, server }: { email: string; secretKey?: string; recoveryKey?: string; server: string }) {
  return (
    <section className={s.kit} aria-label="Emergency Kit">
      <strong>urkey Emergency Kit</strong>
      <div className={s.kitRow}>
        <span className={s.kitLabel}>Sign-in address</span>
        <span className={s.kitValue}>{server}</span>
      </div>
      <div className={s.kitRow}>
        <span className={s.kitLabel}>Email</span>
        <span className={s.kitValue}>{email}</span>
      </div>
      {secretKey !== undefined && (
        <div className={s.kitRow}>
          <span className={s.kitLabel}>Secret Key — needed to sign in on a new device</span>
          <span className={s.kitValue} data-testid="kit-secret-key">
            {secretKey}
          </span>
        </div>
      )}
      {recoveryKey !== undefined && (
        <div className={s.kitRow}>
          <span className={s.kitLabel}>Recovery Key — opens your vault if you forget your master password</span>
          <span className={s.kitValue} data-testid="kit-recovery-key">
            {recoveryKey}
          </span>
        </div>
      )}
      <div className={s.kitRow}>
        <span className={s.kitLabel}>Master password</span>
        <span className={s.kitValue}>______________________________</span>
      </div>
      <p className={s.kitNote}>
        Print this or store the file offline. Anyone with this kit can open your vault. Don&apos;t keep it in email or cloud notes. urkey can&apos;t recover these
        for you.
      </p>
    </section>
  );
}

function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

/** Shows a kit and requires typing the last 4 characters of the Recovery Key (screens.md §3.2). */
export function KitStep({ email, secretKey, recoveryKey, onDone, doneLabel = "Continue" }: { email: string; secretKey?: string; recoveryKey?: string; onDone: () => void; doneLabel?: string }) {
  const { state } = useApp();
  const [confirm, setConfirm] = useState("");
  const tail = (recoveryKey ?? secretKey ?? "").replace(/-/g, "").slice(-4);
  const ok = confirm.trim().toUpperCase() === tail.toUpperCase();
  const text = [
    "urkey Emergency Kit",
    `Sign-in address: ${state.apiOrigin}`,
    `Email: ${email}`,
    secretKey === undefined ? "" : `Secret Key: ${secretKey}`,
    recoveryKey === undefined ? "" : `Recovery Key: ${recoveryKey}`,
    "Master password: ____________",
    "Store offline. Anyone with this kit can open your vault.",
  ]
    .filter(Boolean)
    .join("\n");
  return (
    <div className={s.stack}>
      <EmergencyKit email={email} server={state.apiOrigin} {...(secretKey === undefined ? {} : { secretKey })} {...(recoveryKey === undefined ? {} : { recoveryKey })} />
      <Actions>
        <Button onClick={() => window.print()}>
          <Printer size={16} aria-hidden="true" /> Print
        </Button>
        <Button onClick={() => download("urkey-emergency-kit.txt", text)}>Download as text</Button>
      </Actions>
      <TextField
        label={`To continue, type the last 4 characters of your ${recoveryKey === undefined ? "Secret Key" : "Recovery Key"}`}
        value={confirm}
        onChange={(e) => setConfirm(e.target.value)}
        autoComplete="off"
        mono
      />
      <Button variant="primary" disabled={!ok} onClick={onDone}>
        {doneLabel}
      </Button>
    </div>
  );
}

function CreateAccount({ onBack }: { onBack: () => void }) {
  const { call, refreshItems } = useApp();
  const [step, setStep] = useState<"email" | "password" | "working" | "kit">("email");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [kit, setKit] = useState<{ secretKeyText: string; recoveryKeyText: string } | null>(null);

  const submitPassword = async (e: { preventDefault(): void }) => {
    e.preventDefault();
    if (password !== repeat) {
      setError("The passwords don't match.");
      return;
    }
    if (password.length < 10) {
      setError("Use at least 10 characters.");
      return;
    }
    setError(null);
    setStep("working");
    window.dispatchEvent(new CustomEvent("urkey:kit-start"));
    try {
      setKit(await call("createAccount", { email, password, deviceName: defaultDeviceName() }));
      setStep("kit");
    } catch (err) {
      window.dispatchEvent(new CustomEvent("urkey:kit-cancel"));
      setError(errorText(err));
      setStep("password");
    }
  };

  if (step === "kit" && kit !== null) {
    return (
      <Shell wide>
        <span className={s.step}>Step 3 of 3</span>
        <h1 className={s.title}>Save your Emergency Kit</h1>
        <p className={s.lead}>This is the only time we can show your Recovery Key. Your Secret Key is also saved on this device.</p>
        <KitStep email={email} secretKey={kit.secretKeyText} recoveryKey={kit.recoveryKeyText} onDone={() => {
            void refreshItems();
            window.dispatchEvent(new CustomEvent("urkey:kit-done"));
          }} doneLabel="Open my vault" />
      </Shell>
    );
  }
  return (
    <Shell>
      <span className={s.step}>Step {step === "email" ? 1 : 2} of 3</span>
      {step === "email" ? (
        <form
          className={s.stack}
          onSubmit={(e) => {
            e.preventDefault();
            setStep("password");
          }}
        >
          <h1 className={s.title}>Create your vault</h1>
          <TextField label="Email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} hint="Used only to sign in. No marketing." autoFocus />
          <Actions>
            <Button onClick={onBack}>Back</Button>
            <Button variant="primary" type="submit">
              Continue
            </Button>
          </Actions>
        </form>
      ) : (
        <form className={s.stack} onSubmit={(e) => void submitPassword(e)}>
          <h1 className={s.title}>Choose a master password</h1>
          <p className={s.lead}>We can&apos;t reset it for you. Your Recovery Key can, so keep your Emergency Kit safe.</p>
          <PasswordField label="Master password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus disabled={step === "working"} />
          <StrengthMeter password={password} />
          {password.length > 0 && estimateStrength(password).bits < 40 && <Banner tone="warn">This password is easy to guess. Consider a longer passphrase.</Banner>}
          <PasswordField label="Repeat master password" value={repeat} onChange={(e) => setRepeat(e.target.value)} disabled={step === "working"} error={error} />
          {step === "working" ? (
            <div className={s.progress} role="status">
              <LoaderCircle size={16} className="spin" aria-hidden="true" /> Creating your keys…
            </div>
          ) : (
            <Actions>
              <Button onClick={() => setStep("email")}>Back</Button>
              <Button variant="primary" type="submit">
                Create vault
              </Button>
            </Actions>
          )}
        </form>
      )}
    </Shell>
  );
}

function SignIn({ onBack }: { onBack: () => void }) {
  const { call } = useApp();
  const [email, setEmail] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [password, setPassword] = useState("");
  const [deviceName, setDeviceName] = useState(defaultDeviceName());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const valid = /^\s*UK1/i.test(secretKey.replace(/[-\s]/g, "")) && secretKey.replace(/[-\s]/g, "").length === 30;
  const submit = async (e: { preventDefault(): void }) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await call("signIn", { email, secretKey, password, deviceName });
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  };
  return (
    <Shell>
      <form className={s.stack} onSubmit={(e) => void submit(e)}>
        <h1 className={s.title}>Sign in on this device</h1>
        <TextField label="Email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} autoFocus />
        <PasswordField
          label="Secret Key"
          value={secretKey}
          onChange={(e) => setSecretKey(e.target.value)}
          hint={secretKey === "" ? "From your Emergency Kit, starts with UK1-" : valid ? "Looks right." : "Keep typing — the format is UK1-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXXX."}
        />
        <PasswordField label="Master password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <TextField label="Device name" value={deviceName} onChange={(e) => setDeviceName(e.target.value)} maxLength={64} hint="Shown in your device list." />
        {error !== null && <Banner tone="danger">{error}</Banner>}
        {busy ? (
          <div className={s.progress} role="status">
            <LoaderCircle size={16} className="spin" aria-hidden="true" /> Signing in…
          </div>
        ) : (
          <Actions>
            <Button onClick={onBack}>Back</Button>
            <Button variant="primary" type="submit" disabled={!valid || password === ""}>
              Sign in
            </Button>
          </Actions>
        )}
      </form>
    </Shell>
  );
}

function Recover({ onBack }: { onBack: () => void }) {
  const { call } = useApp();
  const [step, setStep] = useState<"key" | "password" | "kit">("key");
  const [email, setEmail] = useState("");
  const [rk, setRk] = useState("");
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [kit, setKit] = useState<{ secretKeyText: string; recoveryKeyText: string } | null>(null);

  const start = async (e: { preventDefault(): void }) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await call("recoveryStart", { email, recoveryKey: rk, deviceName: defaultDeviceName() });
      setStep("password");
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };
  const finish = async (e: { preventDefault(): void }) => {
    e.preventDefault();
    if (password !== repeat) {
      setError("The passwords don't match.");
      return;
    }
    if (password.length < 10) {
      setError("Use at least 10 characters.");
      return;
    }
    setBusy(true);
    setError(null);
    window.dispatchEvent(new CustomEvent("urkey:kit-start"));
    try {
      setKit(await call("recoveryFinish", { newPassword: password }));
      setStep("kit");
    } catch (err) {
      window.dispatchEvent(new CustomEvent("urkey:kit-cancel"));
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  if (step === "kit" && kit !== null) {
    return (
      <Shell wide>
        <h1 className={s.title}>Your new Emergency Kit</h1>
        <p className={s.lead}>Your old Secret Key and Recovery Key no longer work. All your other devices were signed out.</p>
        <KitStep email={email} secretKey={kit.secretKeyText} recoveryKey={kit.recoveryKeyText} onDone={() => window.dispatchEvent(new CustomEvent("urkey:kit-done"))} doneLabel="Open my vault" />
      </Shell>
    );
  }
  return (
    <Shell>
      {step === "key" ? (
        <form className={s.stack} onSubmit={(e) => void start(e)}>
          <h1 className={s.title}>Recover your vault</h1>
          <Banner tone="warn">This signs out all your other devices and replaces your master password, Secret Key and Recovery Key.</Banner>
          <TextField label="Email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} autoFocus />
          <PasswordField label="Recovery Key" value={rk} onChange={(e) => setRk(e.target.value)} hint="From your Emergency Kit, starts with UKR1-" />
          {error !== null && <Banner tone="danger">{error}</Banner>}
          <Actions>
            <Button onClick={onBack}>Back</Button>
            <Button variant="primary" type="submit" disabled={busy || rk === ""}>
              {busy ? "Checking…" : "Continue"}
            </Button>
          </Actions>
        </form>
      ) : (
        <form className={s.stack} onSubmit={(e) => void finish(e)}>
          <h1 className={s.title}>Choose a new master password</h1>
          <PasswordField label="New master password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus />
          <StrengthMeter password={password} />
          <PasswordField label="Repeat it" value={repeat} onChange={(e) => setRepeat(e.target.value)} error={error} />
          <Button variant="primary" type="submit" disabled={busy}>
            {busy ? "Setting up…" : "Finish recovery"}
          </Button>
        </form>
      )}
    </Shell>
  );
}

const LOCK_REASONS: Record<string, string> = {
  idle: "Locked after a period of inactivity.",
  keys_changed: "Your vault key was changed on another device. Unlock to continue — your unsynced changes are kept.",
  password_changed: "Your master password was changed on another device. Use the new one.",
};

export function LockScreen() {
  const { call, state } = useApp();
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: { preventDefault(): void }) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await call("unlock", { password });
    } catch (err) {
      setError(errorText(err));
      setBusy(false);
    }
  };
  return (
    <Shell>
      <form className={s.stack} onSubmit={(e) => void submit(e)}>
        <h1 className={s.title}>Your vault is locked</h1>
        <p className={s.lead}>{state.email}</p>
        {state.lockReason !== null && LOCK_REASONS[state.lockReason] !== undefined && <Banner tone="info">{LOCK_REASONS[state.lockReason]}</Banner>}
        <PasswordField label="Master password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus error={error} />
        <Button variant="primary" type="submit" disabled={busy || password === ""}>
          {busy ? "Unlocking…" : "Unlock"}
        </Button>
        <button type="button" className={s.linkButton} onClick={() => void call("forget", undefined)}>
          Forgot your password? Sign out here, then use your Recovery Key.
        </button>
      </form>
    </Shell>
  );
}

export function Revoked() {
  const { call } = useApp();
  return (
    <Shell>
      <h1 className={s.title}>This device was removed from your account</h1>
      <p className={s.lead}>It can no longer sync. Remove the encrypted data stored here, then sign in again if this was a mistake.</p>
      <Button variant="primary" onClick={() => void call("forget", undefined)}>
        Remove data from this device
      </Button>
    </Shell>
  );
}
