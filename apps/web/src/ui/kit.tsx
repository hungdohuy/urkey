/** urkey UI building blocks (design-principles §3; Radix primitives with our own styling, D-16). */
import * as Dialog from "@radix-ui/react-dialog";
import * as Switch from "@radix-ui/react-switch";
import { Check, Copy, Eye, EyeOff, FileText, KeyRound, SquareTerminal, CircleAlert } from "lucide-react";
import { forwardRef, useEffect, useId, useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode } from "react";
import { useApp } from "../app/context";
import s from "./ui.module.css";

type BtnProps = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "danger" | "ghost" | "default" };

export const Button = forwardRef<HTMLButtonElement, BtnProps>(function Button({ variant = "default", className, ...rest }, ref) {
  const v = variant === "default" ? "" : s[variant];
  return <button ref={ref} type="button" className={[s.button, v, className].filter(Boolean).join(" ")} {...rest} />;
});

export function IconButton({ label, children, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { label: string }) {
  return (
    <button type="button" className={s.iconButton} aria-label={label} title={label} {...rest}>
      {children}
    </button>
  );
}

type FieldProps = InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: string; error?: string | null; mono?: boolean };

export const TextField = forwardRef<HTMLInputElement, FieldProps>(function TextField({ label, hint, error, mono, className, ...rest }, ref) {
  const id = useId();
  return (
    <div className={s.field}>
      <label className={s.label} htmlFor={id}>
        {label}
      </label>
      <input ref={ref} id={id} className={[s.input, mono === true ? s.mono : "", className].filter(Boolean).join(" ")} aria-invalid={error ? true : undefined} {...rest} />
      {hint !== undefined && <span className={s.hint}>{hint}</span>}
      {error && (
        <span className={s.error} role="alert">
          {error}
        </span>
      )}
    </div>
  );
});

/** Password input with a show/hide toggle. */
export function PasswordField(props: FieldProps & { after?: ReactNode }) {
  const [shown, setShown] = useState(false);
  const id = useId();
  const { label, hint, error, after, ...rest } = props;
  return (
    <div className={s.field}>
      <label className={s.label} htmlFor={id}>
        {label}
      </label>
      <div className={s.inputRow}>
        <input id={id} className={`${s.input} ${s.mono}`} type={shown ? "text" : "password"} autoComplete="off" spellCheck={false} {...rest} />
        <IconButton label={shown ? "Hide" : "Show"} onClick={() => setShown((v) => !v)}>
          {shown ? <EyeOff size={16} /> : <Eye size={16} />}
        </IconButton>
        {after}
      </div>
      {hint !== undefined && <span className={s.hint}>{hint}</span>}
      {error && (
        <span className={s.error} role="alert">
          {error}
        </span>
      )}
    </div>
  );
}

/** Local strength estimate (no data leaves the device). */
export function estimateStrength(pw: string): { bits: number; label: string; color: string } {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
  const unique = new Set(pw).size;
  let bits = pool === 0 ? 0 : Math.min(pw.length, unique * 1.5) * Math.log2(pool);
  if (/^(.)\1+$/.test(pw) || /(password|qwerty|123456|letmein)/i.test(pw)) bits = Math.min(bits, 20);
  if (bits < 40) return { bits, label: "Weak", color: "var(--danger)" };
  if (bits < 60) return { bits, label: "Fair", color: "var(--warn)" };
  if (bits < 80) return { bits, label: "Good", color: "var(--accent)" };
  return { bits, label: "Strong", color: "var(--ok)" };
}

export function StrengthMeter({ password }: { password: string }) {
  if (password === "") return null;
  const { bits, label, color } = estimateStrength(password);
  return (
    <div aria-live="polite">
      <div className={s.meter}>
        <div className={s.meterFill} style={{ width: `${String(Math.min(100, bits))}%`, background: color }} />
      </div>
      <span className={s.hint}>Strength: {label} (estimated on this device)</span>
    </div>
  );
}

export function typeColor(type: string): string {
  return type === "login" ? "var(--type-login)" : type === "note" ? "var(--type-note)" : type === "ssh_key" ? "var(--type-ssh)" : "var(--type-unknown)";
}

export function TypeTile({ type, title }: { type: string; title: string }) {
  const icon =
    type === "note" ? <FileText size={16} /> : type === "ssh_key" ? <SquareTerminal size={16} /> : type === "login" ? (title.trim().charAt(0).toUpperCase() || <KeyRound size={16} />) : <CircleAlert size={16} />;
  return (
    <span className={s.tile} style={{ background: typeColor(type) }} aria-hidden="true">
      {icon}
    </span>
  );
}

/** Revealed passwords: digits and symbols coloured differently from letters (§3.4). */
export function PasswordText({ value }: { value: string }) {
  return (
    <span className={s.mono}>
      {Array.from(value).map((c, i) => (
        <span key={i} className={/[0-9]/.test(c) ? s.digit : /[A-Za-z]/.test(c) ? undefined : s.symbol}>
          {c}
        </span>
      ))}
    </span>
  );
}

/** Copy with feedback (design-principles §3.5). The value is fetched only when copying. */
export function CopyButton({ label, getValue }: { label: string; getValue: () => Promise<string> }) {
  const { toast } = useApp();
  const [done, setDone] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(await getValue());
      setDone(true);
      setTimeout(() => {
        setDone(false);
      }, 1500);
      const noted = sessionStorage.getItem("urkey-clipboard-note") === "1";
      toast(noted ? `${label} copied` : `${label} copied. Your browser can't clear the clipboard automatically.`, "ok");
      sessionStorage.setItem("urkey-clipboard-note", "1");
    } catch {
      toast("Couldn't copy to the clipboard.", "error");
    }
  };
  return (
    <IconButton label={`Copy ${label.toLowerCase()}`} onClick={() => void copy()}>
      {done ? <Check size={16} /> : <Copy size={16} />}
    </IconButton>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className={s.empty}>
      <h2 className={s.emptyTitle}>{title}</h2>
      {children}
    </div>
  );
}

export function Banner({ tone, children }: { tone: "info" | "warn" | "danger" | "ok"; children: ReactNode }) {
  const cls = { info: s.bannerInfo, warn: s.bannerWarn, danger: s.bannerDanger, ok: s.bannerOk }[tone];
  return (
    <div className={`${s.banner} ${cls ?? ""}`} role={tone === "danger" ? "alert" : "status"}>
      {children}
    </div>
  );
}

export function Modal({ open, onOpenChange, title, description, children }: { open: boolean; onOpenChange: (o: boolean) => void; title: string; description?: string; children: ReactNode }) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className={s.overlay} />
        <Dialog.Content className={s.dialog} aria-describedby={description === undefined ? undefined : "dialog-desc"}>
          <Dialog.Title className={s.dialogTitle}>{title}</Dialog.Title>
          {description !== undefined && (
            <Dialog.Description id="dialog-desc" className={s.dialogText}>
              {description}
            </Dialog.Description>
          )}
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export function Actions({ children }: { children: ReactNode }) {
  return <div className={s.actions}>{children}</div>;
}

export function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <Switch.Root className={s.switchRoot} checked={checked} onCheckedChange={onChange} aria-label={label}>
      <Switch.Thumb className={s.switchThumb} />
    </Switch.Root>
  );
}

export function Toasts() {
  const { toasts, dismiss } = useApp();
  return (
    <div className={s.toasts} aria-live="polite" role="status">
      {toasts.map((t) => (
        <div key={t.id} className={`${s.toast} ${t.tone === "error" ? s.toastError : ""}`}>
          <span>{t.text}</span>
          {t.action !== undefined && (
            <button
              type="button"
              className={s.toastAction}
              onClick={() => {
                t.action?.run();
                dismiss(t.id);
              }}
            >
              {t.action.label}
            </button>
          )}
        </div>
      ))}
    </div>
  );
}

/** Re-renders every second (TOTP countdowns, relative times). */
export function useTick(ms = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => {
      setNow(Date.now());
    }, ms);
    return () => {
      clearInterval(t);
    };
  }, [ms]);
  return now;
}

export const css = s;
