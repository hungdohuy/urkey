/** Password generator (ux/screens.md §3.11). Values never leave the device. */
import { RefreshCw } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { errorText, useApp } from "../app/context";
import type { Generated } from "../core/protocol";
import { Button, CopyButton, PasswordText, Toggle, css } from "../ui/kit";
import s from "./vault.module.css";

export function GeneratorPanel({ onUse }: { onUse?: (value: string) => void }) {
  const { call, toast } = useApp();
  const [mode, setMode] = useState<"random" | "passphrase">("random");
  const [length, setLength] = useState(20);
  const [digits, setDigits] = useState(true);
  const [symbols, setSymbols] = useState(true);
  const [lookalikes, setLookalikes] = useState(false);
  const [words, setWords] = useState(6);
  const [separator, setSeparator] = useState("-");
  const [capitalize, setCapitalize] = useState(false);
  const [out, setOut] = useState<Generated | null>(null);

  const generate = useCallback(async () => {
    try {
      setOut(
        mode === "random"
          ? await call("generatePassword", { length, digits, symbols, avoid_lookalikes: lookalikes })
          : await call("generatePassphrase", { words, separator, capitalize }),
      );
    } catch (e) {
      toast(errorText(e), "error");
    }
  }, [call, mode, length, digits, symbols, lookalikes, words, separator, capitalize, toast]);

  useEffect(() => {
    void generate();
  }, [generate]);

  const row = (label: string, control: React.ReactNode) => (
    <label style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "var(--space-3)" }}>
      <span>{label}</span>
      {control}
    </label>
  );
  return (
    <div style={{ display: "grid", gap: "var(--space-3)" }}>
      <div className={s.tabs} role="tablist">
        {(["random", "passphrase"] as const).map((m) => (
          <button key={m} type="button" role="tab" aria-selected={mode === m} className={`${s.tab} ${mode === m ? s.tabActive : ""}`} onClick={() => setMode(m)}>
            {m === "random" ? "Random" : "Passphrase"}
          </button>
        ))}
      </div>
      <div className={s.genValue} data-testid="generated">
        {out === null ? "…" : <PasswordText value={out.value} />}
      </div>
      <span className={css.hint}>About {out === null ? "…" : Math.round(out.bits)} bits of entropy</span>
      {mode === "random" ? (
        <>
          {row(`Length: ${String(length)}`, <input type="range" min={8} max={64} value={length} onChange={(e) => setLength(Number(e.target.value))} aria-label="Length" />)}
          {row("Digits", <Toggle label="Digits" checked={digits} onChange={setDigits} />)}
          {row("Symbols", <Toggle label="Symbols" checked={symbols} onChange={setSymbols} />)}
          {row("Avoid look-alike characters", <Toggle label="Avoid look-alike characters" checked={lookalikes} onChange={setLookalikes} />)}
        </>
      ) : (
        <>
          {row(`Words: ${String(words)}`, <input type="range" min={4} max={10} value={words} onChange={(e) => setWords(Number(e.target.value))} aria-label="Words" />)}
          {row(
            "Separator",
            <select className={css.input} style={{ width: 100 }} value={separator} onChange={(e) => setSeparator(e.target.value)}>
              <option value="-">-</option>
              <option value=" ">space</option>
              <option value=".">.</option>
              <option value="_">_</option>
            </select>,
          )}
          {row("Capitalize", <Toggle label="Capitalize" checked={capitalize} onChange={setCapitalize} />)}
        </>
      )}
      <div style={{ display: "flex", gap: "var(--space-2)", justifyContent: "flex-end" }}>
        <Button onClick={() => void generate()}>
          <RefreshCw size={16} aria-hidden="true" /> Regenerate
        </Button>
        {out !== null && <CopyButton label="Password" getValue={() => Promise.resolve(out.value)} />}
        {onUse !== undefined && out !== null && (
          <Button variant="primary" onClick={() => onUse(out.value)}>
            Use
          </Button>
        )}
      </div>
    </div>
  );
}

export function GeneratorPage() {
  return (
    <div className={s.editor}>
      <h1 className={s.detailTitle}>Password generator</h1>
      <div className={s.section}>
        <GeneratorPanel />
      </div>
    </div>
  );
}
