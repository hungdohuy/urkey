/** Create / edit items (ux/screens.md §3.9, §3.10). */
import * as Popover from "@radix-ui/react-popover";
import { Plus, Trash2, Wand2 } from "lucide-react";
import { useEffect, useState } from "react";
import { errorText, useApp } from "../app/context";
import type { ItemBody } from "../core/protocol";
import { Actions, Banner, Button, IconButton, Modal, PasswordField, TextField, css } from "../ui/kit";
import { GeneratorPanel } from "./Generator";
import s from "./vault.module.css";

type Url = { url: string; label: string };
type Custom = { id: string; label: string; kind: string; value: string };

function randomId(): string {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(8)))).replace(/[+/=]/g, "").slice(0, 11);
}

function blank(type: "login" | "note" | "ssh_key"): ItemBody {
  const fields: Record<string, unknown> = type === "login" ? { username: "", password: "", urls: [], totp: null } : {};
  return { schema: 1, type, title: "", favorite: false, tags: [], notes: "", fields, custom_fields: [] };
}

export function ItemEditor({ type, id, onDone }: { type: "login" | "note" | "ssh_key" | null; id: string | null; onDone: (id: string | null) => void }) {
  const { call, toast } = useApp();
  const [item, setItem] = useState<ItemBody | null>(type === null ? null : blank(type));
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmCancel, setConfirmCancel] = useState(false);
  const [totpInput, setTotpInput] = useState("");
  const [sshPem, setSshPem] = useState("");
  const [sshPass, setSshPass] = useState("");
  const [busy, setBusy] = useState(false);
  const [genOpen, setGenOpen] = useState(false);

  useEffect(() => {
    if (id !== null) {
      void call("getItemForEdit", { id })
        .then(setItem)
        .catch((e: unknown) => setError(errorText(e)));
    }
  }, [call, id]);

  const update = (patch: Partial<ItemBody>) => {
    setDirty(true);
    setItem((i) => (i === null ? i : { ...i, ...patch }));
  };
  const setField = (k: string, v: unknown) => {
    setDirty(true);
    setItem((i) => (i === null ? i : { ...i, fields: { ...i.fields, [k]: v } }));
  };

  const save = async (e?: { preventDefault(): void }) => {
    e?.preventDefault();
    if (item === null) return;
    if (item.title.trim() === "") {
      setError("Give the item a title.");
      return;
    }
    if (item.type === "ssh_key" && typeof item.fields["private_key"] !== "string") {
      setError("Import a key first.");
      return;
    }
    setBusy(true);
    try {
      const body = { ...item, tags: (item.tags ?? []).map((t) => t.trim()).filter(Boolean) };
      const newId = await call("saveItem", { id, item: body });
      toast("Saved", "ok");
      onDone(newId);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const cancel = () => (dirty ? setConfirmCancel(true) : onDone(null));

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") void save();
      else if (e.key === "Escape") {
        // Let an open popover or dialog handle its own Escape first.
        if (genOpen || document.querySelector("[data-radix-popper-content-wrapper], [role='dialog']") !== null) return;
        cancel();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
    };
  });

  const addTotp = async () => {
    const input = totpInput.trim();
    try {
      const config = input.startsWith("otpauth://") ? await call("parseOtpauth", { uri: input }) : { secret: input.replace(/\s/g, "").toUpperCase(), algorithm: "SHA1", digits: 6, period: 30 };
      await call("totpPreview", { config });
      setField("totp", config);
      setTotpInput("");
      setError(null);
    } catch (err) {
      setError(errorText(err));
    }
  };

  const importKey = async () => {
    try {
      const fields = await call("importSsh", { pem: sshPem, passphrase: sshPass });
      setItem((i) => (i === null ? i : { ...i, fields, title: i.title || (typeof fields["comment"] === "string" && fields["comment"] !== "" ? fields["comment"] : "SSH key") }));
      setSshPem("");
      setSshPass("");
      setDirty(true);
      setError(null);
      if (fields["key_type"] === "rsa") toast("RSA keys are stored but not offered by the SSH agent yet.", "info");
    } catch (err) {
      setError(errorText(err));
    }
  };

  if (item === null) return error === null ? null : <div className={s.editor}><Banner tone="danger">{error}</Banner></div>;
  const f = item.fields;
  const urls = (Array.isArray(f["urls"]) ? f["urls"] : []) as Url[];
  const custom = (item.custom_fields ?? []) as Custom[];
  const totp = f["totp"] as Record<string, unknown> | null | undefined;
  const typeName = item.type === "login" ? "login" : item.type === "note" ? "secure note" : "SSH key";

  return (
    <form className={s.editor} onSubmit={(e) => void save(e)} aria-label={id === null ? `New ${typeName}` : `Edit ${typeName}`}>
      <h1 className={s.detailTitle}>{id === null ? `New ${typeName}` : `Edit ${item.title}`}</h1>
      <TextField label="Title" value={item.title} onChange={(e) => update({ title: e.target.value })} maxLength={200} autoFocus />

      {item.type === "login" && (
        <>
          <TextField label="Username" value={(f["username"] as string | undefined) ?? ""} onChange={(e) => setField("username", e.target.value)} autoComplete="off" />
          <PasswordField
            label="Password"
            value={(f["password"] as string | undefined) ?? ""}
            onChange={(e) => setField("password", e.target.value)}
            after={
              <Popover.Root open={genOpen} onOpenChange={setGenOpen}>
                <Popover.Trigger asChild>
                  <IconButton label="Generate a password">
                    <Wand2 size={16} />
                  </IconButton>
                </Popover.Trigger>
                <Popover.Portal>
                  <Popover.Content className={css.menu} style={{ width: 340, padding: "var(--space-4)" }} align="end" sideOffset={4}>
                    <GeneratorPanel
                      onUse={(v) => {
                        setField("password", v);
                        setGenOpen(false);
                      }}
                    />
                  </Popover.Content>
                </Popover.Portal>
              </Popover.Root>
            }
          />
          <section className={s.section}>
            <h2 className={s.sectionTitle}>Websites</h2>
            {urls.map((u, i) => (
              <div key={i} className={s.inline}>
                <TextField label={`Website ${String(i + 1)}`} value={u.url} type="url" onChange={(e) => setField("urls", urls.map((x, j) => (j === i ? { ...x, url: e.target.value } : x)))} />
                <IconButton label={`Remove website ${String(i + 1)}`} onClick={() => setField("urls", urls.filter((_, j) => j !== i))}>
                  <Trash2 size={16} />
                </IconButton>
              </div>
            ))}
            {urls.length < 20 && (
              <Button onClick={() => setField("urls", [...urls, { url: "https://", label: "website" }])}>
                <Plus size={16} aria-hidden="true" /> Add website
              </Button>
            )}
          </section>
          <section className={s.section}>
            <h2 className={s.sectionTitle}>One-time password</h2>
            {totp != null ? (
              <div className={s.inline}>
                <span>
                  {typeof totp["issuer"] === "string" ? totp["issuer"] : "Configured"} · {typeof totp["digits"] === "number" ? totp["digits"] : 6} digits every{" "}
                  {typeof totp["period"] === "number" ? totp["period"] : 30}s
                </span>
                <Button onClick={() => setField("totp", null)}>Remove</Button>
              </div>
            ) : (
              <div className={s.inline}>
                <TextField label="Paste an otpauth:// link or the secret" value={totpInput} onChange={(e) => setTotpInput(e.target.value)} mono autoComplete="off" />
                <Button onClick={() => void addTotp()} disabled={totpInput.trim() === ""}>
                  Add
                </Button>
              </div>
            )}
          </section>
        </>
      )}

      {item.type === "ssh_key" && (
        <section className={s.section}>
          <h2 className={s.sectionTitle}>Private key</h2>
          {typeof f["fingerprint"] === "string" ? (
            <p style={{ margin: 0 }}>
              {String(f["key_type"])} · <span className={css.mono}>{f["fingerprint"]}</span>
            </p>
          ) : (
            <>
              <label className={css.field}>
                <span className={css.label}>Paste an OpenSSH private key, or choose a file</span>
                <textarea className={`${css.textarea} ${css.mono}`} value={sshPem} onChange={(e) => setSshPem(e.target.value)} spellCheck={false} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" />
              </label>
              <input
                type="file"
                aria-label="Choose a key file"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file !== undefined) void file.text().then(setSshPem);
                }}
              />
              <PasswordField label="Passphrase (if the key has one)" value={sshPass} onChange={(e) => setSshPass(e.target.value)} />
              <Button onClick={() => void importKey()} disabled={sshPem.trim() === ""}>
                Import key
              </Button>
            </>
          )}
        </section>
      )}

      <section className={s.section}>
        <h2 className={s.sectionTitle}>Custom fields</h2>
        {custom.map((c, i) => (
          <div key={c.id} className={s.inline}>
            <TextField label="Label" value={c.label} onChange={(e) => update({ custom_fields: custom.map((x, j) => (j === i ? { ...x, label: e.target.value } : x)) })} />
            <label className={css.field}>
              <span className={css.label}>Kind</span>
              <select className={css.input} value={c.kind} onChange={(e) => update({ custom_fields: custom.map((x, j) => (j === i ? { ...x, kind: e.target.value } : x)) })}>
                <option value="text">Text</option>
                <option value="concealed">Hidden</option>
                <option value="url">URL</option>
                <option value="email">Email</option>
              </select>
            </label>
            <TextField label="Value" value={c.value} type={c.kind === "concealed" ? "password" : "text"} onChange={(e) => update({ custom_fields: custom.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)) })} />
            <IconButton label={`Remove field ${c.label}`} onClick={() => update({ custom_fields: custom.filter((_, j) => j !== i) })}>
              <Trash2 size={16} />
            </IconButton>
          </div>
        ))}
        {custom.length < 50 && (
          <Button onClick={() => update({ custom_fields: [...custom, { id: randomId(), label: "", kind: "text", value: "" }] })}>
            <Plus size={16} aria-hidden="true" /> Add field
          </Button>
        )}
      </section>

      <label className={css.field}>
        <span className={css.label}>{item.type === "note" ? "Note" : "Notes"}</span>
        <textarea className={css.textarea} value={typeof item.notes === "string" ? item.notes : ""} onChange={(e) => update({ notes: e.target.value })} rows={item.type === "note" ? 12 : 4} />
      </label>
      <TextField label="Tags (comma separated)" value={(item.tags ?? []).join(", ")} onChange={(e) => update({ tags: e.target.value.split(",") })} />
      {error !== null && <Banner tone="danger">{error}</Banner>}
      <Actions>
        <Button onClick={cancel}>Cancel</Button>
        <Button variant="primary" type="submit" disabled={busy}>
          {busy ? "Saving…" : "Save"}
        </Button>
      </Actions>
      <Modal open={confirmCancel} onOpenChange={setConfirmCancel} title="Discard your changes?">
        <Actions>
          <Button onClick={() => setConfirmCancel(false)}>Keep editing</Button>
          <Button variant="primary" onClick={() => onDone(null)}>
            Discard
          </Button>
        </Actions>
      </Modal>
    </form>
  );
}
