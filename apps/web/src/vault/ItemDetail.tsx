/** Item detail (ux/screens.md §3.8): field rows with copy/reveal, live TOTP, delete with undo. */
import * as Menu from "@radix-ui/react-dropdown-menu";
import { Eye, EyeOff, ExternalLink, MoreHorizontal, Pencil, Star, Trash2 } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { errorText, useApp } from "../app/context";
import type { ItemBody, TotpCode } from "../core/protocol";
import { Actions, Banner, Button, CopyButton, IconButton, Modal, PasswordText, TypeTile, css, useTick } from "../ui/kit";
import s from "./vault.module.css";

let deleteConfirmed = false;

type Fields = Record<string, unknown>;
const str = (v: unknown) => (typeof v === "string" ? v : "");

function Row({ label, children, actions }: { label: string; children: React.ReactNode; actions?: React.ReactNode }) {
  return (
    <div className={s.fieldRow}>
      <span className={s.fieldLabel}>{label}</span>
      <span className={s.fieldValue}>{children}</span>
      <span className={s.fieldActions}>{actions}</span>
    </div>
  );
}

/** A concealed value: 8 fixed dots until revealed; re-masks after 30 s, on blur or item change. */
function Concealed({ id, field, label, shortcut = false }: { id: string; field: string; label: string; shortcut?: boolean }) {
  const { call, toast } = useApp();
  const [value, setValue] = useState<string | null>(null);
  useEffect(() => {
    if (value === null) return;
    const t = setTimeout(() => {
      setValue(null);
    }, 30_000);
    const hide = () => {
      setValue(null);
    };
    window.addEventListener("blur", hide);
    return () => {
      clearTimeout(t);
      window.removeEventListener("blur", hide);
    };
  }, [value]);
  const toggle = useCallback(async () => {
    if (value !== null) {
      setValue(null);
      return;
    }
    try {
      setValue(await call("reveal", { id, field }));
    } catch (e) {
      toast(errorText(e), "error");
    }
  }, [call, field, id, toast, value]);
  useEffect(() => {
    if (!shortcut) return;
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (t !== null && (t.tagName === "INPUT" || t.tagName === "TEXTAREA")) return;
      if (e.key === "r" && !e.metaKey && !e.ctrlKey && !e.altKey) void toggle();
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
    };
  }, [shortcut, toggle]);
  return (
    <Row
      label={label}
      actions={
        <>
          <IconButton label={value === null ? `Reveal ${label.toLowerCase()}` : `Hide ${label.toLowerCase()}`} onClick={() => void toggle()}>
            {value === null ? <Eye size={16} /> : <EyeOff size={16} />}
          </IconButton>
          <CopyButton label={label} getValue={() => call("reveal", { id, field })} />
        </>
      }
    >
      {value === null ? (
        <span className={css.mono} aria-label={`${label}, hidden`}>
          ••••••••
        </span>
      ) : field === "private_key" ? (
        <pre className={css.mono} style={{ margin: 0, whiteSpace: "pre-wrap", fontSize: "var(--text-xs)" }}>
          {value}
        </pre>
      ) : (
        <PasswordText value={value} />
      )}
    </Row>
  );
}

function Totp({ id }: { id: string }) {
  const { call } = useApp();
  const now = useTick();
  const [code, setCode] = useState<TotpCode | null>(null);
  useEffect(() => {
    let live = true;
    void call("totp", { id }).then((c) => {
      if (live) setCode(c);
    });
    return () => {
      live = false;
    };
  }, [call, id, now]);
  if (code === null) return null;
  const frac = code.seconds_remaining / code.period;
  const warn = code.seconds_remaining <= 5;
  return (
    <Row label="One-time code" actions={<CopyButton label="One-time code" getValue={async () => (await call("totp", { id })).code} />}>
      <span style={{ display: "inline-flex", gap: "var(--space-2)", alignItems: "center" }}>
        <span className={`${s.totp} ${warn ? s.totpWarn : ""}`} data-testid="totp-code">
          {code.code.slice(0, code.code.length / 2)} {code.code.slice(code.code.length / 2)}
        </span>
        <svg className={s.ring} viewBox="0 0 20 20" aria-label={`${String(code.seconds_remaining)} seconds left`}>
          <circle cx="10" cy="10" r="8" fill="none" stroke="var(--border)" strokeWidth="3" />
          <circle cx="10" cy="10" r="8" fill="none" stroke={warn ? "var(--warn)" : "var(--accent)"} strokeWidth="3" strokeDasharray={`${String(50.3 * frac)} 50.3`} transform="rotate(-90 10 10)" />
        </svg>
      </span>
    </Row>
  );
}

export function ItemDetail({ id, onEdit, onDeleted }: { id: string; onEdit: () => void; onDeleted: () => void; onBack: () => void }) {
  const { call, toast, items } = useApp();
  const [item, setItem] = useState<ItemBody | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const summary = items.find((i) => i.id === id);

  useEffect(() => {
    let live = true;
    call("getItem", { id })
      .then((it) => {
        if (live) setItem(it);
      })
      .catch((e: unknown) => {
        if (live) setError(errorText(e));
      });
    return () => {
      live = false;
    };
  }, [call, id, summary?.updated_at, summary?.pending]);

  const copy = useCallback(
    async (field: string, label: string, viaTotp = false) => {
      try {
        const value = viaTotp ? (await call("totp", { id })).code : await call("reveal", { id, field });
        await navigator.clipboard.writeText(value);
        toast(`${label} copied`, "ok");
      } catch (e) {
        toast(errorText(e), "error");
      }
    },
    [call, id, toast],
  );

  const toggleFavorite = useCallback(async () => {
    try {
      const full = await call("getItemForEdit", { id });
      await call("saveItem", { id, item: { ...full, favorite: full.favorite !== true } });
    } catch (e) {
      toast(errorText(e), "error");
    }
  }, [call, id, toast]);

  const doDelete = useCallback(async () => {
    setConfirmDelete(false);
    deleteConfirmed = true;
    try {
      const full = item?.editable === true ? await call("getItemForEdit", { id }) : null;
      await call("deleteItem", { id });
      onDeleted();
      toast("Item deleted", "info", full === null ? undefined : { label: "Undo", run: () => void call("saveItem", { id, item: full }) });
    } catch (e) {
      toast(errorText(e), "error");
    }
  }, [call, id, item, onDeleted, toast]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (t !== null && (t.tagName === "INPUT" || t.tagName === "TEXTAREA")) return;
      if (e.metaKey || e.ctrlKey || e.altKey || item === null) return;
      const login = item.type === "login";
      if (e.key === "c" && login) void copy("password", "Password");
      else if (e.key === "u" && login) void copy("username", "Username");
      else if (e.key === "t" && login && item.fields["totp"] != null) void copy("", "One-time code", true);
      else if (e.key === "f") void toggleFavorite();
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
    };
  }, [copy, item, toggleFavorite]);

  if (error !== null) return <div className={s.detail}><Banner tone="danger">{error}</Banner></div>;
  if (item === null) return null;
  const f = item.fields as Fields;
  const urls = (Array.isArray(f["urls"]) ? f["urls"] : []) as { url: string; label?: string }[];
  const custom = item.custom_fields ?? [];
  const history = item.password_history ?? [];
  return (
    <article className={s.detail} aria-labelledby="item-title">
      <header className={s.detailHeader}>
        <TypeTile type={item.type} title={item.title} />
        <h1 id="item-title" className={s.detailTitle}>
          {item.title}
        </h1>
        <IconButton label={item.favorite === true ? "Remove from favorites" : "Add to favorites"} onClick={() => void toggleFavorite()}>
          <Star size={18} fill={item.favorite === true ? "currentColor" : "none"} />
        </IconButton>
        {item.editable === true && (
          <Button onClick={onEdit}>
            <Pencil size={16} aria-hidden="true" /> Edit
          </Button>
        )}
        <Menu.Root>
          <Menu.Trigger asChild>
            <IconButton label="More actions">
              <MoreHorizontal size={18} />
            </IconButton>
          </Menu.Trigger>
          <Menu.Portal>
            <Menu.Content className={css.menu} align="end">
              <Menu.Item className={css.menuItem} onSelect={() => (deleteConfirmed ? void doDelete() : setConfirmDelete(true))}>
                <Trash2 size={16} /> Delete
              </Menu.Item>
            </Menu.Content>
          </Menu.Portal>
        </Menu.Root>
      </header>
      {summary?.conflict === true && <Banner tone="warn">This item was edited on two devices. Resolve it under Needs attention.</Banner>}
      {item.editable !== true && <Banner tone="info">This item was made by a newer version of urkey. Update to edit it.</Banner>}
      {summary?.pending === true && <span className={s.meta}>Not synced yet</span>}

      <div className={s.fields}>
        {item.type === "login" && (
          <>
            <Row label="Username" actions={<CopyButton label="Username" getValue={() => call("reveal", { id, field: "username" })} />}>
              {str(f["username"]) || <span className={s.meta}>—</span>}
            </Row>
            {f["has_password"] === true && <Concealed key={`${id}:password`} id={id} field="password" label="Password" shortcut />}
            {f["totp"] != null && <Totp id={id} />}
            {urls.map((u, i) => (
              <Row
                key={i}
                label={u.label ?? "Website"}
                actions={
                  /^https?:\/\//i.test(u.url) ? (
                    <IconButton label="Open website" onClick={() => window.open(u.url, "_blank", "noopener,noreferrer")}>
                      <ExternalLink size={16} />
                    </IconButton>
                  ) : undefined
                }
              >
                {u.url}
              </Row>
            ))}
          </>
        )}
        {item.type === "ssh_key" && (
          <>
            <Row label="Type">{str(f["key_type"])}</Row>
            <Row label="Fingerprint">
              <span className={css.mono}>{str(f["fingerprint"])}</span>
            </Row>
            <Row label="Public key" actions={<CopyButton label="Public key" getValue={() => Promise.resolve(str(f["public_key"]))} />}>
              <span className={css.mono} style={{ fontSize: "var(--text-xs)" }}>
                {str(f["public_key"])}
              </span>
            </Row>
            <Row label="SSH agent">{(f["agent"] as { enabled?: boolean } | undefined)?.enabled === false ? "Not offered" : "Offered when unlocked (urk agent)"}</Row>
            <Concealed key={`${id}:pk`} id={id} field="private_key" label="Private key" />
          </>
        )}
        {custom.map((c) =>
          c.kind === "concealed" ? (
            <Concealed key={`${id}:${c.id}`} id={id} field={`custom:${c.id}`} label={c.label} />
          ) : (
            <Row key={c.id} label={c.label} actions={<CopyButton label={c.label} getValue={() => Promise.resolve(c.value ?? "")} />}>
              {c.value}
            </Row>
          ),
        )}
      </div>
      {str(item.notes) !== "" && (
        <section className={s.section} aria-label="Notes">
          <h2 className={s.sectionTitle}>Notes</h2>
          <div className={s.notes}>{str(item.notes)}</div>
        </section>
      )}
      {history.length > 0 && (
        <details>
          <summary>Password history ({history.length})</summary>
          <div className={s.fields}>
            {history.map((h, i) => (
              <Concealed key={`${id}:h${String(i)}`} id={id} field={`history:${String(i)}`} label={new Date(h.replaced_at).toLocaleDateString()} />
            ))}
          </div>
        </details>
      )}
      <span className={s.meta}>
        Edited {str(item["updated_at"]) === "" ? "—" : new Date(str(item["updated_at"])).toLocaleString()}
        {(item.tags ?? []).length > 0 ? ` · Tags: ${(item.tags ?? []).join(", ")}` : ""}
      </span>
      <Modal open={confirmDelete} onOpenChange={setConfirmDelete} title="Delete this item?" description="You can undo right after deleting. Other devices remove it at their next sync.">
        <Actions>
          <Button onClick={() => setConfirmDelete(false)}>Cancel</Button>
          <Button variant="primary" className={css.danger} onClick={() => void doDelete()}>
            Delete
          </Button>
        </Actions>
      </Modal>
    </article>
  );
}
