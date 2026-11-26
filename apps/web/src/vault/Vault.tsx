/** The vault: sidebar, list and detail panes (ux/screens.md §2, §3.6–3.8), shortcuts, auto-lock. */
import * as Menu from "@radix-ui/react-dropdown-menu";
import { ArrowLeft, CircleAlert, CloudOff, FileText, Folder, KeyRound, Lock, Plus, RefreshCw, Settings as Cog, ShieldCheck, SquareTerminal, Star, Tag, TriangleAlert, Wand2 } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useApp } from "../app/context";
import type { ItemSummary } from "../core/protocol";
import { Banner, Button, EmptyState, IconButton, Modal, TypeTile, css } from "../ui/kit";
import { Attention } from "./Attention";
import { GeneratorPage } from "./Generator";
import { ItemDetail } from "./ItemDetail";
import { ItemEditor } from "./ItemEditor";
import { SettingsPage } from "./Settings";
import s from "./vault.module.css";

export type Category = "all" | "favorites" | "login" | "note" | "ssh_key" | "attention" | "settings" | "generator" | `tag:${string}`;
type Mode = { kind: "view" } | { kind: "edit"; id: string } | { kind: "new"; type: "login" | "note" | "ssh_key" };

const NAV: { id: Category; label: string; icon: React.ReactNode }[] = [
  { id: "all", label: "All items", icon: <Folder size={16} /> },
  { id: "favorites", label: "Favorites", icon: <Star size={16} /> },
  { id: "login", label: "Logins", icon: <KeyRound size={16} /> },
  { id: "note", label: "Secure Notes", icon: <FileText size={16} /> },
  { id: "ssh_key", label: "SSH Keys", icon: <SquareTerminal size={16} /> },
];

function inCategory(i: ItemSummary, c: Category): boolean {
  if (c === "all") return true;
  if (c === "favorites") return i.favorite;
  if (c.startsWith("tag:")) return i.tags.includes(c.slice(4));
  return i.type === c;
}

const typing = (e: KeyboardEvent) => {
  const t = e.target as HTMLElement | null;
  return t !== null && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable);
};

function SyncIndicator() {
  const { sync, call } = useApp();
  const st = sync?.state ?? "synced";
  const pending = sync?.pending ?? 0;
  const color = st === "synced" && pending === 0 ? "var(--ok)" : st === "offline" ? "var(--text-3)" : st === "error" || st === "update_required" ? "var(--danger)" : "var(--warn)";
  const text =
    st === "syncing"
      ? "Syncing…"
      : st === "offline"
        ? `Offline${pending > 0 ? ` (${String(pending)} pending)` : ""}`
        : st === "error"
          ? "Sync error"
          : st === "update_required"
            ? "Update required"
            : (sync?.conflicts ?? 0) > 0
              ? "Needs attention"
              : pending > 0
                ? `${String(pending)} not synced`
                : "Synced";
  return (
    <div className={s.sync} role="status" aria-live="polite">
      <span className={s.dot} style={{ background: color }} aria-hidden="true" />
      <span className={s.syncText}>{text}</span>
      <span style={{ marginLeft: "auto" }}>
        <IconButton label="Sync now" onClick={() => void call("sync", undefined)}>
          {st === "offline" ? <CloudOff size={14} /> : <RefreshCw size={14} />}
        </IconButton>
      </span>
    </div>
  );
}

function Notices({ onOpen }: { onOpen: () => void }) {
  const { sync } = useApp();
  if ((sync?.unread_events ?? 0) === 0 && sync?.rollback !== true && (sync?.quarantined ?? 0) === 0) return null;
  return (
    <div style={{ padding: "var(--space-2) var(--space-3) 0" }}>
      {sync?.rollback === true && <Banner tone="danger">The server returned older data than this device has seen. Syncing is paused.</Banner>}
      {(sync?.quarantined ?? 0) > 0 && <Banner tone="danger">Some changes from the server failed integrity checks and were not applied.</Banner>}
      {(sync?.unread_events ?? 0) > 0 && (
        <Banner tone="info">
          <span>Security activity on your account.</span>
          <Button variant="ghost" onClick={onOpen}>
            Review
          </Button>
        </Banner>
      )}
    </div>
  );
}

export function Vault() {
  const app = useApp();
  const { items, call, settings, sync } = app;
  const [category, setCategory] = useState<Category>("all");
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<"title" | "recent">("title");
  const [selected, setSelected] = useState<string | null>(null);
  const [mode, setMode] = useState<Mode>({ kind: "view" });
  const [help, setHelp] = useState(false);
  const [settingsTab, setSettingsTab] = useState("security");
  const searchRef = useRef<HTMLInputElement>(null);

  // Auto-lock after inactivity (R-ACC-5).
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    const reset = () => {
      clearTimeout(timer);
      timer = setTimeout(() => void call("lock", { reason: "idle" }), settings.autoLockMinutes * 60_000);
    };
    const events = ["pointerdown", "keydown", "mousemove", "wheel", "touchstart"] as const;
    events.forEach((e) => {
      window.addEventListener(e, reset, { passive: true });
    });
    reset();
    return () => {
      clearTimeout(timer);
      events.forEach((e) => {
        window.removeEventListener(e, reset);
      });
    };
  }, [call, settings.autoLockMinutes]);

  const tags = useMemo(() => [...new Set(items.flatMap((i) => i.tags))].sort(), [items]);
  const visible = useMemo(() => {
    const q = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
    const list = items.filter(
      (i) => inCategory(i, category) && q.every((t) => [i.title, i.subtitle, i.host, ...i.tags].some((f) => f.toLowerCase().includes(t))),
    );
    return list.sort((a, b) => (sort === "title" ? a.title.localeCompare(b.title, undefined, { sensitivity: "base" }) : b.updated_at.localeCompare(a.updated_at)));
  }, [items, category, query, sort]);

  const listView = category !== "attention" && category !== "settings" && category !== "generator";
  const select = useCallback((id: string | null) => {
    setSelected(id);
    setMode({ kind: "view" });
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        if (mode.kind !== "view") return; // editor handles its own Esc
        if (query !== "") setQuery("");
        return;
      }
      if (((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "f") || (!typing(e) && e.key === "/")) {
        e.preventDefault();
        setCategory((c) => (c === "settings" || c === "attention" || c === "generator" ? "all" : c));
        setTimeout(() => searchRef.current?.focus(), 0);
        return;
      }
      if (typing(e) || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === "L") void call("lock", { reason: "manual" });
      else if (e.key === "?") setHelp(true);
      else if (e.key === "n") setMode({ kind: "new", type: "login" });
      else if (e.key === "e" && selected !== null) setMode({ kind: "edit", id: selected });
      else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        if (!listView || visible.length === 0) return;
        e.preventDefault();
        const idx = visible.findIndex((i) => i.id === selected);
        const next = e.key === "ArrowDown" ? Math.min(visible.length - 1, idx + 1) : Math.max(0, idx - 1);
        select(visible[next]?.id ?? null);
        document.getElementById(`row-${visible[next]?.id ?? ""}`)?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
    };
  }, [call, mode.kind, query, selected, visible, listView, select]);

  const attentionCount = (sync?.conflicts ?? 0) + (sync?.failed ?? 0);
  const count = (c: Category) => items.filter((i) => inCategory(i, c)).length;
  const navButton = (id: Category, label: string, icon: React.ReactNode, extra?: React.ReactNode) => (
    <li key={id}>
      <button
        type="button"
        className={`${s.navItem} ${category === id ? s.navActive : ""}`}
        aria-current={category === id ? "page" : undefined}
        onClick={() => {
          setCategory(id);
          setMode({ kind: "view" });
        }}
        title={label}
      >
        {icon}
        <span className={s.navLabel}>{label}</span>
        {extra}
      </button>
    </li>
  );

  let main: React.ReactNode;
  if (category === "settings") main = <SettingsPage tab={settingsTab} onTab={setSettingsTab} />;
  else if (category === "attention") main = <Attention />;
  else if (category === "generator") main = <GeneratorPage />;
  else if (mode.kind === "new") main = <ItemEditor type={mode.type} id={null} onDone={(id) => { setMode({ kind: "view" }); if (id !== null) setSelected(id); }} />;
  else if (mode.kind === "edit") main = <ItemEditor type={null} id={mode.id} onDone={() => setMode({ kind: "view" })} />;
  else if (selected !== null && items.some((i) => i.id === selected))
    main = <ItemDetail key={selected} id={selected} onEdit={() => setMode({ kind: "edit", id: selected })} onDeleted={() => setSelected(null)} onBack={() => setSelected(null)} />;
  else
    main = (
      <EmptyState title={items.length === 0 ? "Your vault is empty" : "Select an item"}>
        {items.length === 0 ? (
          <>
            <p>Add your first login, or import an SSH key.</p>
            <div style={{ display: "flex", gap: "var(--space-2)" }}>
              <Button variant="primary" onClick={() => setMode({ kind: "new", type: "login" })}>
                Add a login
              </Button>
              <Button onClick={() => setMode({ kind: "new", type: "ssh_key" })}>Import an SSH key</Button>
            </div>
          </>
        ) : (
          <p>
            Press <kbd className={css.kbd}>?</kbd> for keyboard shortcuts.
          </p>
        )}
      </EmptyState>
    );

  const showDetail = mode.kind !== "view" || selected !== null || !listView;
  return (
    <div className={s.shell} data-view={showDetail ? "detail" : "list"}>
      <nav className={s.sidebar} aria-label="Vault">
        <div className={s.sideHeader}>
          <span className={s.brand}>
            <ShieldCheck size={18} aria-hidden="true" /> <span className={s.brandText}>urkey</span>
          </span>
          <IconButton label="Lock now (Shift+L)" onClick={() => void call("lock", { reason: "manual" })}>
            <Lock size={16} />
          </IconButton>
        </div>
        <ul className={s.nav}>
          {NAV.map((n) => navButton(n.id, n.label, n.icon, <span className={s.navCount}>{count(n.id)}</span>))}
          {tags.length > 0 && <li className={s.navSection}>Tags</li>}
          {tags.map((t) => navButton(`tag:${t}`, t, <Tag size={16} />, <span className={s.navCount}>{count(`tag:${t}`)}</span>))}
          <li className={s.navSection}>Tools</li>
          {navButton("generator", "Password generator", <Wand2 size={16} />)}
          {attentionCount > 0 &&
            navButton("attention", "Needs attention", <TriangleAlert size={16} className={s.attention} />, <span className={s.navCount}>{attentionCount}</span>)}
        </ul>
        <div className={s.sideFooter}>
          <SyncIndicator />
          <ul className={s.nav} style={{ padding: 0 }}>
            {navButton("settings", "Settings", <Cog size={16} />)}
          </ul>
        </div>
      </nav>
      <section className={s.listPane} aria-label="Items">
        <div className={s.listHeader}>
          <div className={s.searchRow}>
            <input
              ref={searchRef}
              className={css.input}
              type="search"
              placeholder="Search vault ( / )"
              aria-label="Search vault"
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                if (!listView) setCategory("all");
              }}
            />
            <Menu.Root>
              <Menu.Trigger asChild>
                <Button variant="primary" aria-label="New item">
                  <Plus size={16} aria-hidden="true" /> New
                </Button>
              </Menu.Trigger>
              <Menu.Portal>
                <Menu.Content className={css.menu} align="end" sideOffset={4}>
                  <Menu.Item className={css.menuItem} onSelect={() => setMode({ kind: "new", type: "login" })}>
                    <KeyRound size={16} /> Login
                  </Menu.Item>
                  <Menu.Item className={css.menuItem} onSelect={() => setMode({ kind: "new", type: "note" })}>
                    <FileText size={16} /> Secure Note
                  </Menu.Item>
                  <Menu.Item className={css.menuItem} onSelect={() => setMode({ kind: "new", type: "ssh_key" })}>
                    <SquareTerminal size={16} /> SSH Key
                  </Menu.Item>
                </Menu.Content>
              </Menu.Portal>
            </Menu.Root>
          </div>
          <div className={s.listTools}>
            <span>
              {visible.length} item{visible.length === 1 ? "" : "s"}
            </span>
            <select className={s.select} aria-label="Sort" value={sort} onChange={(e) => setSort(e.target.value as "title" | "recent")}>
              <option value="title">Title (A–Z)</option>
              <option value="recent">Recently edited</option>
            </select>
          </div>
        </div>
        <Notices
          onOpen={() => {
            setCategory("settings");
            setSettingsTab("activity");
          }}
        />
        {visible.length === 0 ? (
          <EmptyState title={query !== "" ? `No items match "${query}"` : items.length === 0 ? "Nothing here yet" : "No items in this category"} />
        ) : (
          <ul className={s.list} role="listbox" aria-label="Items">
            {visible.map((i, idx) => {
              const letter = sort === "title" ? (i.title.charAt(0).toUpperCase() || "#") : null;
              const prev = idx > 0 ? (visible[idx - 1]?.title.charAt(0).toUpperCase() ?? "") : null;
              return (
                <li key={i.id} role="presentation">
                  {letter !== null && letter !== prev && <div className={s.group}>{letter}</div>}
                  <div
                    id={`row-${i.id}`}
                    role="option"
                    aria-selected={selected === i.id}
                    tabIndex={selected === i.id || (selected === null && idx === 0) ? 0 : -1}
                    className={`${s.row} ${selected === i.id ? s.rowSelected : ""}`}
                    onClick={() => select(i.id)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") select(i.id);
                    }}
                  >
                    <TypeTile type={i.type} title={i.title} />
                    <span className={s.rowText}>
                      <span className={s.rowTitle}>{i.title}</span>
                      <span className={s.rowSub}>{i.subtitle}</span>
                    </span>
                    <span className={s.badges}>
                      {i.favorite && <Star size={14} aria-label="Favorite" />}
                      {i.pending && <RefreshCw size={14} aria-label="Not synced" />}
                      {i.conflict && <CircleAlert size={14} aria-label="In conflict" color="var(--warn)" />}
                    </span>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </section>
      <main className={s.detailPane} aria-label="Item details">
        {showDetail && (
          <div className={s.mobileOnly} style={{ padding: "var(--space-2)" }}>
            <Button
              variant="ghost"
              onClick={() => {
                setSelected(null);
                setMode({ kind: "view" });
                if (!listView) setCategory("all");
              }}
            >
              <ArrowLeft size={16} /> Back
            </Button>
          </div>
        )}
        {main}
      </main>
      <Modal open={help} onOpenChange={setHelp} title="Keyboard shortcuts">
        <table className={s.table}>
          <tbody>
            {[
              ["/ or Ctrl/⌘+F", "Search"],
              ["↑ ↓ Enter", "Move in the list, open"],
              ["n", "New item"],
              ["e", "Edit item"],
              ["c / u / t", "Copy password / username / one-time code"],
              ["r", "Reveal or hide the password"],
              ["f", "Toggle favorite"],
              ["Shift+L", "Lock now"],
              ["Ctrl/⌘+Enter", "Save (while editing)"],
              ["Esc", "Cancel, close, clear search"],
            ].map(([k, d]) => (
              <tr key={k}>
                <td>
                  <kbd className={css.kbd}>{k}</kbd>
                </td>
                <td>{d}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Modal>
    </div>
  );
}
