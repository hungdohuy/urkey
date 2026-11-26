/** Needs attention: conflicts and integrity problems (sync.md §6–§7, screens.md §3.12). */
import { useEffect, useState } from "react";
import { errorText, useApp } from "../app/context";
import type { ItemBody } from "../core/protocol";
import { Banner, Button, EmptyState } from "../ui/kit";
import s from "./vault.module.css";

const REASONS: Record<string, string> = {
  edited_elsewhere: "Edited on two devices",
  deleted_elsewhere: "Deleted on another device while you edited it here",
  keys_changed: "Changed on another device while the vault key was being replaced",
};

function Side({ title, item }: { title: string; item: ItemBody | null }) {
  const f = (item?.fields ?? {});
  return (
    <section className={s.section} aria-label={title}>
      <h3 className={s.sectionTitle}>{title}</h3>
      {item === null ? (
        <p>Deleted</p>
      ) : (
        <dl style={{ margin: 0, display: "grid", gap: "var(--space-1)" }}>
          <dt className={s.fieldLabel}>Title</dt>
          <dd style={{ margin: 0 }}>{item.title}</dd>
          {typeof f["username"] === "string" && (
            <>
              <dt className={s.fieldLabel}>Username</dt>
              <dd style={{ margin: 0 }}>{f["username"]}</dd>
            </>
          )}
          {f["has_password"] === true && (
            <>
              <dt className={s.fieldLabel}>Password</dt>
              <dd style={{ margin: 0 }}>•••••••• (hidden)</dd>
            </>
          )}
          {typeof item.notes === "string" && item.notes !== "" && (
            <>
              <dt className={s.fieldLabel}>Notes</dt>
              <dd style={{ margin: 0 }} className={s.notes}>
                {item.notes}
              </dd>
            </>
          )}
          <dt className={s.fieldLabel}>Edited</dt>
          <dd style={{ margin: 0 }}>{typeof item["updated_at"] === "string" ? new Date(item["updated_at"]).toLocaleString() : "—"}</dd>
        </dl>
      )}
    </section>
  );
}

function Conflict({ id, reason, onDone }: { id: string; reason: string; onDone: () => void }) {
  const { call, toast } = useApp();
  const [data, setData] = useState<{ server: ItemBody | null; local: ItemBody | null } | null>(null);
  useEffect(() => {
    void call("openConflict", { id }).then(setData);
  }, [call, id]);
  const resolve = async (choice: "server" | "local" | "both") => {
    try {
      await call("resolveConflict", { id, choice });
      toast("Conflict resolved", "ok");
      onDone();
    } catch (e) {
      toast(errorText(e), "error");
    }
  };
  if (data === null) return null;
  return (
    <div className={s.section}>
      <strong>{REASONS[reason] ?? "Conflict"}</strong>
      <div className={s.compare}>
        <Side title="This device" item={data.local} />
        <Side title="Other device" item={data.server} />
      </div>
      <div style={{ display: "flex", gap: "var(--space-2)", flexWrap: "wrap" }}>
        <Button variant="primary" onClick={() => void resolve("local")}>
          Keep this device&apos;s
        </Button>
        <Button onClick={() => void resolve("server")}>Keep other</Button>
        <Button onClick={() => void resolve("both")}>Keep both</Button>
      </div>
    </div>
  );
}

export function Attention() {
  const { call, sync } = useApp();
  const [list, setList] = useState<{ id: string; reason: string }[]>([]);
  const load = () => void call("conflicts", undefined).then(setList);
  useEffect(load, [call, sync?.conflicts]);
  return (
    <div className={s.editor}>
      <h1 className={s.detailTitle}>Needs attention</h1>
      {(sync?.failed ?? 0) > 0 && <Banner tone="danger">{sync?.failed} change(s) were refused by the server.</Banner>}
      {list.length === 0 && (sync?.failed ?? 0) === 0 ? <EmptyState title="Nothing needs your attention" /> : list.map((c) => <Conflict key={c.id} id={c.id} reason={c.reason} onDone={load} />)}
    </div>
  );
}
