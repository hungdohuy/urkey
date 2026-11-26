import styles from "./AppShell.module.css";

const CATEGORIES = ["All items", "Favorites", "Logins", "Secure Notes", "SSH Keys"] as const;

/** Three-pane layout from docs/ux/screens.md §2. No vault data yet (roadmap P2). */
export function AppShell() {
  return (
    <div className={styles.shell}>
      <nav className={styles.sidebar} aria-label="Vault">
        <div className={styles.brand}>urkey</div>
        <ul className={styles.categories}>
          {CATEGORIES.map((name) => (
            <li key={name}>{name}</li>
          ))}
        </ul>
      </nav>
      <main className={styles.main}>
        <section className={styles.list} aria-label="Items">
          <div className={styles.empty}>
            <h1 className={styles.emptyTitle}>Nothing here yet</h1>
            <p className={styles.emptyText}>The vault arrives in a later phase.</p>
          </div>
        </section>
        <section className={styles.detail} aria-label="Item details" />
      </main>
    </div>
  );
}
