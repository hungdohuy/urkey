# UX Design Principles and Design System

Status: **Draft — awaiting review.**
Related: [`screens.md`](screens.md) (screen and component map), [`../requirements/v1.md`](../requirements/v1.md) §2.8.

## 1. Reference, not imitation

The **quality and interaction reference** is the mature password-manager category (brief §3).
We take general, widely-used patterns that make such apps pleasant:

- a persistent sidebar for categories, a searchable item list, a focused detail pane;
- fields shown as labelled rows with copy and reveal right next to the value;
- fast keyboard-driven create, find, copy and lock;
- calm visuals, clear type distinctions, helpful empty states and onboarding;
- security explained in plain words at the moment it matters.

We do **not** use its name, logo, icons, illustrations, colours, wording, layouts copied
pixel-for-pixel, or any other asset. The design system below is original, and reviews check
for this (R-UX-4).

## 2. Principles

1. **Calm by default.** Neutral surfaces, one accent colour, no decoration that does not carry
   meaning. Colour is used for item type, state and actions — not ornament.
2. **The secret stays hidden until asked for.** Concealed values are masked by default, revealed
   only by an explicit action, and re-masked automatically (30 s, or when the item changes or
   the window loses focus).
3. **Every action answers back.** Copy, save, delete, lock, sync and errors all give visible
   feedback within 100 ms (toast, inline status, or state change). Feedback never contains the
   secret itself.
4. **Two steps or fewer for the common jobs:** find an item and copy its password; create a login;
   lock the vault.
5. **Keyboard first, pointer friendly.** Everything is reachable by keyboard; targets are at
   least 24 × 24 px (44 × 44 px on touch).
6. **Explain security at the point of use.** Short, plain sentences ("Your Secret Key is stored on
   this device. You'll need it to sign in on a new one.") with a "Learn more" link, never a wall
   of text up front.
7. **Honest about limits.** When the platform cannot do something (e.g. the browser cannot clear
   the clipboard), say so once, clearly.
8. **Never lose work silently.** Unsynced, conflicting or damaged items are visible and
   actionable (sync.md §6).

## 3. Design system ("urkey UI")

### 3.1 Building blocks (D-16)
- **Radix UI primitives** (unstyled, accessible: dialog, popover, menu, tooltip, tabs, toast,
  toggle) with our own styling.
- **CSS Modules + CSS custom properties** for tokens; no CSS-in-JS runtime.
- **Lucide icons**, bundled locally (ISC licence), plus a few custom SVGs for item types.
- **System font stack**; no web fonts are loaded (strict CSP, no third-party requests).

### 3.2 Tokens

All values are CSS variables in `apps/web/src/ui/tokens.css`, defined for light and dark themes.

| Group | Tokens |
|-------|--------|
| Colour — surfaces | `--surface-0` app background, `--surface-1` panes, `--surface-2` raised (cards, popovers), `--border` |
| Colour — text | `--text-1` primary, `--text-2` secondary, `--text-3` hints/disabled |
| Colour — accent | `--accent` (deep teal, original choice), `--accent-hover`, `--accent-text` (on accent) |
| Colour — state | `--ok` green, `--warn` amber, `--danger` red, `--info` blue — each with a `-bg` tint |
| Colour — item types | `--type-login` (teal), `--type-note` (amber), `--type-ssh` (violet), `--type-unknown` (grey) |
| Spacing | 4 px scale: `--space-1` 4 … `--space-8` 32, `--space-12` 48 |
| Radius | `--radius-s` 6, `--radius-m` 10, `--radius-l` 14 |
| Type | `--font-ui` system stack, `--font-mono` system monospace; sizes 12 / 13 / 14 (body) / 16 / 20 / 24 |
| Elevation | `--shadow-1` (popovers), `--shadow-2` (dialogs) |
| Motion | `--duration-fast` 120 ms, `--duration-normal` 200 ms; all motion off with `prefers-reduced-motion` |

All text/background pairs meet WCAG 2.2 AA contrast (4.5:1 body, 3:1 large text and UI
outlines); checked by a token test.

### 3.3 Item type language

| Type | Icon | Tint | Subtitle in list |
|------|------|------|------------------|
| Login | key | `--type-login` | username, else first URL host |
| Secure Note | file-text | `--type-note` | first line of the note (max 60 chars) |
| SSH Key | terminal | `--type-ssh` | key type + short fingerprint |
| Unsupported / damaged | alert-circle | `--type-unknown` | "Update urkey to view" / "Damaged item" |

Each list row shows a 32 px rounded tile: the type icon on its tint, or a monogram (first letter
of the title) for logins. **No favicons are fetched** — that would leak which sites you use.

### 3.4 Concealed values
- Shown as 8 fixed dots regardless of length (length is not leaked), in `--font-mono`.
- Revealed passwords use `--font-mono` with digits and symbols coloured differently from
  letters so similar characters (`l`, `1`, `I`, `0`, `O`) can be told apart.
- Screen readers announce "Password, hidden" until revealed.

### 3.5 Feedback patterns

| Situation | Pattern |
|-----------|---------|
| Copy | Toast "Password copied" (no value) + check icon on the button for 1.5 s; web shows once: "Your browser can't clear the clipboard automatically." Native: "Clears in 90 s". |
| Save | Detail pane leaves edit mode; inline "Saved" with sync dot (pending → synced) |
| Delete | Confirm dialog for the first delete of a session, then toast with **Undo** (10 s) |
| Errors | Inline next to the field when the user can fix it; toast + "Details" for system errors. Errors never include secret values. |
| Long work (unlock ~1–2 s, rotation) | Progress text with what is happening ("Unlocking…", "Re-encrypting 412 items…"); controls disabled; cannot be double-submitted |
| Security notices | Banner at the top of the list pane + entry in Settings › Activity |

### 3.6 Writing style
- Plain, short, second person: "Lock now", "Copy password", "Your vault is locked".
- Name things consistently: **Master password**, **Secret Key**, **Recovery Key**,
  **Emergency Kit**, **vault**, **item**, **device**.
- Error messages say what happened and what to do: "Couldn't unlock. Check your master password
  and try again." (never which secret was wrong — crypto §10).

## 4. Accessibility (R-UX-2)

- WCAG 2.2 AA target. Automated axe checks in Playwright on every screen; manual keyboard and
  VoiceOver pass before each phase exit.
- Visible focus ring (`2px --accent` + offset) on every interactive element.
- Landmarks: `nav` (sidebar), `main` (list + detail), `aria-live="polite"` region for toasts and
  sync state; `assertive` only for lock and errors.
- Lists use `listbox` semantics with roving focus; detail fields are labelled rows with
  buttons named "Copy password", "Reveal password".
- Reduced motion respected; no information carried by colour alone (icons + text with every state).

## 5. Privacy in the UI

- Document title is always `urkey` or `urkey — Locked`; never item titles.
- No item data in URLs (routes use opaque local ids only, never titles) and no URLs shared to
  the server.
- No favicons, link previews, analytics or remote images.
- The vault is hidden (blurred overlay) when the app goes to the background on mobile, to keep
  it out of app-switcher previews where the browser allows.
