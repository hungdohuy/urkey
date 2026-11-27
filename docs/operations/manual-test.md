# Manual test checklist (owner)

Use **test data only** (no real passwords) until M2. Start everything with:

```bash
./scripts/dev.sh dev --fresh      # API :8787 + app http://localhost:5173, empty local database
```

Tick each item, and note anything odd in an issue or tell Claude. Items marked **(auto)** are also
covered by `scripts/dev.sh e2e`, so a failure here means the difference is your browser or OS.

## 1. Web app (http://localhost:5173)

- [ ] Create a vault: email → master password → Emergency Kit → type the last 4 characters → vault opens **(auto)**
- [ ] Save the Emergency Kit text somewhere for this test (Secret Key `UK1-…`, Recovery Key `UKR1-…`)
- [ ] Add a **Login** with a generated password; the password is masked until you click Reveal **(auto)**
- [ ] Copy the password; a toast confirms, and says the browser can't clear the clipboard
- [ ] Add a one-time code (paste `otpauth://totp/Test:me?secret=JBSWY3DPEHPK3PXP&issuer=Test`); a 6-digit code counts down **(auto)**
- [ ] Add a **Secure Note** and an **SSH Key** (import a test key: `ssh-keygen -t ed25519 -f /tmp/k -N ""`)
- [ ] Search finds items by title and username; the keyboard shortcuts work (`/` search, `Shift+L` lock)
- [ ] Lock, then unlock with a wrong password: one generic message; the correct password unlocks **(auto)**
- [ ] Auto-lock: set Settings › Security › Lock after 1 minute, leave the tab idle, and check it locks
- [ ] Settings › Backup: export, then restore into a second account (another browser profile) **(auto)**
- [ ] Settings › Appearance: light and dark themes are both readable
- [ ] Narrow the window to phone width: the panes collapse and everything stays reachable (R-UX-1)

## 2. Second device and sync

Use a second browser or a private window as "device 2".

- [ ] Device 2: "Sign in on this device" with email + Secret Key + password; it sees the items **(auto)**
- [ ] Edit an item on device 1 → Sync now on device 2 shows the change
- [ ] Conflict: go offline on both (DevTools › Network › Offline), edit the same item differently, go
      online, then sync both. "Needs attention" offers server / this device / keep both
- [ ] Device 1 sees a notice in Settings › Activity that device 2 signed in (R-DEV-2)
- [ ] Device 1 › Settings › Devices › Remove device 2 → device 2 shows "This device was removed" **(auto, CLI)**

## 3. Key changes and recovery

- [ ] Change the master password; the other device asks for the new one after it syncs **(auto)**
- [ ] Change the vault key; all items stay readable on both devices **(auto)**
- [ ] Recovery on a new browser profile: "Use a Recovery Key" → set a new password → new Emergency
      Kit; the old devices are signed out **(auto)**

## 4. Production build (security headers, offline)

```bash
./scripts/dev.sh preview          # http://localhost:4173
```

- [ ] DevTools › Console shows no CSP or Trusted Types errors while you use the app **(auto)**
- [ ] Settings › About shows a release hash, and it matches `apps/web/.cloudflare/output/v1/workers/default/assets/release.json`
- [ ] Turn the network off and reload: the app loads and unlocks offline; items are readable **(auto)**
- [ ] Rebuild after a code change and reload: an "Update now" banner waits for your approval (R-SEC-12)

## 5. CLI and SSH agent (macOS: also covers O-6)

```bash
./scripts/dev.sh cli init --server http://localhost:8787
./scripts/dev.sh cli login --email <your test email>    # password + Secret Key from the kit
./scripts/dev.sh cli item list
./scripts/dev.sh cli item get "<title>" --field password
```

- [ ] `item list` shows what the web app created (Rust ↔ WASM interop) **(auto)**
- [ ] `./scripts/dev.sh cli item copy "<title>"` → paste works; after 90 s the clipboard is empty
      (and if you copy something else meanwhile, it is left alone) (R-ITEM-7)
- [ ] macOS: the first run asks for Keychain access for `dev.urkey`; after you allow it, no
      Secret Key file exists in the profile directory (ADR 0006)
- [ ] `./scripts/dev.sh cli agent run` in one terminal; in another, `./scripts/dev.sh cli unlock --minutes 5`
- [ ] `SSH_AUTH_SOCK=<socket from 'urk agent status'> ssh-add -l` lists the vault's SSH key
- [ ] `ssh` or `git` to a host that trusts that key works through the agent
- [ ] `./scripts/dev.sh cli lock` → `ssh-add -l` shows no identities **(auto)**
- [ ] macOS: `urk agent install` installs the launchd agent; after you log out and back in, the agent runs
- [ ] `./scripts/dev.sh cli export --out /tmp/test.urkey-export`; the file is mode 600 and contains no
      readable item text **(auto)**

## 6. iPhone (covers O-4)

Only after deployment (O-8), because the PWA needs HTTPS:
- [ ] Add to Home Screen, then create or sign in
- [ ] Time the unlock (Argon2id). Under about 2 s is the target in the crypto spec (§4.2). Note the
      model and the time in PROGRESS.md.

## When you're done

Stop with Ctrl-C (or `./scripts/dev.sh stop`). Tell Claude which items failed. Passing sections
let the matching PROGRESS.md items be closed (O-6 for section 5 on a Mac, O-12 for the
layout check, O-4 for section 6).
