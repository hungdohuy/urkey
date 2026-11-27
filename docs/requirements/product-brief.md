# AI Coding Agent Instructions --- Personal Password Manager

> **Project:** Personal, developer-focused password manager\
> **Primary goal:** Build a secure, local-first password manager with a
> polished user experience inspired by the interaction patterns and
> visual quality of established password managers, while maintaining an independent
> implementation and architecture.

## 1. Your role

Act as the lead software architect and senior engineer responsible for
designing, implementing, testing, and documenting this product.

You are responsible for:

-   Architecture and technical decisions.
-   Security-first implementation.
-   Product-quality user experience.
-   Automated testing and code quality.
-   Documentation and incremental delivery.

Do not blindly implement requirements. Evaluate technical decisions,
identify security risks, and explain trade-offs before making
significant architectural changes.

## 2. Product vision

Build a personal password manager for an individual developer. It should
combine:

-   A polished, intuitive vault experience inspired by established password managers.
-   End-to-end encrypted storage and synchronization.
-   A strong account recovery mechanism.
-   TOTP authenticator functionality.
-   SSH private-key storage and SSH Agent integration.
-   A PWA for the primary cross-platform vault experience.
-   A macOS companion where native OS integration is required.
-   Cloudflare-hosted infrastructure that stores ciphertext but cannot
    decrypt the vault.

The product is primarily for individual use. Do not introduce
enterprise, family-sharing, or multi-tenant complexity unless explicitly
requested.

## 3. UI/UX direction: use established password managers as the reference

Use **established password managers as a product-quality and interaction reference**, not as
a source to copy its proprietary assets, branding, text, or
implementation.

Study and reproduce the general strengths of its user experience:

-   Clear information hierarchy and calm visual design.
-   A persistent navigation/sidebar for vaults and item categories.
-   A searchable item list with useful grouping and filtering.
-   A focused item detail view with clearly organized fields.
-   Fast create, edit, copy, reveal, and delete interactions.
-   Clear visual distinction between passwords, secure notes,
    identities, payment cards, SSH keys, and other item types.
-   Helpful empty states, onboarding, and recovery guidance.
-   Consistent icons, spacing, typography, keyboard behavior, and
    responsive layouts.
-   Security actions that are understandable without overwhelming the
    user.

### UX requirements

-   Design desktop-first, while keeping the PWA responsive for tablet
    and mobile screens.
-   Make common actions discoverable and require as few steps as
    practical.
-   Support keyboard navigation and accessible labels.
-   Provide clear feedback for save, sync, copy, reveal, lock, and error
    states.
-   Mask sensitive values by default; reveal them only on explicit user
    action.
-   Make copy-to-clipboard actions explicit and provide appropriate
    feedback.
-   Clearly show vault lock state, sync state, and device status.
-   Do not expose secrets in notifications, URLs, browser console
    output, analytics, or error messages.
-   Do not use visual complexity merely to imitate another product.
    Prefer a coherent, original design system.

Before implementing the UI, create a short UX specification and
page/component map. Use original components and assets.

## 4. Required technology direction

  -----------------------------------------------------------------------
  Area                                Preferred technology
  ----------------------------------- -----------------------------------
  Web application                     React + TypeScript

  UI                                  Accessible, reusable component
                                      system

  Cryptographic core                  Rust

  Web integration                     Rust compiled to WebAssembly

  macOS integration                   Rust core with native macOS
                                      integration where needed

  SSH Agent                           Rust

  CLI                                 Rust

  Backend API                         Cloudflare Workers

  Metadata database                   Cloudflare D1

  Encrypted object storage            Cloudflare R2

  Local web storage                   IndexedDB

  Deployment                          Cloudflare
  -----------------------------------------------------------------------

Prefer mature, maintained libraries over custom implementations. Do not
add infrastructure or frameworks without a clear reason.

## 5. Architecture principles

### 5.1 Security first

-   Follow a zero-knowledge architecture for vault content.
-   All sensitive encryption and decryption must happen on trusted
    client devices.
-   The backend must never receive plaintext vault data or plaintext
    encryption keys.
-   Separate account authentication, device identity, and vault
    encryption.
-   Use established cryptographic primitives and reviewed libraries.
-   Never invent cryptographic algorithms.
-   Treat a compromised, unlocked endpoint as a major threat;
    server-side encryption cannot protect plaintext already available on
    that endpoint.

### 5.2 Rust core

Keep security-sensitive and platform-independent logic in reusable Rust
crates.

The Rust core should own, as appropriate:

-   Key hierarchy and key derivation.
-   Authenticated encryption and decryption.
-   Vault serialization and versioning.
-   Recovery and key-envelope operations.
-   TOTP generation.
-   SSH key parsing and handling.
-   Shared validation and domain logic.

Expose only the required functionality through narrow WASM and native
interfaces. Do not expose unnecessary secret material to JavaScript.

### 5.3 Cloudflare backend

The backend is responsible for:

-   Account authentication and authorization.
-   Device registration and revocation.
-   Encrypted vault synchronization.
-   Encrypted backup/object storage.
-   Revision tracking and conflict coordination.

The backend must not have the ability to decrypt vault contents. Keep
server-side metadata minimal and document exactly what metadata is
visible to the service.

### 5.4 Maintainability

-   Use a modular architecture with explicit interfaces.
-   Use strong typing and validated data structures.
-   Version all persisted and encrypted formats.
-   Keep dependencies minimal and review their maintenance and licenses.
-   Write automated unit, integration, and interoperability tests.
-   Document important decisions using Architecture Decision Records
    (ADRs).

## 6. Cryptographic design requirements

The following is a **conceptual target**, not permission to invent or
improvise a cryptographic protocol. Produce a detailed design for review
before implementing production cryptography.

### 6.1 Key hierarchy

The intended conceptual hierarchy is:

1.  Generate a high-entropy Account Secret Key locally.
2.  The user chooses a master password.
3.  Generate an independent random 256-bit Vault Master Key (VMK).
4.  Derive a key-encryption key (KEK) from the master password and
    Account Secret Key using a carefully specified, reviewed
    construction.
5.  Use the KEK to wrap the VMK in a normal unlock envelope.
6.  Generate an independent high-entropy Recovery Key.
7.  Use the Recovery Key, through a separately specified
    key-derivation/wrapping construction, to wrap the same VMK in a
    recovery envelope.
8.  Use the VMK or appropriately derived per-item data-encryption keys
    to protect vault items.
9.  Encrypt item payloads using authenticated encryption.

### 6.2 Mandatory design details

Specify and justify:

-   Exact KDF construction and ordering of inputs.
-   Argon2id parameters and calibration strategy for supported devices.
-   HKDF usage and domain separation, if applicable.
-   AEAD algorithm choice and key/nonce sizes.
-   Nonce generation and uniqueness requirements.
-   Key separation between normal unlock, recovery, items, and other
    purposes.
-   Key-envelope and ciphertext formats.
-   Algorithm identifiers and format versioning.
-   Random-number generation requirements.
-   Error handling that does not leak secrets.
-   Test vectors and cross-platform interoperability tests.

Do not claim equivalence to any other product's internal cryptographic design.
Use public standards and an independently reviewed design.

### 6.3 Critical rules

-   The master password and Account Secret Key must not directly encrypt
    every vault item.
-   Changing the master password should normally require re-wrapping the
    VMK, not decrypting and re-encrypting every item.
-   Recovery must work without the original master password when valid
    recovery material is available.
-   Recovery credentials must be replaceable.
-   Never store plaintext keys on the backend.
-   Never log master passwords, secret keys, recovery keys, VMKs, DEKs,
    TOTP secrets, SSH private keys, or decrypted vault content.

## 7. V1 functional scope

### 7.1 Vault

-   Account creation and unlock.
-   Password/login items.
-   Usernames and website URLs.
-   Secure notes.
-   TOTP secrets and locally generated codes.
-   Password generator.
-   Create, read, update, search, and delete items.
-   Mask/reveal sensitive fields.
-   Copy sensitive fields with clear user feedback.
-   Automatic vault locking.
-   Offline access to the local encrypted vault.

### 7.2 Security, recovery, and devices

-   Local Account Secret Key generation.
-   VMK generation and wrapping.
-   Recovery Key generation and recovery envelope.
-   Clear recovery setup and backup guidance.
-   Recovery on a new device.
-   Master password change.
-   Account Secret Key rotation.
-   Recovery Key rotation and replacement of the recovery envelope.
-   Device registration, listing, and revocation.
-   New-device enrollment notifications or equivalent user-visible
    warnings.

### 7.3 Synchronization

-   End-to-end encrypted cloud synchronization.
-   Multiple enrolled devices.
-   Offline changes and later synchronization.
-   Revision tracking.
-   Conflict detection and a safe conflict-resolution workflow.
-   Tombstones for deleted items.
-   Idempotent operations and retry-safe sync.
-   Explicit handling of stale devices and schema upgrades.

### 7.4 Developer features

-   Import existing SSH private keys.
-   Store SSH private keys encrypted in the vault.
-   SSH Agent compatible with the standard SSH Agent protocol.
-   macOS SSH client integration.
-   Locking and unloading SSH identities.
-   Basic CLI for vault and SSH Agent operations.

### 7.5 Explicitly out of scope for V1

Do not implement these unless the product owner changes the scope:

-   iOS native Password AutoFill extension.
-   iOS native SSH Agent integration.
-   Browser extensions.
-   Family or team sharing.
-   Enterprise administration and organization policies.
-   Advanced cloud credential injection.
-   Trusted-contact or multi-person emergency recovery.
-   Complex role-based access control.

## 8. Suggested repository structure

Start with a modular monorepo. Adjust only when there is a clear
technical reason.

``` text
apps/
  web/
  macos/

crates/
  vault-core/
  crypto-core/
  sync-core/
  ssh-agent/
  cli/
  wasm-bindings/

cloud/
  workers/

docs/
  requirements/
  architecture/
  security/
  decisions/
  ux/

tests/
  fixtures/
  integration/
```

Keep product requirements, architecture, security design, and UX
documentation separate.

## 9. Required engineering workflow

For every task:

1.  Inspect the existing repository and relevant files before editing.
2.  Read the applicable requirements and architecture documents.
3.  Identify dependencies, risks, and affected interfaces.
4.  Propose a small implementation plan.
5.  Implement one logical unit at a time.
6.  Add or update automated tests.
7.  Run relevant tests, formatting, linting, and static analysis.
8.  Review the diff for correctness, security, and unnecessary changes.
9.  Update documentation when behavior or architecture changes.
10. Report exactly what changed, what was tested, and what remains
    incomplete.

### Do not

-   Rewrite unrelated code.
-   Introduce unnecessary abstractions or dependencies.
-   Implement placeholder behavior for security-critical functionality.
-   Claim tests passed unless they were actually run.
-   Silently change approved architectural decisions.
-   Commit credentials, secrets, or real user vault data.
-   Put secrets in logs, fixtures, screenshots, or generated
    documentation.
-   Treat a successful build as proof of cryptographic correctness.

If a requirement is ambiguous, state the ambiguity and recommend a
default. If a security decision is uncertain, stop and explain the risk
before implementing it.

## 10. Documentation to maintain

Maintain these documents and update them as decisions are made:

-   `docs/requirements/v1.md` --- V1 scope, requirements, and acceptance
    criteria.
-   `docs/architecture/overview.md` --- System architecture and
    component boundaries.
-   `docs/architecture/data-model.md` --- Vault item and synchronization
    data models.
-   `docs/security/threat-model.md` --- Threats, assumptions, and
    mitigations.
-   `docs/security/cryptographic-design.md` --- Key hierarchy, KDF,
    encryption, and envelope formats.
-   `docs/security/recovery.md` --- Recovery, rotation, and device
    lifecycle.
-   `docs/ux/design-principles.md` --- UX principles
    and original design system.
-   `docs/decisions/` --- Architecture Decision Records.

## 11. Definition of done for V1

V1 is ready for controlled personal testing when:

-   A user can create and unlock a vault.
-   Vault entries are encrypted locally before persistence or upload.
-   The backend stores ciphertext and only the minimum required
    metadata.
-   A second device can securely enroll and synchronize.
-   Recovery works using the Recovery Key without the original master
    password.
-   Password/key changes work without re-encrypting every item when the
    VMK is unchanged.
-   Recovery Key rotation replaces the active recovery envelope.
-   Device revocation prevents future authorized synchronization by that
    device.
-   SSH Agent works with supported macOS SSH clients.
-   Automated tests cover encryption, decryption, recovery, key
    rotation, and synchronization.
-   The UX supports the core workflows with clear loading, empty,
    success, error, lock, and sync states.
-   Security-sensitive code has received independent review before real
    production credentials are stored.

## 12. First assignment --- do not build the whole application yet

First inspect the repository and establish the project foundation.

Produce:

1.  Repository assessment and proposed structure.
2.  System architecture and component/data-flow diagrams.
3.  Threat model and explicit security assumptions.
4.  Cryptographic protocol specification.
5.  Key hierarchy diagram.
6.  Vault item and encrypted-envelope data models.
7.  Device enrollment and revocation design.
8.  Synchronization protocol and conflict strategy.
9.  UX specification referencing the general interaction patterns of
    established password managers, with original screens and components.
10. ADRs for major technology and security decisions.
11. Phased implementation roadmap with testable acceptance criteria.
12. List of unresolved decisions and the recommended choices.

**Do not implement the production cryptographic core or the full
application until the architecture and cryptographic design have been
reviewed and approved.**

The objective is a secure, maintainable, polished password manager---not
simply fast code generation.
