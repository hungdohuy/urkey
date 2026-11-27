//! Account lifecycle on the client (crypto design §7): create, unlock, change the master password
//! or Secret Key, replace the Recovery Key, recover, and rotate the vault key. Every function
//! returns the exact payload the API expects plus the new secrets for the caller to keep.

use crypto_core::container;
use crypto_core::ids::{AccountId, DeviceId, ItemId, KdfSalt, VmkId};
use crypto_core::kdf::{self, KdfParams};
use crypto_core::secret::{AccountSecretKey, RecoveryKey, VaultMasterKey};
use crypto_core::sign::{self, AuthKey, CHALLENGE_LEN};

use crate::b64::B64;
use crate::record::{self, ItemRecord, VaultKey};
use crate::wire::{
    CreateAccountPayload, DeviceInfo, LoginRequest, RecoverPayload, RecoveryKeyPayload,
    RecoveryLoginRequest, RefreshRequest, RekeyItem, RekeyPayload, SignedRequest,
    UnlockKeysPayload,
};
use crate::{Result, VaultError};

/// What a client needs to unlock locally (cached from [`crate::wire::AccountState`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockMaterial {
    /// Account.
    pub account_id: AccountId,
    /// Salt.
    pub kdf_salt: KdfSalt,
    /// Parameters (validated: floor/ceiling).
    pub kdf_params: KdfParams,
    /// Unlock envelope.
    pub unlock_env: Vec<u8>,
    /// VMK generation in the envelope.
    pub vmk_id: VmkId,
}

/// The result of a successful unlock.
pub struct Unlocked {
    /// Vault key.
    pub vault: VaultKey,
    /// Account auth key (for step-up signatures).
    pub auth: AuthKey,
}

/// A freshly created account.
pub struct NewAccount {
    /// Payload for `POST /v1/accounts`.
    pub payload: CreateAccountPayload,
    /// Show in the Emergency Kit; keep on the device.
    pub secret_key: AccountSecretKey,
    /// Show in the Emergency Kit only.
    pub recovery_key: RecoveryKey,
    /// The unlocked vault.
    pub vault: VaultKey,
    /// Account auth key.
    pub auth: AuthKey,
}

/// New unlock credentials (password change or Secret Key rotation).
pub struct UnlockKeysChange {
    /// Payload for `POST /v1/account/unlock-keys`.
    pub payload: UnlockKeysPayload,
    /// The new auth key (signs `sig_new`).
    pub new_auth: AuthKey,
    /// New salt (cache locally after success).
    pub kdf_salt: KdfSalt,
    /// New Secret Key, for a Secret Key rotation.
    pub secret_key: Option<AccountSecretKey>,
}

/// New recovery credentials.
pub struct RecoveryKeyChange {
    /// Payload for `POST /v1/account/recovery-key`.
    pub payload: RecoveryKeyPayload,
    /// Show in a new Emergency Kit.
    pub recovery_key: RecoveryKey,
}

/// Credentials set at the end of a recovery.
pub struct RecoverySetup {
    /// Payload for `POST /v1/account/recover`.
    pub payload: RecoverPayload,
    /// New Secret Key.
    pub secret_key: AccountSecretKey,
    /// New Recovery Key.
    pub recovery_key: RecoveryKey,
    /// New account auth key.
    pub auth: AuthKey,
    /// New salt.
    pub kdf_salt: KdfSalt,
}

/// A prepared vault-key rotation.
pub struct Rotation {
    /// Payload for `POST /v1/account/rekey`.
    pub payload: RekeyPayload,
    /// The new vault key (use after the server accepts).
    pub vault: VaultKey,
    /// New Recovery Key (D-12).
    pub recovery_key: RecoveryKey,
}

fn b(bytes: &[u8]) -> B64 {
    B64(bytes.to_vec())
}

/// Creates an account (crypto §7.1). `device` describes this device; its key signs the request.
pub fn create_account(
    email: &str,
    password: &str,
    device: &DeviceInfo,
    params: KdfParams,
) -> Result<NewAccount> {
    let account_id = AccountId::generate()?;
    let kdf_salt = KdfSalt::generate()?;
    let secret_key = AccountSecretKey::generate()?;
    let recovery_key = RecoveryKey::generate()?;
    let vmk = VaultMasterKey::generate()?;
    let vmk_id = VmkId::generate()?;
    let unlock = kdf::derive_unlock(password, &secret_key, &account_id, &kdf_salt, &params)?;
    let recovery = kdf::derive_recovery(&recovery_key, &account_id)?;
    let unlock_env =
        container::wrap_vmk_unlock(&unlock.kek, &vmk, account_id, vmk_id, params, kdf_salt)?;
    let recovery_env = container::wrap_vmk_recovery(&recovery.kek, &vmk, account_id, vmk_id)?;
    let payload = CreateAccountPayload {
        account_id: b(account_id.as_bytes()),
        email: email.trim().to_lowercase(),
        kdf_salt: b(kdf_salt.as_bytes()),
        kdf_params: b(&params.encode()),
        auth_pk: b(&unlock.auth.public_key()),
        rauth_pk: b(&recovery.auth.public_key()),
        unlock_env: B64(unlock_env),
        recovery_env: B64(recovery_env),
        vmk_id: b(vmk_id.as_bytes()),
        device: device.clone(),
    };
    Ok(NewAccount {
        payload,
        secret_key,
        recovery_key,
        vault: VaultKey {
            account_id,
            vmk_id,
            vmk,
        },
        auth: unlock.auth,
    })
}

/// Signs the account-creation payload (`sig_account` and `sig_device`).
pub fn sign_create(account: &NewAccount, device_key: &AuthKey) -> Result<SignedRequest> {
    let payload =
        serde_json::to_vec(&account.payload).map_err(|_| VaultError::Invalid("payload"))?;
    let msg = sign::create_message(&account.vault.account_id, &sign::sha256(&payload));
    Ok(SignedRequest {
        sig_account: b(&account.auth.sign(&msg)),
        sig_device: Some(b(&device_key.sign(&msg))),
        payload: B64(payload),
        challenge_id: None,
        sig_new: None,
    })
}

/// Unlocks with the master password and Secret Key (crypto §7.3). Any failure is the same
/// [`crypto_core::CryptoError::Decrypt`]: wrong password, wrong Secret Key or damaged envelope.
pub fn unlock(
    material: &UnlockMaterial,
    password: &str,
    secret_key: &AccountSecretKey,
) -> Result<Unlocked> {
    let keys = kdf::derive_unlock(
        password,
        secret_key,
        &material.account_id,
        &material.kdf_salt,
        &material.kdf_params,
    )
    .map_err(|e| match e {
        crypto_core::CryptoError::InvalidInput(_) => crypto_core::CryptoError::Decrypt,
        other => other,
    })?;
    let vmk = container::unwrap_vmk_unlock(
        &keys.kek,
        &material.unlock_env,
        material.account_id,
        material.vmk_id,
        material.kdf_params,
        material.kdf_salt,
    )?;
    Ok(Unlocked {
        vault: VaultKey {
            account_id: material.account_id,
            vmk_id: material.vmk_id,
            vmk,
        },
        auth: keys.auth,
    })
}

/// Derives the account auth key without unwrapping (for login on a new device, crypto §7.4).
pub fn derive_auth(
    account_id: &AccountId,
    salt: &KdfSalt,
    params: &KdfParams,
    password: &str,
    secret_key: &AccountSecretKey,
) -> Result<AuthKey> {
    Ok(kdf::derive_unlock(password, secret_key, account_id, salt, params)?.auth)
}

/// Builds a login request (crypto §7.4): both the account key and the device key sign.
pub fn login_request(
    account_id: &AccountId,
    challenge_id: &[u8],
    nonce: &[u8; CHALLENGE_LEN],
    auth: &AuthKey,
    device_key: &AuthKey,
    device: &DeviceInfo,
    api_origin: &str,
) -> Result<LoginRequest> {
    let device_id = DeviceId::from_slice(&device.device_id.0)?;
    let msg = sign::login_message(
        account_id,
        nonce,
        &device_id,
        &device_key.public_key(),
        api_origin,
    );
    Ok(LoginRequest {
        account_id: b(account_id.as_bytes()),
        challenge_id: b(challenge_id),
        device: device.clone(),
        sig_account: b(&auth.sign(&msg)),
        sig_device: b(&device_key.sign(&msg)),
    })
}

/// Builds a session refresh request signed by the device key (crypto §7.9).
pub fn refresh_request(
    account_id: &AccountId,
    device_id: &DeviceId,
    challenge_id: &[u8],
    nonce: &[u8; CHALLENGE_LEN],
    device_key: &AuthKey,
) -> RefreshRequest {
    let msg = sign::refresh_message(account_id, nonce, device_id);
    RefreshRequest {
        account_id: b(account_id.as_bytes()),
        device_id: b(device_id.as_bytes()),
        challenge_id: b(challenge_id),
        sig_device: b(&device_key.sign(&msg)),
    }
}

/// Signs a step-up operation (crypto §7.8). `new_auth` adds the proof signature for operations
/// that replace the account auth key.
pub fn stepup_request<T: serde::Serialize>(
    account_id: &AccountId,
    challenge_id: &[u8],
    nonce: &[u8; CHALLENGE_LEN],
    operation: &str,
    payload: &T,
    auth: &AuthKey,
    new_auth: Option<&AuthKey>,
) -> Result<SignedRequest> {
    let payload = serde_json::to_vec(payload).map_err(|_| VaultError::Invalid("payload"))?;
    let msg = sign::stepup_message(account_id, nonce, operation, &sign::sha256(&payload));
    Ok(SignedRequest {
        sig_account: b(&auth.sign(&msg)),
        sig_new: new_auth.map(|k| b(&k.sign(&msg))),
        sig_device: None,
        challenge_id: Some(b(challenge_id)),
        payload: B64(payload),
    })
}

fn new_unlock_keys(
    vault: &VaultKey,
    password: &str,
    secret_key: &AccountSecretKey,
    params: KdfParams,
    reason: &str,
) -> Result<(UnlockKeysPayload, AuthKey, KdfSalt)> {
    let salt = KdfSalt::generate()?;
    let keys = kdf::derive_unlock(password, secret_key, &vault.account_id, &salt, &params)?;
    let env = container::wrap_vmk_unlock(
        &keys.kek,
        &vault.vmk,
        vault.account_id,
        vault.vmk_id,
        params,
        salt,
    )?;
    let payload = UnlockKeysPayload {
        kdf_salt: b(salt.as_bytes()),
        kdf_params: b(&params.encode()),
        auth_pk: b(&keys.auth.public_key()),
        unlock_env: B64(env),
        reason: reason.to_owned(),
    };
    Ok((payload, keys.auth, salt))
}

/// Master password change (crypto §7.5): re-wraps the VMK only; items are untouched (R-ACC-6).
pub fn change_password(
    vault: &VaultKey,
    secret_key: &AccountSecretKey,
    new_password: &str,
    params: KdfParams,
) -> Result<UnlockKeysChange> {
    let (payload, new_auth, kdf_salt) =
        new_unlock_keys(vault, new_password, secret_key, params, "password")?;
    Ok(UnlockKeysChange {
        payload,
        new_auth,
        kdf_salt,
        secret_key: None,
    })
}

/// Secret Key rotation (crypto §7.6): new Secret Key, same password (R-ACC-7).
pub fn rotate_secret_key(
    vault: &VaultKey,
    password: &str,
    params: KdfParams,
) -> Result<UnlockKeysChange> {
    let secret_key = AccountSecretKey::generate()?;
    let (payload, new_auth, kdf_salt) =
        new_unlock_keys(vault, password, &secret_key, params, "secret_key")?;
    Ok(UnlockKeysChange {
        payload,
        new_auth,
        kdf_salt,
        secret_key: Some(secret_key),
    })
}

fn new_recovery(
    vault: &VaultKey,
    vmk: &VaultMasterKey,
    vmk_id: VmkId,
) -> Result<(RecoveryKeyPayload, RecoveryKey)> {
    let recovery_key = RecoveryKey::generate()?;
    let keys = kdf::derive_recovery(&recovery_key, &vault.account_id)?;
    let env = container::wrap_vmk_recovery(&keys.kek, vmk, vault.account_id, vmk_id)?;
    Ok((
        RecoveryKeyPayload {
            rauth_pk: b(&keys.auth.public_key()),
            recovery_env: B64(env),
        },
        recovery_key,
    ))
}

/// Recovery Key replacement (crypto §7.7, R-REC-3).
pub fn replace_recovery_key(vault: &VaultKey) -> Result<RecoveryKeyChange> {
    let (payload, recovery_key) = new_recovery(vault, &vault.vmk, vault.vmk_id)?;
    Ok(RecoveryKeyChange {
        payload,
        recovery_key,
    })
}

/// The recovery auth key, to sign the recovery login.
pub fn recovery_auth(account_id: &AccountId, recovery_key: &RecoveryKey) -> Result<AuthKey> {
    Ok(kdf::derive_recovery(recovery_key, account_id)?.auth)
}

/// Builds the recovery login request (crypto §7.7).
pub fn recovery_login_request(
    account_id: &AccountId,
    challenge_id: &[u8],
    nonce: &[u8; CHALLENGE_LEN],
    recovery_key: &RecoveryKey,
    device_key: &AuthKey,
    device: &DeviceInfo,
    api_origin: &str,
) -> Result<RecoveryLoginRequest> {
    let rauth = recovery_auth(account_id, recovery_key)?;
    let msg = sign::recovery_message(account_id, nonce, &device_key.public_key(), api_origin);
    Ok(RecoveryLoginRequest {
        account_id: b(account_id.as_bytes()),
        challenge_id: b(challenge_id),
        device: device.clone(),
        sig_recovery: b(&rauth.sign(&msg)),
        sig_device: b(&device_key.sign(&msg)),
    })
}

/// Opens the recovery envelope with the Recovery Key.
pub fn open_recovery(
    account_id: AccountId,
    vmk_id: VmkId,
    recovery_env: &[u8],
    recovery_key: &RecoveryKey,
) -> Result<VaultKey> {
    let keys = kdf::derive_recovery(recovery_key, &account_id)?;
    let vmk = container::unwrap_vmk_recovery(&keys.kek, recovery_env, account_id, vmk_id)?;
    Ok(VaultKey {
        account_id,
        vmk_id,
        vmk,
    })
}

/// Sets all new credentials after recovery (R-REC-2): new password, Secret Key and Recovery Key.
pub fn setup_after_recovery(
    vault: &VaultKey,
    new_password: &str,
    params: KdfParams,
) -> Result<RecoverySetup> {
    let secret_key = AccountSecretKey::generate()?;
    let (unlock, auth, kdf_salt) =
        new_unlock_keys(vault, new_password, &secret_key, params, "recovery")?;
    let (recovery, recovery_key) = new_recovery(vault, &vault.vmk, vault.vmk_id)?;
    Ok(RecoverySetup {
        payload: RecoverPayload {
            kdf_salt: unlock.kdf_salt,
            kdf_params: unlock.kdf_params,
            auth_pk: unlock.auth_pk,
            unlock_env: unlock.unlock_env,
            rauth_pk: recovery.rauth_pk,
            recovery_env: recovery.recovery_env,
        },
        secret_key,
        recovery_key,
        auth,
        kdf_salt,
    })
}

/// Prepares a VMK rotation (crypto §7.10, R-DEV-3): new VMK, new item key for every item, every
/// record re-encrypted at its next revision, new unlock envelope (same password, Secret Key and
/// salt) and a new Recovery Key (D-12). Records that fail to open are refused: rotation must not
/// silently drop data.
pub fn rotate_vmk(
    old: &VaultKey,
    material: &UnlockMaterial,
    password: &str,
    secret_key: &AccountSecretKey,
    records: &[ItemRecord],
    expected_vault_seq: u64,
) -> Result<Rotation> {
    let keys = kdf::derive_unlock(
        password,
        secret_key,
        &material.account_id,
        &material.kdf_salt,
        &material.kdf_params,
    )?;
    // Prove the password is right before doing any work.
    container::unwrap_vmk_unlock(
        &keys.kek,
        &material.unlock_env,
        material.account_id,
        material.vmk_id,
        material.kdf_params,
        material.kdf_salt,
    )?;
    let new = VaultKey {
        account_id: old.account_id,
        vmk_id: VmkId::generate()?,
        vmk: VaultMasterKey::generate()?,
    };
    let mut items = Vec::with_capacity(records.len());
    for r in records {
        let opened = record::open(old, r)?;
        let (rec, _) =
            record::reseal_for_rotation(&new, r.item_id, r.revision, opened.item.as_ref())?;
        items.push(RekeyItem {
            item_id: b(rec.item_id.as_bytes()),
            revision: rec.revision,
            dek_wrap: B64(rec.dek_wrap),
            body: B64(rec.body),
            deleted: opened.item.is_none(),
        });
    }
    let unlock_env = container::wrap_vmk_unlock(
        &keys.kek,
        &new.vmk,
        new.account_id,
        new.vmk_id,
        material.kdf_params,
        material.kdf_salt,
    )?;
    let (recovery, recovery_key) = new_recovery(&new, &new.vmk, new.vmk_id)?;
    Ok(Rotation {
        payload: RekeyPayload {
            expected_vault_seq,
            vmk_id: b(new.vmk_id.as_bytes()),
            unlock_env: B64(unlock_env),
            recovery_env: recovery.recovery_env,
            rauth_pk: recovery.rauth_pk,
            items,
        },
        vault: new,
        recovery_key,
    })
}

/// Parses id/salt/param fields received from the server into [`UnlockMaterial`].
pub fn material_from_wire(state: &crate::wire::AccountState) -> Result<UnlockMaterial> {
    Ok(UnlockMaterial {
        account_id: AccountId::from_slice(&state.account_id.0)?,
        kdf_salt: KdfSalt::from_slice(&state.kdf_salt.0)?,
        kdf_params: KdfParams::decode(&state.kdf_params.0)?,
        unlock_env: state.unlock_env.0.clone(),
        vmk_id: VmkId::from_slice(&state.vmk_id.0)?,
    })
}

/// Item id helper for callers holding wire bytes.
pub fn item_id(bytes: &B64) -> Result<ItemId> {
    Ok(ItemId::from_slice(&bytes.0)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{Content, Item, NoteFields};
    use crypto_core::CryptoError;

    fn fast() -> KdfParams {
        KdfParams::new(KdfParams::MIN_M_KIB, KdfParams::MIN_T, 1).unwrap()
    }

    fn device() -> (DeviceInfo, AuthKey) {
        let key = AuthKey::generate_device_key().unwrap();
        let info = DeviceInfo {
            device_id: B64(DeviceId::generate().unwrap().as_bytes().to_vec()),
            device_pk: B64(key.public_key().to_vec()),
            name: "Test".into(),
            platform: "web".into(),
            client_version: "0.0.0".into(),
        };
        (info, key)
    }

    fn material(a: &NewAccount) -> UnlockMaterial {
        UnlockMaterial {
            account_id: a.vault.account_id,
            kdf_salt: KdfSalt::from_slice(&a.payload.kdf_salt.0).unwrap(),
            kdf_params: KdfParams::decode(&a.payload.kdf_params.0).unwrap(),
            unlock_env: a.payload.unlock_env.0.clone(),
            vmk_id: a.vault.vmk_id,
        }
    }

    fn note(text: &str) -> Item {
        let mut i = Item::new(Content::Note(NoteFields::default()), "n", "t", "d");
        i.notes = text.into();
        i
    }

    #[test]
    fn create_sign_and_unlock() {
        let (info, dkey) = device();
        let a = create_account(" Alice@Example.COM ", "pw one", &info, fast()).unwrap();
        assert_eq!(a.payload.email, "alice@example.com");
        let signed = sign_create(&a, &dkey).unwrap();
        let msg = sign::create_message(&a.vault.account_id, &sign::sha256(&signed.payload.0));
        sign::verify(
            &a.payload.auth_pk.array().unwrap(),
            &msg,
            &signed.sig_account.array().unwrap(),
        )
        .unwrap();
        let u = unlock(&material(&a), "pw one", &a.secret_key).unwrap();
        assert_eq!(u.vault.vmk.expose_secret(), a.vault.vmk.expose_secret());
        assert_eq!(u.auth.public_key(), a.auth.public_key());
    }

    #[test]
    fn wrong_password_or_secret_key_give_the_same_error() {
        let (info, _) = device();
        let a = create_account("a@b.c", "pw", &info, fast()).unwrap();
        let m = material(&a);
        let e1 = unlock(&m, "nope", &a.secret_key).err().unwrap();
        let e2 = unlock(&m, "pw", &AccountSecretKey::generate().unwrap())
            .err()
            .unwrap();
        let e3 = unlock(&m, "", &a.secret_key).err().unwrap();
        assert_eq!(e1, VaultError::Crypto(CryptoError::Decrypt));
        assert_eq!(e1, e2);
        assert_eq!(e1, e3);
    }

    #[test]
    fn password_change_keeps_items_and_vmk() {
        let (info, _) = device();
        let a = create_account("a@b.c", "old", &info, fast()).unwrap();
        let (rec, _) = record::seal_new(&a.vault, &note("x")).unwrap();
        let ch = change_password(&a.vault, &a.secret_key, "new", fast()).unwrap();
        let mut m = material(&a);
        m.unlock_env = ch.payload.unlock_env.0.clone();
        m.kdf_salt = ch.kdf_salt;
        assert!(unlock(&m, "old", &a.secret_key).is_err());
        let u = unlock(&m, "new", &a.secret_key).unwrap();
        assert_eq!(u.auth.public_key(), ch.new_auth.public_key());
        // Same record still opens: no re-encryption needed (R-ACC-6).
        assert_eq!(
            record::open(&u.vault, &rec).unwrap().item.unwrap().notes,
            "x"
        );
    }

    #[test]
    fn secret_key_rotation() {
        let (info, _) = device();
        let a = create_account("a@b.c", "pw", &info, fast()).unwrap();
        let ch = rotate_secret_key(&a.vault, "pw", fast()).unwrap();
        let new_ask = ch.secret_key.unwrap();
        let mut m = material(&a);
        m.unlock_env = ch.payload.unlock_env.0.clone();
        m.kdf_salt = ch.kdf_salt;
        assert!(unlock(&m, "pw", &a.secret_key).is_err());
        assert!(unlock(&m, "pw", &new_ask).is_ok());
    }

    #[test]
    fn recovery_then_new_credentials() {
        let (info, _) = device();
        let a = create_account("a@b.c", "forgotten", &info, fast()).unwrap();
        let v = open_recovery(
            a.vault.account_id,
            a.vault.vmk_id,
            &a.payload.recovery_env.0,
            &a.recovery_key,
        )
        .unwrap();
        assert_eq!(v.vmk.expose_secret(), a.vault.vmk.expose_secret());
        assert!(
            open_recovery(
                a.vault.account_id,
                a.vault.vmk_id,
                &a.payload.recovery_env.0,
                &RecoveryKey::generate().unwrap()
            )
            .is_err()
        );
        let s = setup_after_recovery(&v, "fresh", fast()).unwrap();
        let m = UnlockMaterial {
            account_id: a.vault.account_id,
            kdf_salt: s.kdf_salt,
            kdf_params: fast(),
            unlock_env: s.payload.unlock_env.0.clone(),
            vmk_id: a.vault.vmk_id,
        };
        assert!(unlock(&m, "fresh", &s.secret_key).is_ok());
        // The old Recovery Key cannot open the new recovery envelope (R-REC-2).
        assert!(
            open_recovery(
                a.vault.account_id,
                a.vault.vmk_id,
                &s.payload.recovery_env.0,
                &a.recovery_key
            )
            .is_err()
        );
        assert!(
            open_recovery(
                a.vault.account_id,
                a.vault.vmk_id,
                &s.payload.recovery_env.0,
                &s.recovery_key
            )
            .is_ok()
        );
    }

    #[test]
    fn vmk_rotation_reencrypts_everything() {
        let (info, _) = device();
        let a = create_account("a@b.c", "pw", &info, fast()).unwrap();
        let (r1, k1) = record::seal_new(&a.vault, &note("one")).unwrap();
        let (r2, _) = record::seal_new(&a.vault, &note("two")).unwrap();
        let r1d = record::seal_delete(&a.vault, r1.item_id, &k1, 1).unwrap();
        let rot = rotate_vmk(
            &a.vault,
            &material(&a),
            "pw",
            &a.secret_key,
            &[r1d, r2.clone()],
            7,
        )
        .unwrap();
        assert_eq!(rot.payload.items.len(), 2);
        assert_ne!(rot.vault.vmk_id, a.vault.vmk_id);
        for it in &rot.payload.items {
            let rec = ItemRecord {
                item_id: ItemId::from_slice(&it.item_id.0).unwrap(),
                revision: it.revision,
                vmk_id: rot.vault.vmk_id,
                dek_wrap: it.dek_wrap.0.clone(),
                body: it.body.0.clone(),
            };
            let opened = record::open(&rot.vault, &rec).unwrap();
            assert_eq!(opened.item.is_none(), it.deleted);
            // The old VMK cannot open anything written after rotation (R-DEV-3).
            assert!(
                record::open(
                    &a.vault,
                    &ItemRecord {
                        vmk_id: a.vault.vmk_id,
                        ..rec
                    }
                )
                .is_err()
            );
        }
        let m = UnlockMaterial {
            unlock_env: rot.payload.unlock_env.0.clone(),
            vmk_id: rot.vault.vmk_id,
            ..material(&a)
        };
        assert_eq!(
            unlock(&m, "pw", &a.secret_key)
                .unwrap()
                .vault
                .vmk
                .expose_secret(),
            rot.vault.vmk.expose_secret()
        );
        // Wrong password is refused before any work.
        assert!(rotate_vmk(&a.vault, &material(&a), "bad", &a.secret_key, &[], 0).is_err());
    }
}
