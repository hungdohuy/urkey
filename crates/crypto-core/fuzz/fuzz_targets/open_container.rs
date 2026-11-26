//! Arbitrary bytes as every container type: must never panic, and must only ever succeed for
//! genuine ciphertext (which random input essentially never is).
#![no_main]

use crypto_core::container::{self, peek_header};
use crypto_core::ids::{AccountId, ItemId, KdfSalt, VmkId};
use crypto_core::kdf::KdfParams;
use crypto_core::secret::{ItemKey, RecoveryKek, UnlockKek, VaultMasterKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let account = AccountId::from_bytes([1; 16]);
    let item = ItemId::from_bytes([2; 16]);
    let vmk_id = VmkId::from_bytes([3; 16]);
    let _ = peek_header(data);
    if let (Ok(kek), Ok(rkek), Ok(vmk), Ok(dek)) = (
        UnlockKek::from_slice(&[4; 32]),
        RecoveryKek::from_slice(&[5; 32]),
        VaultMasterKey::from_slice(&[6; 32]),
        ItemKey::from_slice(&[7; 32]),
    ) {
        let _ = container::unwrap_vmk_unlock(
            &kek,
            data,
            account,
            vmk_id,
            KdfParams::DEFAULT,
            KdfSalt::from_bytes([8; 16]),
        );
        let _ = container::unwrap_vmk_recovery(&rkek, data, account, vmk_id);
        let _ = container::unwrap_item_key(&vmk, vmk_id, data, account, item);
        let revision = data.first().copied().map_or(1, u64::from);
        let _ = container::open_item(&dek, account, item, revision, data);
    }
});
