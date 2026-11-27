//! Compile-time guard: no secret-holding type implements `Debug` (owner decision O-2, roadmap P1).
//!
//! `assert_not_debug!(T, ...)` fails to compile if any `T: Debug`. It uses the ambiguity trick of
//! the `static_assertions` crate: a type that implements `Debug` matches both impls below, which
//! is an inference error. Adding `#[derive(Debug)]` to a guarded type therefore breaks the build.
//! Every crate that holds secrets lists its secret types in a `#[cfg(test)]` module.

/// Support trait for [`assert_not_debug!`]. Not part of the public API.
#[doc(hidden)]
pub trait AmbiguousIfDebug<A> {
    /// Referenced only to force inference.
    fn check() {}
}
impl<T: ?Sized> AmbiguousIfDebug<()> for T {}
impl<T: ?Sized + core::fmt::Debug> AmbiguousIfDebug<u8> for T {}

/// Fails to compile if any listed type implements `Debug`.
#[macro_export]
macro_rules! assert_not_debug {
    ($($t:ty),+ $(,)?) => {$(
        const _: fn() = || {
            let _ = <$t as $crate::no_debug::AmbiguousIfDebug<_>>::check;
        };
    )+};
}

#[cfg(test)]
mod tests {
    use crate::container::ItemContent;
    use crate::kdf::{RecoveryKeys, UnlockKeys};
    use crate::secret::{
        AccountSecretKey, ItemKey, RecoveryKek, RecoveryKey, UnlockKek, VaultMasterKey,
    };
    use crate::sign::AuthKey;

    crate::assert_not_debug!(
        AccountSecretKey,
        RecoveryKey,
        VaultMasterKey,
        ItemKey,
        UnlockKek,
        RecoveryKek,
        AuthKey,
        UnlockKeys,
        RecoveryKeys,
        ItemContent,
    );
}
