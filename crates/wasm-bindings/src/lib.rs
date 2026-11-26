//! Narrow WebAssembly API for the web app (`docs/architecture/overview.md` §5).
//!
//! The API exposes opaque handles and display data only; raw keys never cross into
//! JavaScript. Until roadmap P2 it only reports the core version, so the web build
//! pipeline can be exercised end to end.

use wasm_bindgen::prelude::wasm_bindgen;

/// Version of the urkey core compiled into this WASM module.
#[wasm_bindgen(js_name = coreVersion)]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

#[cfg(test)]
mod tests {
    #[test]
    fn reports_package_version() {
        assert_eq!(super::core_version(), env!("CARGO_PKG_VERSION"));
    }
}
