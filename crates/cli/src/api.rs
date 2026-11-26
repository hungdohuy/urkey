//! HTTP client for the API (`docs/architecture/api.md`), using the OS trust store.

use crate::vault_core;
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use ureq::Agent;
use ureq::tls::{RootCerts, TlsConfig};

use crate::error::CliError;

/// An API failure: HTTP status and the server's error code (never echoes request data).
#[derive(Debug)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
}

impl From<ApiError> for CliError {
    fn from(e: ApiError) -> Self {
        CliError::new(match (e.status, e.code.as_str()) {
            (0, _) => "Can't reach the server. Check your connection.".to_owned(),
            (401, "device_revoked") => "This device was removed from your account.".to_owned(),
            (401, _) => {
                "The server refused the sign-in. Check your email, Secret Key and master password."
                    .to_owned()
            }
            (409, "email_taken") => "An account with this email already exists.".to_owned(),
            (426, _) => "This version of urk is too old. Please update.".to_owned(),
            (429, _) => "Too many attempts. Wait a minute and try again.".to_owned(),
            (s, c) => format!("Server error ({s} {c})."),
        })
    }
}

pub struct Api {
    base: String,
    agent: Agent,
    pub token: Option<String>,
}

const CLIENT: &str = concat!("macos-cli/", env!("CARGO_PKG_VERSION"));

impl Api {
    pub fn new(base: &str) -> Self {
        let tls = TlsConfig::builder()
            .root_certs(RootCerts::PlatformVerifier)
            .build();
        let agent: Agent = Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(60)))
            .http_status_as_error(false)
            .tls_config(tls)
            .build()
            .into();
        Self {
            base: base.trim_end_matches('/').to_owned(),
            agent,
            token: None,
        }
    }

    /// The origin string signed in login/recovery messages (must equal the server's API_ORIGIN).
    pub fn origin(&self) -> &str {
        &self.base
    }

    fn finish<T: DeserializeOwned>(
        res: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    ) -> Result<T, ApiError> {
        let mut res = res.map_err(|_| ApiError {
            status: 0,
            code: "network".into(),
        })?;
        let status = res.status().as_u16();
        if (200..300).contains(&status) {
            if status == 204 {
                return serde_json::from_str("null").map_err(|_| ApiError {
                    status,
                    code: "bad_response".into(),
                });
            }
            return res.body_mut().read_json::<T>().map_err(|_| ApiError {
                status,
                code: "bad_response".into(),
            });
        }
        let code = res
            .body_mut()
            .read_json::<vault_core::wire::ErrorBody>()
            .map(|b| b.error)
            .unwrap_or_else(|_| "unknown".into());
        Err(ApiError { status, code })
    }

    pub fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        let mut req = self
            .agent
            .get(format!("{}{path}", self.base))
            .header("urkey-client", CLIENT);
        if let Some(t) = &self.token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        Self::finish(req.call())
    }

    pub fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        let mut req = self
            .agent
            .post(format!("{}{path}", self.base))
            .header("urkey-client", CLIENT);
        if let Some(t) = &self.token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        Self::finish(req.send_json(body))
    }
}
