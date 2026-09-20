//! What the gate told us about the caller, and what this function is configured
//! to do — both parsed from JSON the gate hands over on every request.
//!
//! This is the whole of what used to be shared types inside the gate. The gate
//! now knows only that it verified *someone* and carried *some* settings
//! through; what those mean is decided here, which is why nothing about Coil
//! releases appears in the gate any more.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The gate's view of the authenticated caller, from `Request::auth()`.
#[derive(Debug, Clone, Deserialize)]
pub struct Caller {
    #[serde(default)]
    pub principal: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub claims: Option<GitHubClaims>,
}

/// The identity a GitHub Actions OIDC token proved. A publication binds to these
/// so a different job — or a different attempt of the same job — cannot continue
/// someone else's transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitHubClaims {
    pub repository_id: String,
    pub workflow_ref: String,
    pub run_id: String,
    pub run_attempt: String,
    pub commit: String,
}

impl Caller {
    pub fn parse(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }

    /// Blanket authority (`*`) or the named scope. Mirrors the gate's own rule,
    /// because the gate admitted this caller on `any_scopes` and left the finer
    /// distinction — reader or publisher — to us.
    pub fn allows(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == "*" || s == scope)
    }

    pub fn github(&self) -> Option<&GitHubClaims> {
        match self.principal.as_str() {
            "github-actions" => self.claims.as_ref(),
            _ => None,
        }
    }
}

/// This function's configuration, from `Request::settings()` — the route's
/// `settings` table, which the gate carried through without reading.
#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    pub root: PathBuf,
    #[serde(default = "default_read_scope")]
    pub read_scope: String,
    #[serde(default = "default_publish_scope")]
    pub publish_scope: String,
    #[serde(default = "default_max_artifact_bytes")]
    pub max_artifact_bytes: u64,
    #[serde(default = "default_retention")]
    pub retain_builds: usize,
}

fn default_read_scope() -> String {
    "coil:read".into()
}
fn default_publish_scope() -> String {
    "coil:nightly:publish".into()
}
fn default_max_artifact_bytes() -> u64 {
    512 * 1024 * 1024
}
fn default_retention() -> usize {
    14
}

impl Settings {
    /// Parse the route's settings, refusing anything that would leave the store
    /// half-configured. A misconfigured release store must fail loudly at the
    /// first request, not serve a surprising root.
    pub fn parse(json: &str) -> Result<Self, String> {
        let settings: Settings = serde_json::from_str(json)
            .map_err(|e| format!("release function settings are invalid: {e}"))?;
        if settings.root.as_os_str().is_empty()
            || settings.read_scope.trim().is_empty()
            || settings.publish_scope.trim().is_empty()
            || settings.max_artifact_bytes == 0
            || settings.retain_builds < 2
        {
            return Err("release function settings have an invalid root/scope/limit".into());
        }
        Ok(settings)
    }
}
