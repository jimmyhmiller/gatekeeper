//! Passkey (WebAuthn) authentication — the human credential.
//!
//! The shared bearer token in [`crate::auth`] is a *machine* credential: one
//! string, valid from anywhere, and whoever holds it is you. This module adds
//! the human half, in three shapes that all converge on the same ceremony:
//!
//! - **Browser** — a WebAuthn assertion mints a signed, expiring session cookie.
//! - **Native app** — the *same* assertion endpoints, driven by Apple's
//!   `ASAuthorizationPlatformPublicKeyCredentialProvider`. The only extra
//!   server-side piece is the associated-domain file, see
//!   [`PasskeyEngine::apple_app_site_association`].
//! - **Command line** — a device-authorization flow. A CLI cannot run a
//!   WebAuthn ceremony, so it requests a code, you approve it in a browser with
//!   your passkey, and the CLI receives a long-lived *device token* of its own.
//!
//! Device tokens are stored hashed and revoked individually. That is the
//! practical win over one shared secret: a leaked device token is one `revoke`
//! away from dead, and it never had to be pasted into a browser in the first
//! place.
//!
//! **Registration is not public.** `main.rs` mounts the whole `/register`
//! subtree as a private route, so enrolling a passkey requires the bootstrap
//! token (or an already-valid passkey session). There is no path by which an
//! unauthenticated caller can enroll a credential.
//!
//! Everything here is *additive* to the safety core: `Router::decide` is
//! untouched, and the only change at the call site is that `auth_ok` now has
//! three ways to become true instead of one.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use webauthn_rs::prelude::*;

use crate::config::PasskeyConfig;

type HmacSha256 = Hmac<Sha256>;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// How long a half-finished WebAuthn ceremony stays valid. Short: the browser
/// is meant to answer immediately.
const CEREMONY_TTL: Duration = Duration::from_secs(300);
/// How long an unapproved device-flow request stays pollable.
const DEVICE_TTL: Duration = Duration::from_secs(900);
/// Poll interval handed to the CLI, in seconds.
const DEVICE_POLL_INTERVAL: u64 = 3;

/// One enrolled passkey, as persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enrolled {
    /// Human label, e.g. "MacBook Touch ID". For the revoke UI and the report.
    pub label: String,
    /// Unix seconds when it was enrolled.
    pub added: u64,
    /// The credential itself (public key, id, signature counter).
    pub passkey: Passkey,
}

/// One issued device token, as persisted. The token value is NOT stored — only
/// its SHA-256 — so the state file leaking does not hand over a credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceToken {
    pub label: String,
    pub added: u64,
    /// Hex SHA-256 of the token string.
    pub hash: String,
}

/// The persisted state: enrolled credentials, issued device tokens, the stable
/// WebAuthn user handle, and the session-signing key.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoreFile {
    #[serde(default)]
    credentials: Vec<Enrolled>,
    #[serde(default)]
    devices: Vec<DeviceToken>,
    /// Stable user handle across all of this user's credentials. Generated once.
    #[serde(default)]
    user_id: Option<Uuid>,
    /// Base64url session-signing key, generated once. Kept here so sessions
    /// survive a restart (otherwise every deploy would log you out).
    #[serde(default)]
    session_key: Option<String>,
}

/// An in-flight device-authorization request.
struct DeviceRequest {
    user_code: String,
    created: Instant,
    /// Set once a human approves it in the browser: the minted device token.
    /// The CLI collects it exactly once.
    approved: Option<String>,
}

/// The passkey subsystem. One instance, shared across worker threads.
pub struct PasskeyEngine {
    webauthn: Webauthn,
    cfg: PasskeyConfig,
    path: PathBuf,
    session_key: [u8; 32],
    user_id: Uuid,
    state: Mutex<StoreFile>,
    reg_states: Mutex<HashMap<String, (Instant, PasskeyRegistration)>>,
    auth_states: Mutex<HashMap<String, (Instant, PasskeyAuthentication)>>,
    devices: Mutex<HashMap<String, DeviceRequest>>,
}

impl PasskeyEngine {
    /// Build the engine, creating the state directory and the persistent
    /// session key on first run. Fails closed: any error here means `main`
    /// refuses to enable passkeys at all rather than serving a half-built
    /// login surface.
    pub fn new(cfg: &PasskeyConfig) -> Result<Self, String> {
        let origin = Url::parse(&cfg.origin)
            .map_err(|e| format!("passkey.origin {:?} is not a URL: {e}", cfg.origin))?;
        let webauthn = WebauthnBuilder::new(&cfg.rp_id, &origin)
            .map_err(|e| format!("webauthn setup (rp_id {:?}): {e}", cfg.rp_id))?
            .rp_name("gatekeeper")
            .build()
            .map_err(|e| format!("webauthn build: {e}"))?;

        let dir = &cfg.state_dir;
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("creating passkey state dir {}: {e}", dir.display()))?;
        // 0700, not the 0755 create_dir_all defaults to: nothing outside the
        // service has business traversing the credential store.
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("chmod 700 {}: {e}", dir.display()))?;
        }
        let path = dir.join("passkeys.json");

        let mut store: StoreFile = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| format!("parsing {}: {e}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => StoreFile::default(),
            Err(e) => return Err(format!("reading {}: {e}", path.display())),
        };

        // Generate the stable bits once, then persist them.
        let mut dirty = false;
        if store.user_id.is_none() {
            store.user_id = Some(Uuid::new_v4());
            dirty = true;
        }
        if store.session_key.is_none() {
            let mut key = [0u8; 32];
            getrandom(&mut key)?;
            store.session_key = Some(B64.encode(key));
            dirty = true;
        }
        let user_id = store.user_id.unwrap();
        let session_key = {
            let raw = B64
                .decode(store.session_key.as_deref().unwrap_or_default())
                .map_err(|e| format!("session key is not base64url: {e}"))?;
            let mut k = [0u8; 32];
            if raw.len() != 32 {
                return Err("session key is not 32 bytes".into());
            }
            k.copy_from_slice(&raw);
            k
        };

        let engine = PasskeyEngine {
            webauthn,
            cfg: cfg.clone(),
            path,
            session_key,
            user_id,
            state: Mutex::new(store),
            reg_states: Mutex::new(HashMap::new()),
            auth_states: Mutex::new(HashMap::new()),
            devices: Mutex::new(HashMap::new()),
        };
        if dirty {
            engine.persist()?;
        }
        Ok(engine)
    }

    /// Write the state file with 0600 permissions. Called under no lock, so
    /// callers must drop the state guard first (we take it again here).
    fn persist(&self) -> Result<(), String> {
        let bytes = {
            let store = self.state.lock().unwrap();
            serde_json::to_vec_pretty(&*store).map_err(|e| format!("serializing state: {e}"))?
        };
        // Write-then-rename so a crash mid-write cannot truncate the credential
        // store and lock us out.
        //
        // The temp file is created 0600 *from the outset* rather than chmod'd
        // after the write. It holds `session_key`, the HMAC secret that forges
        // any session cookie, and a plain `fs::write` would leave it
        // world-readable for the length of the write — a local race with a
        // permanent payoff, since the key only changes if someone edits the
        // store by hand.
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let tmp = self.path.with_extension("json.tmp");
        // Remove first: `mode()` only applies when the file is created, so
        // reusing a leftover temp file would silently keep its old permissions.
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("creating {}: {e}", tmp.display()))?;
        f.write_all(&bytes)
            .map_err(|e| format!("writing {}: {e}", tmp.display()))?;
        f.sync_all()
            .map_err(|e| format!("syncing {}: {e}", tmp.display()))?;
        drop(f);
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| format!("renaming into {}: {e}", self.path.display()))?;
        Ok(())
    }

    /// How many passkeys are enrolled. Used by the login page to decide whether
    /// to offer the passkey button or push you to the bootstrap-token path.
    pub fn credential_count(&self) -> usize {
        self.state.lock().unwrap().credentials.len()
    }

    /// Labels + enrollment times, for the exposure report and the manage page.
    pub fn credential_summary(&self) -> Vec<(String, u64)> {
        self.state
            .lock()
            .unwrap()
            .credentials
            .iter()
            .map(|c| (c.label.clone(), c.added))
            .collect()
    }

    /// Labels + issue times of live device tokens.
    pub fn device_summary(&self) -> Vec<(String, u64)> {
        self.state
            .lock()
            .unwrap()
            .devices
            .iter()
            .map(|d| (d.label.clone(), d.added))
            .collect()
    }

    // ---- registration (private surface) ---------------------------------

    /// Begin enrolling a new passkey. Returns the JSON the browser hands to
    /// `navigator.credentials.create()`, plus a ceremony id to echo back.
    pub fn start_registration(&self, label: &str) -> Result<serde_json::Value, String> {
        let existing: Vec<CredentialID> = self
            .state
            .lock()
            .unwrap()
            .credentials
            .iter()
            .map(|c| c.passkey.cred_id().clone())
            .collect();
        let (challenge, reg_state) = self
            .webauthn
            .start_passkey_registration(
                self.user_id,
                &self.cfg.user_name,
                &self.cfg.user_name,
                // Exclude what is already enrolled so the authenticator offers
                // to add a NEW credential rather than silently overwriting.
                if existing.is_empty() { None } else { Some(existing) },
            )
            .map_err(|e| format!("start registration: {e}"))?;

        let id = random_id()?;
        {
            let mut states = self.reg_states.lock().unwrap();
            prune(&mut states, CEREMONY_TTL);
            states.insert(id.clone(), (Instant::now(), reg_state));
        }
        Ok(serde_json::json!({
            "ceremony": id,
            "label": label,
            "options": challenge,
        }))
    }

    /// Finish enrollment: verify the attestation and persist the credential.
    pub fn finish_registration(
        &self,
        ceremony: &str,
        label: &str,
        credential: RegisterPublicKeyCredential,
    ) -> Result<(), String> {
        let reg_state = {
            let mut states = self.reg_states.lock().unwrap();
            prune(&mut states, CEREMONY_TTL);
            // Single-use: taking it out means a replayed ceremony id fails.
            states
                .remove(ceremony)
                .ok_or("unknown or expired registration ceremony")?
                .1
        };
        let passkey = self
            .webauthn
            .finish_passkey_registration(&credential, &reg_state)
            .map_err(|e| format!("registration failed: {e}"))?;

        let label = if label.trim().is_empty() {
            "passkey".to_string()
        } else {
            label.trim().to_string()
        };
        {
            let mut store = self.state.lock().unwrap();
            if store
                .credentials
                .iter()
                .any(|c| c.passkey.cred_id() == passkey.cred_id())
            {
                return Err("that credential is already enrolled".into());
            }
            store.credentials.push(Enrolled {
                label,
                added: now_secs(),
                passkey,
            });
        }
        self.persist()
    }

    // ---- authentication (public surface) --------------------------------

    /// Begin a login. Public by necessity: you cannot present a credential you
    /// have not been challenged for. Leaks only the credential ids already
    /// enrolled, which is inherent to the WebAuthn ceremony.
    pub fn start_authentication(&self) -> Result<serde_json::Value, String> {
        let creds: Vec<Passkey> = self
            .state
            .lock()
            .unwrap()
            .credentials
            .iter()
            .map(|c| c.passkey.clone())
            .collect();
        if creds.is_empty() {
            return Err("no passkeys are enrolled yet".into());
        }
        let (challenge, auth_state) = self
            .webauthn
            .start_passkey_authentication(&creds)
            .map_err(|e| format!("start authentication: {e}"))?;
        let id = random_id()?;
        {
            let mut states = self.auth_states.lock().unwrap();
            prune(&mut states, CEREMONY_TTL);
            states.insert(id.clone(), (Instant::now(), auth_state));
        }
        Ok(serde_json::json!({ "ceremony": id, "options": challenge }))
    }

    /// Finish a login. On success returns a signed session token (also set as a
    /// cookie by the caller) and updates the stored signature counter.
    pub fn finish_authentication(
        &self,
        ceremony: &str,
        credential: PublicKeyCredential,
    ) -> Result<String, String> {
        let auth_state = {
            let mut states = self.auth_states.lock().unwrap();
            prune(&mut states, CEREMONY_TTL);
            states
                .remove(ceremony)
                .ok_or("unknown or expired login ceremony")?
                .1
        };
        let result = self
            .webauthn
            .finish_passkey_authentication(&credential, &auth_state)
            .map_err(|e| format!("login failed: {e}"))?;

        // Persist the signature counter so a cloned authenticator replaying an
        // old counter is caught by webauthn-rs on the next assertion.
        let mut changed = false;
        {
            let mut store = self.state.lock().unwrap();
            for c in store.credentials.iter_mut() {
                if c.passkey.cred_id() == result.cred_id() {
                    if c.passkey.update_credential(&result).is_some() {
                        changed = true;
                    }
                }
            }
        }
        if changed {
            self.persist()?;
        }
        Ok(self.mint_session())
    }

    // ---- sessions --------------------------------------------------------

    /// Mint a signed session token: `base64url(exp)` + "." + base64url(HMAC).
    /// Stateless on purpose, so a restart does not drop live sessions and there
    /// is no session table to grow or leak.
    fn mint_session(&self) -> String {
        let exp = now_secs() + self.cfg.session_ttl_secs;
        let payload = B64.encode(exp.to_string().as_bytes());
        let sig = self.sign(payload.as_bytes());
        format!("{payload}.{sig}")
    }

    /// Mint a session for a caller who just proved possession of the bootstrap
    /// token. Deliberately the same object a passkey login produces: the
    /// browser ends up holding a signed, expiring session rather than the raw
    /// shared secret, which the documented `gatekeeper=<token>` cookie did not
    /// manage.
    pub fn mint_session_for_bootstrap(&self) -> String {
        self.mint_session()
    }

    fn sign(&self, data: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.session_key)
            .expect("HMAC accepts any key length");
        mac.update(data);
        B64.encode(mac.finalize().into_bytes())
    }

    /// Verify a session cookie value: signature first (constant-time), then
    /// expiry. Returns false on anything malformed.
    pub fn verify_session(&self, token: &str) -> bool {
        let Some((payload, sig)) = token.split_once('.') else {
            return false;
        };
        let expected = self.sign(payload.as_bytes());
        // Compare the base64 of the MACs; both are fixed-length so there is no
        // length side channel.
        if !bool::from(expected.as_bytes().ct_eq(sig.as_bytes())) {
            return false;
        }
        let Ok(raw) = B64.decode(payload) else {
            return false;
        };
        let Ok(text) = std::str::from_utf8(&raw) else {
            return false;
        };
        let Ok(exp) = text.parse::<u64>() else {
            return false;
        };
        exp > now_secs()
    }

    /// The cookie attributes for a freshly minted session. `HttpOnly` matters
    /// more here than for the bootstrap cookie, because the login page ships
    /// JavaScript on the same origin.
    pub fn session_cookie(&self, token: &str) -> String {
        format!(
            "gk_session={token}; Path=/; Max-Age={}; HttpOnly; Secure; SameSite=Lax",
            self.cfg.session_ttl_secs
        )
    }

    // ---- device flow (command line) --------------------------------------

    /// Start a device-authorization request. The CLI calls this, shows the user
    /// code, and then polls. Public: it hands out nothing but a pending slot,
    /// and nothing is issued until a human approves it with a passkey.
    pub fn device_start(&self) -> Result<serde_json::Value, String> {
        let device_code = random_id()?;
        let user_code = random_user_code()?;
        {
            let mut devices = self.devices.lock().unwrap();
            devices.retain(|_, d| d.created.elapsed() < DEVICE_TTL);
            devices.insert(
                device_code.clone(),
                DeviceRequest {
                    user_code: user_code.clone(),
                    created: Instant::now(),
                    approved: None,
                },
            );
        }
        Ok(serde_json::json!({
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": format!("{}/login", self.cfg.origin.trim_end_matches('/')),
            "verification_uri_complete":
                format!("{}/login?code={user_code}", self.cfg.origin.trim_end_matches('/')),
            "interval": DEVICE_POLL_INTERVAL,
            "expires_in": DEVICE_TTL.as_secs(),
        }))
    }

    /// Poll a device request. Returns the token exactly once, then forgets the
    /// request so the same device_code cannot re-collect it.
    pub fn device_poll(&self, device_code: &str) -> serde_json::Value {
        let mut devices = self.devices.lock().unwrap();
        devices.retain(|_, d| d.created.elapsed() < DEVICE_TTL);
        match devices.get_mut(device_code) {
            None => serde_json::json!({ "error": "expired_token" }),
            Some(req) if req.approved.is_none() => {
                serde_json::json!({ "error": "authorization_pending" })
            }
            Some(_) => {
                let req = devices.remove(device_code).unwrap();
                serde_json::json!({ "token": req.approved.unwrap() })
            }
        }
    }

    /// Approve a pending device request by its user code, minting a device
    /// token. Called only from an authenticated context (see `main.rs`), which
    /// is what makes the whole flow safe.
    pub fn device_approve(&self, user_code: &str, label: &str) -> Result<(), String> {
        let token = random_token()?;
        let label = if label.trim().is_empty() {
            "cli".to_string()
        } else {
            label.trim().to_string()
        };
        {
            let mut devices = self.devices.lock().unwrap();
            devices.retain(|_, d| d.created.elapsed() < DEVICE_TTL);
            let entry = devices
                .values_mut()
                .find(|d| d.user_code.eq_ignore_ascii_case(user_code.trim()))
                .ok_or("no pending device request with that code")?;
            if entry.approved.is_some() {
                return Err("that code was already approved".into());
            }
            entry.approved = Some(token.clone());
        }
        {
            let mut store = self.state.lock().unwrap();
            store.devices.push(DeviceToken {
                label,
                added: now_secs(),
                hash: hash_hex(&token),
            });
        }
        self.persist()
    }

    /// True if `presented` matches any issued device token. Constant-time
    /// against every stored hash, and it always checks all of them so the
    /// number of tokens is not observable through timing.
    pub fn verify_device_token(&self, presented: &str) -> bool {
        let got = hash_hex(presented);
        let store = self.state.lock().unwrap();
        let mut hit = false;
        for d in store.devices.iter() {
            hit |= bool::from(got.as_bytes().ct_eq(d.hash.as_bytes()));
        }
        hit
    }

    /// Revoke a device token or an enrolled passkey by label.
    pub fn revoke(&self, kind: &str, label: &str) -> Result<usize, String> {
        let removed = {
            let mut store = self.state.lock().unwrap();
            match kind {
                "device" => {
                    let before = store.devices.len();
                    store.devices.retain(|d| d.label != label);
                    before - store.devices.len()
                }
                "passkey" => {
                    let before = store.credentials.len();
                    store.credentials.retain(|c| c.label != label);
                    before - store.credentials.len()
                }
                other => return Err(format!("unknown credential kind {other:?}")),
            }
        };
        if removed > 0 {
            self.persist()?;
        }
        Ok(removed)
    }

    // ---- native app ------------------------------------------------------

    /// The Apple associated-domains file, or `None` if no app ids are
    /// configured. Serving this publicly is what lets a signed macOS/iOS app
    /// use the SAME passkey as Safari via `ASAuthorization`. It contains only
    /// app ids you put in the config, never a secret.
    pub fn apple_app_site_association(&self) -> Option<String> {
        if self.cfg.apple_app_ids.is_empty() {
            return None;
        }
        Some(
            serde_json::json!({
                "webcredentials": { "apps": self.cfg.apple_app_ids }
            })
            .to_string(),
        )
    }

    pub fn config(&self) -> &PasskeyConfig {
        &self.cfg
    }
}

/// Drop ceremony entries older than `ttl`, so a flood of abandoned ceremonies
/// cannot grow the map without bound.
fn prune<T>(map: &mut HashMap<String, (Instant, T)>, ttl: Duration) {
    map.retain(|_, (t, _)| t.elapsed() < ttl);
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hash_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Fill `buf` with OS randomness. We read /dev/urandom directly rather than add
/// a rand dependency: this is the only randomness the gate needs.
fn getrandom(buf: &mut [u8]) -> Result<(), String> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| format!("opening /dev/urandom: {e}"))?;
    f.read_exact(buf)
        .map_err(|e| format!("reading /dev/urandom: {e}"))
}

fn random_id() -> Result<String, String> {
    let mut b = [0u8; 16];
    getrandom(&mut b)?;
    Ok(B64.encode(b))
}

fn random_token() -> Result<String, String> {
    let mut b = [0u8; 32];
    getrandom(&mut b)?;
    Ok(B64.encode(b))
}

/// A short, human-transcribable code like `KX7M-9QTD`. Avoids characters that
/// look alike when read aloud or off a terminal.
fn random_user_code() -> Result<String, String> {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut b = [0u8; 8];
    getrandom(&mut b)?;
    let s: String = b
        .iter()
        .map(|x| ALPHABET[(*x as usize) % ALPHABET.len()] as char)
        .collect();
    Ok(format!("{}-{}", &s[..4], &s[4..]))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_code_shape() {
        let c = random_user_code().unwrap();
        assert_eq!(c.len(), 9);
        assert_eq!(c.as_bytes()[4], b'-');
        assert!(c.chars().filter(|c| *c != '-').all(|c| c.is_ascii_alphanumeric()));
        // No look-alike characters.
        assert!(!c.contains('O') && !c.contains('I') && !c.contains('0') && !c.contains('1'));
    }

    #[test]
    fn hash_is_stable_and_distinct() {
        assert_eq!(hash_hex("abc"), hash_hex("abc"));
        assert_ne!(hash_hex("abc"), hash_hex("abd"));
        assert_eq!(hash_hex("abc").len(), 64);
    }

    #[test]
    fn prune_drops_nothing_when_fresh() {
        let mut m: HashMap<String, (Instant, u8)> = HashMap::new();
        m.insert("a".into(), (Instant::now(), 1));
        prune(&mut m, Duration::from_secs(60));
        assert_eq!(m.len(), 1);
        prune(&mut m, Duration::from_nanos(1));
        assert_eq!(m.len(), 0);
    }
}
