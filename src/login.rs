//! The reserved built-in routes: passkey login, passkey registration, the CLI
//! device flow, and the Apple associated-domains file.
//!
//! These are *reserved* rather than configured, for the same reason `/describe`
//! is: a `[[route]]` in the config must not be able to shadow the login page or
//! quietly re-point registration at something else. The complete list lives in
//! [`RESERVED`], which is also what the boot exposure report prints — so every
//! path the gate answers on, built-in or configured, shows up in exactly one
//! human-readable table.
//!
//! Exactly one of these is public that would not otherwise be: `/login` and its
//! ceremony endpoints. That is unavoidable (you cannot authenticate to get the
//! ability to authenticate) and it is the entire new exposure surface of the
//! passkey feature. Registration is **not** in that set.

use crate::auth::Verifier;
use crate::passkey::PasskeyEngine;
use crate::reply::Reply;

/// A built-in path the gate answers itself.
pub struct Reserved {
    pub path: &'static str,
    /// `true` = no auth required. Kept explicit and enumerated, not derived
    /// from a prefix, so that reading this table tells you the whole story.
    pub public: bool,
    pub desc: &'static str,
}

/// Every reserved path, with its access. `/describe` is here too so the boot
/// report covers it; before passkeys existed it was invisible to that report.
pub const RESERVED: &[Reserved] = &[
    Reserved { path: "/describe", public: false, desc: "self-describing API catalog" },
    Reserved { path: "/login", public: true, desc: "passkey sign-in page" },
    Reserved { path: "/login/webauthn.js", public: true, desc: "sign-in page script" },
    Reserved { path: "/login/challenge", public: true, desc: "begin a passkey assertion" },
    Reserved { path: "/login/verify", public: true, desc: "finish a passkey assertion" },
    Reserved { path: "/login/token", public: true, desc: "break-glass: bootstrap token for a session" },
    Reserved { path: "/logout", public: true, desc: "clear the session cookie" },
    Reserved { path: "/login/device/start", public: true, desc: "CLI device flow: request a code" },
    Reserved { path: "/login/device/poll", public: true, desc: "CLI device flow: poll for approval" },
    Reserved { path: "/login/device/approve", public: false, desc: "CLI device flow: approve a code" },
    Reserved { path: "/register", public: false, desc: "enroll and revoke passkeys" },
    Reserved { path: "/register/list", public: false, desc: "list credentials" },
    Reserved { path: "/register/challenge", public: false, desc: "begin enrolling a passkey" },
    Reserved { path: "/register/verify", public: false, desc: "finish enrolling a passkey" },
    Reserved { path: "/register/revoke", public: false, desc: "revoke a credential" },
    Reserved { path: APPLE_AASA, public: true, desc: "Apple associated domains (native app)" },
];

pub const APPLE_AASA: &str = "/.well-known/apple-app-site-association";
pub const DESCRIBE_PATH: &str = "/describe";

/// Look up a normalized path in the reserved table.
pub fn lookup(path: &str) -> Option<&'static Reserved> {
    RESERVED.iter().find(|r| r.path == path)
}

/// The reserved paths that are actually live for a given configuration. When
/// passkeys are off, only `/describe` exists; when they are on but no Apple app
/// ids are configured, the associated-domains file is still not served. The
/// exposure report prints exactly this, so it can never claim a route that is
/// not really there (or hide one that is).
pub fn active(passkeys: Option<&PasskeyEngine>) -> Vec<&'static Reserved> {
    RESERVED
        .iter()
        .filter(|r| match r.path {
            DESCRIBE_PATH => true,
            APPLE_AASA => passkeys
                .map(|p| p.apple_app_site_association().is_some())
                .unwrap_or(false),
            _ => passkeys.is_some(),
        })
        .collect()
}

fn json(status: u16, value: serde_json::Value) -> Reply {
    Reply::new(status, value.to_string().into_bytes())
        .with_header("Content-Type", "application/json")
}

fn err(status: u16, message: &str) -> Reply {
    json(status, serde_json::json!({ "error": message }))
}

/// Expire a cookie: same name, empty value, `Max-Age=0`. The attributes have to
/// match the ones it was set with or the browser treats it as a different
/// cookie and quietly keeps the original.
fn expire_cookie(name: &str) -> String {
    format!("{name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
}

fn html(body: &'static str) -> Reply {
    Reply::new(200, body.as_bytes().to_vec())
        .with_header("Content-Type", "text/html; charset=utf-8")
        // The pages are self-contained: no external scripts, styles, or fonts.
        // Say so, so a future edit that reaches for a CDN fails loudly here
        // instead of quietly adding a third party to the login path.
        .with_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self' 'unsafe-inline'; \
             style-src 'unsafe-inline'; connect-src 'self'; form-action 'none'",
        )
        .with_header("Referrer-Policy", "no-referrer")
        .with_header("X-Content-Type-Options", "nosniff")
}

/// Dispatch a reserved request. `authed` says whether the caller already
/// cleared the private gate; `main.rs` enforces that before calling us, so a
/// private path reaching this function has already been authorized.
pub fn handle(
    engine: &PasskeyEngine,
    verifier: &Verifier,
    method: &str,
    path: &str,
    body: &[u8],
) -> Reply {
    // Every endpoint below except the page loads is a POST. Rejecting the wrong
    // method up front keeps a stray GET from being treated as an empty body.
    let want_post = !matches!(
        path,
        "/login" | "/login/webauthn.js" | "/register" | "/logout" | APPLE_AASA
    );
    if want_post && method != "POST" {
        return err(405, "method not allowed");
    }

    let parsed: serde_json::Value = if body.is_empty() {
        serde_json::Value::Null
    } else {
        match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => return err(400, &format!("invalid JSON body: {e}")),
        }
    };
    let field = |name: &str| -> String {
        parsed
            .get(name)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    };

    match path {
        "/login" => html(include_str!("web/login.html")),
        // Signing out is just expiring the cookies; there is no server-side
        // session table to delete, because sessions are signed rather than
        // stored. Both cookies are cleared: the passkey session and the
        // documented break-glass `gatekeeper=<token>` one, so a single visit
        // definitely leaves you unauthenticated rather than leaving whichever
        // one you did not think about still valid.
        "/logout" => Reply::status(303, "")
            .with_header("Location", "/login")
            .with_header("Set-Cookie", &expire_cookie("gk_session"))
            .with_header("Set-Cookie", &expire_cookie("gatekeeper")),
        "/register" => html(include_str!("web/register.html")),
        "/login/webauthn.js" => Reply::new(200, include_str!("web/webauthn.js").as_bytes().to_vec())
            .with_header("Content-Type", "application/javascript; charset=utf-8")
            .with_header("X-Content-Type-Options", "nosniff"),

        APPLE_AASA => match engine.apple_app_site_association() {
            // Apple requires this served as application/json over HTTPS with no
            // redirect. Absent config, `active()` never lists it and main.rs
            // never routes here, but be explicit anyway.
            Some(doc) => Reply::new(200, doc.into_bytes())
                .with_header("Content-Type", "application/json"),
            None => err(404, "not configured"),
        },

        // ---- sign in ----------------------------------------------------
        "/login/challenge" => match engine.start_authentication() {
            Ok(v) => json(200, v),
            Err(e) => err(400, &e),
        },
        "/login/verify" => {
            let ceremony = field("ceremony");
            let credential = match serde_json::from_value(
                parsed.get("credential").cloned().unwrap_or_default(),
            ) {
                Ok(c) => c,
                Err(e) => return err(400, &format!("malformed credential: {e}")),
            };
            match engine.finish_authentication(&ceremony, credential) {
                Ok(token) => json(200, serde_json::json!({ "ok": true }))
                    .with_header("Set-Cookie", &engine.session_cookie(&token)),
                Err(e) => err(401, &e),
            }
        }
        // Break-glass: prove you hold the bootstrap token and get a *session*,
        // not a cookie containing the token itself. The raw secret never lands
        // in the browser's cookie jar, which is a small but real improvement on
        // the documented `gatekeeper=<token>` cookie.
        "/login/token" => {
            let presented = field("token");
            if presented.is_empty() || !verifier.verify_bootstrap(&presented) {
                return err(401, "invalid token");
            }
            let session = engine.mint_session_for_bootstrap();
            json(200, serde_json::json!({ "ok": true }))
                .with_header("Set-Cookie", &engine.session_cookie(&session))
        }

        // ---- device flow (command line) ---------------------------------
        "/login/device/start" => match engine.device_start() {
            Ok(v) => json(200, v),
            Err(e) => err(500, &e),
        },
        "/login/device/poll" => {
            let code = field("device_code");
            let v = engine.device_poll(&code);
            // Three distinct outcomes, and the CLI loops on exactly one of
            // them. Pending is a normal state in this protocol, not a failure
            // (202: keep polling); an expired or already-collected code is a
            // real error (400: stop), because a CLI that cannot tell those
            // apart spins until its timeout instead of saying what went wrong.
            let status = match v.get("token") {
                Some(_) => 200,
                None if v.get("error").and_then(|e| e.as_str()) == Some("authorization_pending") => 202,
                None => 400,
            };
            json(status, v)
        }
        "/login/device/approve" => {
            match engine.device_approve(&field("user_code"), &field("label")) {
                Ok(()) => json(200, serde_json::json!({ "ok": true })),
                Err(e) => err(400, &e),
            }
        }

        // ---- registration (private) -------------------------------------
        "/register/list" => {
            let to_json = |v: Vec<(String, u64)>| -> Vec<serde_json::Value> {
                v.into_iter()
                    .map(|(label, added)| serde_json::json!({ "label": label, "added": added }))
                    .collect()
            };
            json(
                200,
                serde_json::json!({
                    "passkeys": to_json(engine.credential_summary()),
                    "devices": to_json(engine.device_summary()),
                }),
            )
        }
        "/register/challenge" => match engine.start_registration(&field("label")) {
            Ok(v) => json(200, v),
            Err(e) => err(400, &e),
        },
        "/register/verify" => {
            let ceremony = field("ceremony");
            let label = field("label");
            let credential = match serde_json::from_value(
                parsed.get("credential").cloned().unwrap_or_default(),
            ) {
                Ok(c) => c,
                Err(e) => return err(400, &format!("malformed credential: {e}")),
            };
            match engine.finish_registration(&ceremony, &label, credential) {
                Ok(()) => json(200, serde_json::json!({ "ok": true })),
                Err(e) => err(400, &e),
            }
        }
        "/register/revoke" => {
            match engine.revoke(&field("kind"), &field("label")) {
                Ok(0) => err(404, "no such credential"),
                Ok(n) => json(200, serde_json::json!({ "revoked": n })),
                Err(e) => err(400, &e),
            }
        }

        // lookup() gated us, so this is unreachable for real requests.
        other => err(404, &format!("no such reserved path: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_paths_are_all_private() {
        for r in RESERVED {
            if r.path.starts_with("/register") {
                assert!(!r.public, "{} must not be public", r.path);
            }
        }
    }

    #[test]
    fn device_approve_is_private_even_though_it_sits_under_login() {
        let r = lookup("/login/device/approve").expect("present");
        assert!(!r.public, "approving a device must require auth");
    }

    #[test]
    fn only_expected_paths_are_public() {
        let public: Vec<&str> = RESERVED.iter().filter(|r| r.public).map(|r| r.path).collect();
        assert_eq!(
            public,
            vec![
                "/login",
                "/login/webauthn.js",
                "/login/challenge",
                "/login/verify",
                "/login/token",
                "/logout",
                "/login/device/start",
                "/login/device/poll",
                APPLE_AASA,
            ],
            "the set of public built-ins changed; that is the whole exposure \
             surface of this feature, so it should be a deliberate edit"
        );
    }

    #[test]
    fn logout_expires_both_cookies() {
        let s = expire_cookie("gk_session");
        assert!(s.starts_with("gk_session=;"), "value must be emptied: {s}");
        assert!(s.contains("Max-Age=0"), "must expire immediately: {s}");
        // Attributes must match how the cookie was set, or the browser keeps
        // the original and the logout silently does nothing.
        assert!(s.contains("Path=/") && s.contains("HttpOnly") && s.contains("Secure"));
        assert!(s.contains("SameSite=Lax"));
    }

    #[test]
    fn logout_is_public_so_a_stale_cookie_can_always_be_cleared() {
        assert!(lookup("/logout").expect("present").public);
    }

    #[test]
    fn reserved_paths_are_unique_and_normalized() {
        let mut seen = std::collections::HashSet::new();
        for r in RESERVED {
            assert!(seen.insert(r.path), "duplicate reserved path {}", r.path);
            assert!(r.path.starts_with('/'), "{} must be absolute", r.path);
            assert!(!r.path.ends_with('/'), "{} must not end in /", r.path);
            assert_eq!(
                crate::route::Router::normalize(r.path).as_deref(),
                Some(r.path),
                "{} is not in normalized form, so it could never be matched",
                r.path
            );
        }
    }

    #[test]
    fn active_without_passkeys_is_describe_only() {
        let a = active(None);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].path, DESCRIBE_PATH);
    }
}
