//! Shared-secret authentication.
//!
//! A single bearer token gates every private route. The token is presented
//! either as `Authorization: Bearer <token>` (preferred, for APIs) or as a
//! `gatekeeper=<token>` cookie (for browsers). The header wins if both are
//! present.
//!
//! Comparison is constant-time (`subtle`) so an attacker can't recover the
//! token a byte at a time via response-timing. We also hash both sides to a
//! fixed length first, which removes the length-dependent early return that a
//! naive `ct_eq` on differing lengths would otherwise have.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Holds the expected token in a form that compares in constant time.
#[derive(Clone)]
pub struct Authenticator {
    expected: [u8; 32],
}

impl Authenticator {
    pub fn new(token: &str) -> Self {
        Authenticator {
            expected: digest(token.as_bytes()),
        }
    }

    /// True iff `presented` matches the expected token. Constant-time in the
    /// token contents (both sides are hashed to 32 bytes, then compared with
    /// `ct_eq`, so neither length nor content branches early).
    pub fn verify(&self, presented: &str) -> bool {
        let got = digest(presented.as_bytes());
        got.ct_eq(&self.expected).into()
    }

    /// Extract a token from the request headers and verify it. Returns true on
    /// a valid token. The header (`Authorization: Bearer`) takes precedence
    /// over the cookie; if an Authorization header is present we use it and do
    /// NOT fall back to the cookie (so a forged/blank header can't be bypassed).
    pub fn check_headers(&self, headers: &[tiny_http::Header]) -> bool {
        if let Some(auth) = header_value(headers, "authorization") {
            return match bearer(auth) {
                Some(tok) => self.verify(tok),
                None => false,
            };
        }
        if let Some(cookie) = header_value(headers, "cookie") {
            if let Some(tok) = cookie_token(cookie) {
                return self.verify(tok);
            }
        }
        false
    }
}

/// Find the first header whose field name equals `name` (case-insensitive),
/// returning its value as a `&str`.
fn header_value<'a>(headers: &'a [tiny_http::Header], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

/// Pull the token out of an `Authorization: Bearer <tok>` value.
fn bearer(value: &str) -> Option<&str> {
    let tok = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?
        .trim();
    if tok.is_empty() {
        None
    } else {
        Some(tok)
    }
}

/// Pull the `gatekeeper=<tok>` value out of a Cookie header value.
fn cookie_token(value: &str) -> Option<&str> {
    cookie_value(value, "gatekeeper")
}

/// Pull a named cookie's value out of a Cookie header value.
fn cookie_value<'a>(value: &'a str, name: &str) -> Option<&'a str> {
    let prefix = format!("{name}=");
    for pair in value.split(';') {
        let pair = pair.trim();
        if let Some(tok) = pair.strip_prefix(&prefix) {
            let tok = tok.trim();
            if !tok.is_empty() {
                return Some(tok);
            }
        }
    }
    None
}

/// The complete credential check for a request: the shared bootstrap token, a
/// per-device token minted by the device flow, or a passkey session cookie.
///
/// This type exists so that widening authentication does **not** widen the
/// safety core. `Router::decide` still asks one yes/no question ("was auth
/// ok?"); all this does is give that question three ways to answer yes instead
/// of one. `tests/safety.rs` is unchanged and still proves the property.
///
/// The header-beats-cookie precedence from [`Authenticator::check_headers`] is
/// preserved exactly: if an `Authorization` header is present we decide on it
/// alone and never fall back to a cookie, so a stale or forged header cannot be
/// rescued by a good cookie sitting in the browser.
#[derive(Clone)]
pub struct Verifier {
    token: Option<Authenticator>,
    passkeys: Option<std::sync::Arc<crate::passkey::PasskeyEngine>>,
}

impl Verifier {
    pub fn new(
        token: Option<Authenticator>,
        passkeys: Option<std::sync::Arc<crate::passkey::PasskeyEngine>>,
    ) -> Self {
        Verifier { token, passkeys }
    }

    /// True if at least one kind of credential is configured. Boot refuses to
    /// serve a private route when this is false — the fail-closed invariant,
    /// now stated over all credential kinds rather than just the token.
    pub fn is_configured(&self) -> bool {
        self.token.is_some() || self.passkeys.is_some()
    }

    /// True if the shared bootstrap token is configured. The device flow can
    /// mint device tokens and passkeys can mint sessions, but enrolling the
    /// very first passkey has to start somewhere, and this is where.
    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    /// Verify a bare token string presented as a bearer credential.
    pub fn verify_bearer(&self, presented: &str) -> bool {
        let mut ok = false;
        if let Some(a) = &self.token {
            ok |= a.verify(presented);
        }
        if let Some(p) = &self.passkeys {
            ok |= p.verify_device_token(presented);
        }
        ok
    }

    /// True only for the shared bootstrap token, ignoring device tokens and
    /// sessions. Used by the login page's break-glass path, which mints a
    /// cookie and must not accept a device token as proof of a human.
    pub fn verify_bootstrap(&self, presented: &str) -> bool {
        match &self.token {
            Some(a) => a.verify(presented),
            None => false,
        }
    }

    pub fn check_headers(&self, headers: &[tiny_http::Header]) -> bool {
        // Machine path. Bootstrap token or device token; both are bearer.
        if let Some(auth) = header_value(headers, "authorization") {
            let Some(presented) = bearer(auth) else {
                return false;
            };
            // Deliberately not short-circuiting: check every credential kind so
            // the response time does not reveal WHICH kind matched, or how many
            // device tokens exist.
            return self.verify_bearer(presented);
        }
        // Browser path. A passkey session, or the bootstrap token as a cookie
        // (kept as break-glass so a lost passkey never locks you out).
        if let Some(cookie) = header_value(headers, "cookie") {
            let mut ok = false;
            if let Some(p) = &self.passkeys {
                if let Some(sess) = cookie_value(cookie, "gk_session") {
                    ok |= p.verify_session(sess);
                }
            }
            if let Some(a) = &self.token {
                if let Some(tok) = cookie_value(cookie, "gatekeeper") {
                    ok |= a.verify(tok);
                }
            }
            return ok;
        }
        false
    }
}

/// Fixed-length digest of a presented token, so the constant-time compare has
/// no length side channel.
///
/// This was a hand-rolled 4-lane FNV/splitmix mixer, on the reasoning that a
/// token equality check only needs a fixed-width reduction and not hash
/// secrecy. That reasoning is true as far as it goes, but the bootstrap token
/// is the highest-value credential here (it is what enrolls the first passkey),
/// this same file already depends on SHA-256 for device tokens and HMAC-SHA256
/// for sessions, and a hand-rolled mixer has no analyzed preimage or collision
/// resistance. There was no upside to keeping it.
fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(field: &str, value: &str) -> tiny_http::Header {
        tiny_http::Header::from_bytes(field.as_bytes(), value.as_bytes()).unwrap()
    }

    #[test]
    fn verify_correct_and_wrong() {
        let a = Authenticator::new("s3cr3t-token-value");
        assert!(a.verify("s3cr3t-token-value"));
        assert!(!a.verify("s3cr3t-token-valuE"));
        assert!(!a.verify("wrong"));
        assert!(!a.verify(""));
        // Different-length wrong token still rejected (no length leak path).
        assert!(!a.verify("s3cr3t-token-value-extra"));
    }

    #[test]
    fn header_bearer() {
        let a = Authenticator::new("tok");
        assert!(a.check_headers(&[hdr("Authorization", "Bearer tok")]));
        assert!(!a.check_headers(&[hdr("Authorization", "Bearer nope")]));
        assert!(!a.check_headers(&[hdr("Authorization", "tok")])); // missing scheme
    }

    #[test]
    fn cookie_fallback() {
        let a = Authenticator::new("tok");
        assert!(a.check_headers(&[hdr("Cookie", "foo=bar; gatekeeper=tok; baz=1")]));
        assert!(!a.check_headers(&[hdr("Cookie", "gatekeeper=nope")]));
    }

    #[test]
    fn header_wins_over_cookie() {
        let a = Authenticator::new("tok");
        // Good header, bad cookie -> allowed (header checked first).
        assert!(a.check_headers(&[
            hdr("Authorization", "Bearer tok"),
            hdr("Cookie", "gatekeeper=nope"),
        ]));
        // Bad header present -> we use the header and do NOT fall back to a
        // good cookie. This prevents a stale/forged header being bypassed.
        assert!(!a.check_headers(&[
            hdr("Authorization", "Bearer nope"),
            hdr("Cookie", "gatekeeper=tok"),
        ]));
    }

    #[test]
    fn no_credentials() {
        let a = Authenticator::new("tok");
        assert!(!a.check_headers(&[]));
    }

    #[test]
    fn cookie_value_picks_the_right_name() {
        let c = "a=1; gk_session=SESS; gatekeeper=TOK; z=9";
        assert_eq!(cookie_value(c, "gk_session"), Some("SESS"));
        assert_eq!(cookie_value(c, "gatekeeper"), Some("TOK"));
        assert_eq!(cookie_value(c, "missing"), None);
        // A name that another cookie name ends with must not match it.
        assert_eq!(cookie_value("xgatekeeper=NO", "gatekeeper"), None);
    }

    #[test]
    fn verifier_token_only_matches_authenticator() {
        let v = Verifier::new(Some(Authenticator::new("tok")), None);
        assert!(v.is_configured());
        assert!(v.has_token());
        assert!(v.check_headers(&[hdr("Authorization", "Bearer tok")]));
        assert!(!v.check_headers(&[hdr("Authorization", "Bearer nope")]));
        assert!(v.check_headers(&[hdr("Cookie", "gatekeeper=tok")]));
        assert!(!v.check_headers(&[hdr("Cookie", "gk_session=anything")]));
        assert!(!v.check_headers(&[]));
    }

    #[test]
    fn verifier_with_no_credentials_denies_everything() {
        let v = Verifier::new(None, None);
        assert!(!v.is_configured());
        assert!(!v.check_headers(&[hdr("Authorization", "Bearer tok")]));
        assert!(!v.check_headers(&[hdr("Cookie", "gatekeeper=tok")]));
    }

    #[test]
    fn verifier_keeps_header_precedence() {
        let v = Verifier::new(Some(Authenticator::new("tok")), None);
        // Bad header present -> denied even though the cookie is good.
        assert!(!v.check_headers(&[
            hdr("Authorization", "Bearer nope"),
            hdr("Cookie", "gatekeeper=tok"),
        ]));
    }

    #[test]
    fn verify_bootstrap_ignores_everything_but_the_token() {
        let v = Verifier::new(Some(Authenticator::new("tok")), None);
        assert!(v.verify_bootstrap("tok"));
        assert!(!v.verify_bootstrap("nope"));
        let none = Verifier::new(None, None);
        assert!(!none.verify_bootstrap("tok"));
    }
}
