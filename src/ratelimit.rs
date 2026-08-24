//! Per-client rate limiting for the public authentication endpoints.
//!
//! The gate deliberately has no general-purpose rate limiting; the README says
//! so. That was a defensible call while nothing public accepted a credential.
//! Adding passkeys changed it: `/login/token` is a public online oracle for the
//! bootstrap token, and `/login/challenge` and `/login/device/start` allocate
//! server-side state for anyone who asks. Constant-time comparison stops a
//! token being recovered byte-by-byte; it does nothing about unlimited guesses.
//!
//! So this is narrow on purpose. It applies to four reserved paths and nothing
//! else. It is not a general request limiter and should not grow into one.
//!
//! The client identity is the TCP peer address. gatekeeper terminates TLS
//! itself, so that is the real remote address — and `X-Forwarded-For` is
//! deliberately **not** consulted, because any client can send that header and
//! trusting it would make the limiter trivially bypassable.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How many attempts are allowed in a window, and how long the window is.
pub struct Policy {
    pub max: u32,
    pub per: Duration,
}

/// Attempts against a credential: `/login/token`, `/login/verify`. Tight,
/// because each one is a guess. A success calls [`RateLimiter::reset`], so this
/// budget is really "failures in a row", and normal use never approaches it.
pub const CREDENTIAL: Policy = Policy {
    max: 10,
    per: Duration::from_secs(300),
};

/// Requests that allocate server-side state: `/login/challenge`,
/// `/login/device/start`. Looser, since a real person retrying a flaky Touch ID
/// prompt should never see it.
pub const CEREMONY: Policy = Policy {
    max: 30,
    per: Duration::from_secs(60),
};

/// Never track more clients than this. Prevents the limiter itself from
/// becoming the memory-exhaustion vector it exists to prevent. On overflow we
/// prune expired entries first and only then refuse to track more; an untracked
/// client is *allowed*, because failing closed here would let anyone lock
/// everyone out by filling the table.
const MAX_TRACKED: usize = 10_000;

struct Window {
    start: Instant,
    count: u32,
}

pub struct RateLimiter {
    windows: Mutex<HashMap<(IpAddr, &'static str), Window>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Count one attempt. Returns `Some(retry_after)` if the caller is over
    /// budget and should be refused.
    ///
    /// A client we cannot identify (no peer address) is allowed through: that
    /// only happens if the listener could not report a peer, and refusing on
    /// that basis would break the endpoint rather than protect it.
    pub fn check(&self, client: Option<IpAddr>, bucket: &'static str, policy: &Policy) -> Option<Duration> {
        let ip = client?;
        let mut windows = self.windows.lock().ok()?;
        let now = Instant::now();

        if windows.len() >= MAX_TRACKED {
            windows.retain(|_, w| now.duration_since(w.start) < policy.per);
            if windows.len() >= MAX_TRACKED {
                return None;
            }
        }

        let w = windows.entry((ip, bucket)).or_insert(Window {
            start: now,
            count: 0,
        });
        // Window expired: start a fresh one rather than sliding, which keeps
        // this to two fields per client.
        if now.duration_since(w.start) >= policy.per {
            w.start = now;
            w.count = 0;
        }
        w.count += 1;
        if w.count > policy.max {
            Some(policy.per - now.duration_since(w.start))
        } else {
            None
        }
    }

    /// Forget a client's attempts in one bucket. Called after a *successful*
    /// authentication, so signing in correctly does not slowly consume the
    /// budget that exists to catch someone guessing.
    pub fn reset(&self, client: Option<IpAddr>, bucket: &'static str) {
        let Some(ip) = client else { return };
        if let Ok(mut windows) = self.windows.lock() {
            windows.remove(&(ip, bucket));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
    const OTHER: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));
    const FAST: Policy = Policy {
        max: 3,
        per: Duration::from_secs(60),
    };

    #[test]
    fn allows_up_to_the_limit_then_refuses() {
        let rl = RateLimiter::new();
        for i in 0..3 {
            assert!(rl.check(Some(IP), "b", &FAST).is_none(), "attempt {i} should pass");
        }
        let retry = rl.check(Some(IP), "b", &FAST).expect("4th attempt is refused");
        assert!(retry <= Duration::from_secs(60) && retry > Duration::ZERO);
    }

    #[test]
    fn clients_are_independent() {
        let rl = RateLimiter::new();
        for _ in 0..4 {
            let _ = rl.check(Some(IP), "b", &FAST);
        }
        assert!(rl.check(Some(OTHER), "b", &FAST).is_none(), "one client must not limit another");
    }

    #[test]
    fn buckets_are_independent() {
        let rl = RateLimiter::new();
        for _ in 0..4 {
            let _ = rl.check(Some(IP), "cred", &FAST);
        }
        assert!(rl.check(Some(IP), "ceremony", &FAST).is_none());
    }

    #[test]
    fn success_clears_the_budget() {
        let rl = RateLimiter::new();
        for _ in 0..3 {
            let _ = rl.check(Some(IP), "b", &FAST);
        }
        rl.reset(Some(IP), "b");
        assert!(rl.check(Some(IP), "b", &FAST).is_none(), "a success must forgive prior attempts");
    }

    #[test]
    fn unidentifiable_client_is_allowed() {
        let rl = RateLimiter::new();
        for _ in 0..50 {
            assert!(rl.check(None, "b", &FAST).is_none());
        }
    }

    #[test]
    fn expired_window_resets() {
        let rl = RateLimiter::new();
        const INSTANT: Policy = Policy { max: 1, per: Duration::from_millis(1) };
        assert!(rl.check(Some(IP), "b", &INSTANT).is_none());
        assert!(rl.check(Some(IP), "b", &INSTANT).is_some(), "second within the window is refused");
        std::thread::sleep(Duration::from_millis(3));
        assert!(rl.check(Some(IP), "b", &INSTANT).is_none(), "a new window starts clean");
    }
}
