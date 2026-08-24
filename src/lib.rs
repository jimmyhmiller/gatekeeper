//! gatekeeper library surface — the pieces the binary wires together and the
//! integration tests exercise. See `main.rs` for the runnable server.

pub mod auth;
pub mod config;
pub mod function;
pub mod login;
pub mod passkey;
pub mod proxy;
pub mod ratelimit;
pub mod reply;
pub mod route;
pub mod schedule;
pub mod serve;
