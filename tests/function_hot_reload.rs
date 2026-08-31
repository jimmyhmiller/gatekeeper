//! Verifies that a function dylib is hot-reloaded when the file on disk changes
//! (atomic rename), so shipping a new build of a function takes effect on the
//! next request — no gate restart, no config reload.
//!
//! Uses the two example dylibs as "two versions" of a function at one path:
//! `libhello_fn.so` (v1, serves an HTML greeting) and `libanalytics_fn.so` (v2,
//! returns 404 for `/hello` since it has no such endpoint). We invoke through a
//! single `FunctionRegistry` at a fixed path, then atomically rename v2 over the
//! path and invoke again; the registry must serve v2 without being recreated.
//!
//! IMPORTANT: deploy is via rename(2), never an in-place overwrite of a loaded
//! `.so` (that corrupts the live mapping and crashes the process). The registry
//! keys its staleness check on (mtime, size, inode); rename changes the inode.

use std::path::{Path, PathBuf};

use gatekeeper::function::FunctionRegistry;

fn target_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(if cfg!(debug_assertions) { "debug" } else { "release" })
}

fn dylib_name(stem: &str) -> String {
    if cfg!(target_os = "windows") {
        format!("{stem}.dll")
    } else if cfg!(target_os = "macos") {
        format!("lib{stem}.dylib")
    } else {
        format!("lib{stem}.so")
    }
}

fn require(p: &Path) -> PathBuf {
    assert!(
        p.exists(),
        "missing {} — run `cargo build -p hello-fn -p analytics-fn` first",
        p.display()
    );
    p.to_path_buf()
}

/// Atomically place `src`'s contents at `dst` via a temp file + rename, the
/// only safe way to replace a possibly-loaded dylib.
fn deploy(src: &Path, dst: &Path) {
    let tmp = dst.with_extension("so.new");
    std::fs::copy(src, &tmp).expect("copy to temp");
    std::fs::rename(&tmp, dst).expect("atomic rename into place");
}

#[test]
fn rebuilt_dylib_is_picked_up_without_restart() {
    let hello = require(&target_dir().join(dylib_name("hello_fn")));
    let analytics = require(&target_dir().join(dylib_name("analytics_fn")));

    // A unique per-test path under the target dir (avoids cross-test races).
    let live = target_dir().join("libhotswap_test.so");
    let _ = std::fs::remove_file(&live);

    // v1 = hello.
    deploy(&hello, &live);
    let reg = FunctionRegistry::new();
    let r1 = reg.invoke(&live, "GET", "/hello", "", &[], b"");
    assert_eq!(r1.status, 200, "v1 hello should serve 200");
    let body1 = String::from_utf8_lossy(&r1.body);
    assert!(
        body1.contains("hello from a gatekeeper function"),
        "v1 should be the hello handler, got: {body1}"
    );

    // Deploy v2 = analytics over the same path (atomic rename). The analytics
    // handler has no "/hello" endpoint, so it returns 404 — a behavior change
    // that proves the NEW code is running.
    deploy(&analytics, &live);
    let r2 = reg.invoke(&live, "GET", "/hello", "", &[], b"");
    let body2 = String::from_utf8_lossy(&r2.body).to_string();

    // The claim under test is "v2 is live", and v1 is unmistakable: 200 plus
    // the hello body. Anything else proves the swap happened.
    //
    // We do NOT unconditionally require 404 here, because the analytics handler
    // reaches for datalog-db, which needs DATALOG_AUTH_TOKEN in the
    // environment. Without it this legitimately answers 502 ("handshake
    // rejected: authentication failed") — still not v1, so the hot swap still
    // demonstrably worked, but the old assertion went red and blamed the
    // reload for a missing credential. When the token IS present we pin the
    // exact 404, so nothing is lost where it can actually be checked.
    assert_ne!(
        r2.status, 200,
        "after hot-swap the v1 handler must be gone, but it still answered 200: {body2:?}"
    );
    assert!(
        !body2.contains("hello from a gatekeeper function"),
        "after hot-swap the v1 body must be gone, got: {body2:?}"
    );
    if std::env::var_os("DATALOG_AUTH_TOKEN").is_some() {
        assert_eq!(
            r2.status, 404,
            "with DATALOG_AUTH_TOKEN set, the analytics handler should 404 on /hello; \
             got {} with body {body2:?}",
            r2.status
        );
    } else {
        eprintln!(
            "note: DATALOG_AUTH_TOKEN is unset, so the exact 404 is not checked \
             (got {}). Set it to run the strict form.",
            r2.status
        );
    }

    // And swapping BACK to v1 is picked up too (not a one-way latch).
    deploy(&hello, &live);
    let r3 = reg.invoke(&live, "GET", "/hello", "", &[], b"");
    assert_eq!(r3.status, 200, "swapping back to hello should serve 200 again");
    assert!(String::from_utf8_lossy(&r3.body).contains("hello from a gatekeeper function"));

    let _ = std::fs::remove_file(&live);
}

#[test]
fn unchanged_dylib_is_served_from_cache() {
    // Sanity: repeated invokes of an unchanged file must keep working (the fast
    // path) — the stat-per-call must not break the warm cache.
    let hello = require(&target_dir().join(dylib_name("hello_fn")));
    let live = target_dir().join("libhotswap_cache_test.so");
    let _ = std::fs::remove_file(&live);
    deploy(&hello, &live);

    let reg = FunctionRegistry::new();
    for _ in 0..5 {
        let r = reg.invoke(&live, "GET", "/x", "", &[], b"");
        assert_eq!(r.status, 200);
    }
    let _ = std::fs::remove_file(&live);
}

#[test]
fn service_dylib_is_pinned_when_the_file_changes() {
    let hello = require(&target_dir().join(dylib_name("hello_fn")));
    let analytics = require(&target_dir().join(dylib_name("analytics_fn")));
    let live = target_dir().join("libservice_pin_test.so");
    let _ = std::fs::remove_file(&live);
    deploy(&hello, &live);

    let reg = std::sync::Arc::new(FunctionRegistry::new());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let reg = std::sync::Arc::clone(&reg);
        let barrier = std::sync::Arc::clone(&barrier);
        let live = live.clone();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            reg.invoke_service(
                &live,
                "GET",
                "/hello",
                "",
                &[],
                b"",
            )
        }));
    }
    for thread in threads {
        let response = thread.join().unwrap();
        assert_eq!(response.status, 200);
    }

    deploy(&analytics, &live);
    let r2 = reg.invoke_service(
        &live,
        "GET",
        "/hello",
        "",
        &[],
        b"",
    );
    assert_eq!(r2.status, 200, "service functions must not hot-reload");
    assert!(String::from_utf8_lossy(&r2.body).contains("hello from a gatekeeper function"));

    let _ = std::fs::remove_file(&live);
}
