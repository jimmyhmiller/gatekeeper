//! End-to-end test of the function (serverless dylib) backend through the real
//! C ABI. Builds nothing itself — it loads the already-built `hello-fn` dylib
//! and drives it the same way the gate does, exercising the full
//! marshal → dispatch → copy → free cycle across the boundary.
//!
//! Run under valgrind to validate the unsafe memory handling:
//!   cargo test --test function_abi --no-run
//!   valgrind --leak-check=full --error-exitcode=1 \
//!     ./target/debug/deps/function_abi-*  (the test binary)
//!
//! The assertions here cover behaviour; valgrind covers soundness (no leak, no
//! invalid read/write, no double free across the gate/dylib allocator split).

use std::path::PathBuf;

use gatekeeper::function::{Call, CallBody, FunctionRegistry};

/// Path to the example dylib, built by `cargo build -p hello-fn`. We locate it
/// relative to the test binary's target dir so it works in debug and release.
fn dylib_path() -> PathBuf {
    let ext = if cfg!(target_os = "macos") {
        "dylib"
    } else if cfg!(target_os = "windows") {
        "dll"
    } else {
        "so"
    };
    let name = if cfg!(target_os = "windows") {
        format!("hello_fn.{ext}")
    } else {
        format!("libhello_fn.{ext}")
    };
    // tests run from the crate root; the workspace target dir is ./target.
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        })
        .join(&name);
    assert!(
        p.exists(),
        "dylib not built at {} — run `cargo build -p hello-fn` first",
        p.display()
    );
    p
}

fn v2_dylib_path() -> PathBuf {
    let ext = if cfg!(target_os = "macos") {
        "dylib"
    } else if cfg!(target_os = "windows") {
        "dll"
    } else {
        "so"
    };
    let name = if cfg!(target_os = "windows") {
        format!("v2_compat_fn.{ext}")
    } else {
        format!("libv2_compat_fn.{ext}")
    };
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        })
        .join(name);
    assert!(
        path.exists(),
        "ABI v2 fixture not built at {} — run `cargo build -p v2-compat-fn` first",
        path.display()
    );
    path
}

fn hdr(name: &str, value: &str) -> (String, String) {
    (name.to_string(), value.to_string())
}

#[test]
fn invoke_covers_request_shapes() {
    let reg = FunctionRegistry::new();
    let lib = dylib_path();

    // Plain GET, no headers, no body -> the catch-all HTML response.
    let r = reg.invoke(&lib, Call::buffered("GET", "/anything", "", &[], &[]));
    assert_eq!(r.status, 200);
    assert!(String::from_utf8_lossy(&r.body).contains("/anything"));
    assert!(r
        .headers
        .iter()
        .any(|(k, v)| k == "Content-Type" && v.contains("text/html")));

    // Health route.
    let r = reg.invoke(&lib, Call::buffered("GET", "/health", "", &[], &[]));
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"ok");

    // Echo with headers, query and a body — exercises every borrowed field.
    let headers = [hdr("X-Test", "abc"), hdr("Accept", "application/json")];
    let r = reg.invoke(&lib, Call::buffered("POST", "/echo", "a=1&b=2", &headers, b"payload"));
    assert_eq!(r.status, 200);
    let body = String::from_utf8_lossy(&r.body);
    assert!(body.contains("\"method\":\"POST\""), "{body}");
    assert!(body.contains("\"query\":\"a=1&b=2\""), "{body}");
    assert!(body.contains("\"body\":\"payload\""), "{body}");
}

#[test]
fn describe_returns_self_description() {
    // The hello dylib exports gk_describe (ABI v2). The registry should fetch it
    // and return valid JSON naming the function and its endpoints.
    let reg = FunctionRegistry::new();
    let lib = dylib_path();
    let desc = reg
        .describe(&lib)
        .expect("hello exports gk_describe (required) -> json");
    assert!(desc.contains("\"name\":\"hello\""), "got: {desc}");
    assert!(
        desc.contains("\"/health\""),
        "should list the /health endpoint: {desc}"
    );
    // It must be valid JSON.
    let v: serde_json::Value = serde_json::from_str(&desc).expect("describe is valid JSON");
    assert!(v.get("endpoints").and_then(|e| e.as_array()).is_some());
}

#[test]
fn abi_v2_buffered_function_remains_compatible() {
    let reg = FunctionRegistry::new();
    let lib = v2_dylib_path();
    let response = reg.invoke(&lib, Call::buffered("GET", "/legacy", "", &[], &[]));
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"v2 buffered response for /legacy");
    assert!(!response.is_stream());

    let description = reg.describe(&lib).expect("ABI v2 description loads");
    assert!(description.contains("\"name\":\"v2-compat\""));
}

#[test]
fn function_without_describe_is_rejected() {
    // #[describe] is REQUIRED. The nodescribe-fn fixture has a #[handler] but no
    // #[describe], so the gate must refuse to load it (invoke -> 502, describe ->
    // Err), guaranteeing the catalog can never have an undocumented function.
    let lib = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        })
        .join("libnodescribe_fn.so");
    if !lib.exists() {
        // Built by `cargo build -p nodescribe-fn`; skip cleanly if absent.
        eprintln!("skipping: {} not built", lib.display());
        return;
    }
    let reg = FunctionRegistry::new();
    let r = reg.invoke(&lib, Call::buffered("GET", "/x", "", &[], &[]));
    assert_eq!(
        r.status, 502,
        "a function without #[describe] must fail to load"
    );
    assert!(
        reg.describe(&lib).is_err(),
        "describe() on a no-describe dylib must error, not silently succeed"
    );
}

#[test]
fn handler_panic_becomes_500_not_abort() {
    let reg = FunctionRegistry::new();
    let lib = dylib_path();
    // The /panic route panics; the SDK catches it and returns 500. If the panic
    // unwound across the ABI this test would abort the whole process instead.
    let r = reg.invoke(&lib, Call::buffered("GET", "/panic", "", &[], &[]));
    assert_eq!(r.status, 500);
}

#[test]
fn repeated_invocations_reuse_cached_library() {
    // Many calls through one registry: loads once, then reuses. Under valgrind
    // this also checks we don't leak per-call (every response is freed).
    let reg = FunctionRegistry::new();
    let lib = dylib_path();
    for i in 0..50 {
        let q = format!("n={i}");
        let r = reg.invoke(&lib, Call::buffered("GET", "/echo", &q, &[hdr("X-N", &q)], q.as_bytes()));
        assert_eq!(r.status, 200);
    }
}

#[test]
fn streaming_response_crosses_the_native_abi() {
    let reg = FunctionRegistry::new();
    let response = reg.invoke(&dylib_path(), Call::buffered("GET", "/sse", "", &[], &[]));
    assert_eq!(response.status, 200);
    assert!(response.is_stream());
    assert!(response
        .headers
        .iter()
        .any(|(name, value)| name == "Content-Type" && value == "text/event-stream"));
    // Dropping the Reply without consuming it exercises disconnect cleanup:
    // the gate returns the opaque reader to the function's gk_stream_free.
}

#[test]
fn missing_dylib_fails_closed() {
    let reg = FunctionRegistry::new();
    let r = reg.invoke(
        &PathBuf::from("definitely/not/a/real.so"),
        Call::buffered(
            "GET",
            "/x",
            "",
            &[],
            &[],
        ),
    );
    // Load failure -> 502, never a panic.
    assert_eq!(r.status, 502);
}

/// The v4 capability that let the release store stop being part of the gate: a
/// body crosses the ABI as a stream, so a route can accept an upload far larger
/// than anything the gate would be willing to hold in memory.
#[test]
fn request_bodies_cross_the_abi_as_a_stream() {
    let lib = dylib_path();
    let reg = FunctionRegistry::new();

    // Bigger than any buffer on either side of the boundary, and not a multiple
    // of the function's chunk size, so a partial final read is exercised.
    const SIZE: u64 = 9 * 1024 * 1024 + 7;
    let mut source = std::io::Read::take(std::io::repeat(b'c'), SIZE);
    let response = reg.invoke(
        &lib,
        Call {
            method: "POST",
            path: "/drain",
            query: "",
            headers: &[],
            body: CallBody::Stream { reader: &mut source, total: SIZE },
            auth: "",
            settings: "",
        },
    );
    assert_eq!(response.status, 200);
    let body = String::from_utf8(response.body).unwrap();
    assert_eq!(body, format!(r#"{{"bytes":{SIZE},"streamed":true}}"#));

    // The same handler still sees a complete buffer on an ordinary route.
    let response = reg.invoke(&lib, Call::buffered("POST", "/drain", "", &[], b"twelve bytes"));
    assert_eq!(
        String::from_utf8(response.body).unwrap(),
        r#"{"bytes":12,"streamed":false}"#
    );
}

/// The caller and the route's settings reach a function as gate-built JSON, not
/// as headers a client could have set.
#[test]
fn the_gate_states_who_called_and_how_the_route_is_configured() {
    let lib = dylib_path();
    let reg = FunctionRegistry::new();
    let auth = r#"{"principal":"github-actions","scopes":["releases:publish"],"claims":{"run_id":"7"}}"#;
    let settings = r#"{"root":"/var/lib/releases"}"#;
    let response = reg.invoke(
        &lib,
        Call {
            method: "GET",
            path: "/whoami",
            query: "",
            // A client trying to forge the same thing through headers.
            headers: &[hdr("X-Gatekeeper-Auth", r#"{"scopes":["*"]}"#)],
            body: CallBody::Buffered(b""),
            auth,
            settings,
        },
    );
    assert_eq!(response.status, 200);
    let seen: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(seen["auth"]["scopes"][0], "releases:publish");
    assert_eq!(seen["auth"]["claims"]["run_id"], "7");
    assert_eq!(seen["settings"]["root"], "/var/lib/releases");
}
