//! The Coil release store, exercised as a *function* across the real C ABI.
//!
//! This is the path the store could not take before ABI v4: an artifact larger
//! than anything the gate would buffer is streamed into the dylib, committed,
//! and streamed back out. It is the justification for moving the store out of
//! the gate, so it is tested against the actual `.so`/`.dylib` through
//! `FunctionRegistry`, not against the store's own internals.
//!
//! Run `cargo build -p coil-release-fn` first.

use std::path::PathBuf;

use gatekeeper::function::{Call, CallBody, FunctionRegistry};
use sha2::{Digest, Sha256};

const COMMIT: &str = "1234567890abcdef1234567890abcdef12345678";
const TARGET: &str = "x86_64-unknown-linux-gnu";
/// Comfortably past the gate's own buffering and not a round number, so a
/// partial final chunk is exercised on both sides of the boundary.
const ARTIFACT_BYTES: u64 = 12 * 1024 * 1024 + 13;

fn dylib_path() -> PathBuf {
    let name = if cfg!(target_os = "macos") {
        "libcoil_release_fn.dylib"
    } else if cfg!(target_os = "windows") {
        "coil_release_fn.dll"
    } else {
        "libcoil_release_fn.so"
    };
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(if cfg!(debug_assertions) { "debug" } else { "release" })
        .join(name);
    assert!(
        p.exists(),
        "dylib not built at {} — run `cargo build -p coil-release-fn` first",
        p.display()
    );
    p
}

/// The gate's statement about a workflow whose OIDC token it verified.
fn publisher_auth(run: &str) -> String {
    format!(
        r#"{{"principal":"github-actions","scopes":["coil:nightly:publish"],
            "claims":{{"repository_id":"1","workflow_ref":"o/r/.github/workflows/n.yml@refs/heads/main",
            "run_id":"{run}","run_attempt":"1","commit":"{COMMIT}"}}}}"#
    )
}

fn reader_auth() -> String {
    r#"{"principal":"bootstrap","scopes":["coil:read"],"claims":null}"#.into()
}

struct Store {
    root: PathBuf,
    settings: String,
    reg: FunctionRegistry,
    lib: PathBuf,
}

impl Store {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "gatekeeper-release-fn-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let settings = format!(
            r#"{{"root":"{}","read_scope":"coil:read","publish_scope":"coil:nightly:publish",
                "max_artifact_bytes":536870912,"retain_builds":14}}"#,
            root.display()
        );
        Store { root, settings, reg: FunctionRegistry::new(), lib: dylib_path() }
    }

    fn call(&self, method: &str, path: &str, query: &str, auth: &str, body: &[u8]) -> gatekeeper::reply::Reply {
        self.reg.invoke(
            &self.lib,
            Call {
                method,
                path,
                query,
                headers: &[],
                body: CallBody::Buffered(body),
                auth,
                settings: &self.settings,
            },
        )
    }
}

#[test]
fn a_release_publishes_and_downloads_through_the_function_abi() {
    let store = Store::new();
    let auth = publisher_auth("42");

    // The artifact is generated, hashed and streamed; it is never held whole.
    let digest = {
        let mut hasher = Sha256::new();
        let mut remaining = ARTIFACT_BYTES;
        let chunk = vec![b'z'; 64 * 1024];
        while remaining > 0 {
            let n = chunk.len().min(remaining as usize);
            hasher.update(&chunk[..n]);
            remaining -= n as u64;
        }
        format!("{:x}", hasher.finalize())
    };

    // Nothing published yet, so a build of this commit has work to do.
    let pre = store.call(
        "GET",
        "/publications/preflight",
        &format!("channel=nightly&commit={COMMIT}&sequence=100"),
        &auth,
        b"",
    );
    assert_eq!(pre.status, 200);
    let pre: serde_json::Value = serde_json::from_slice(&pre.body).unwrap();
    assert_eq!(pre["verdict"], "publish");

    let begin = store.call(
        "POST",
        "/publications",
        "",
        &auth,
        format!(
            r#"{{"schema":1,"channel":"nightly","release":"0.1.0-nightly.20260920+g123456789012",
                "commit":"{COMMIT}","sequence":100,"published_at":"2026-09-20T00:00:00Z",
                "targets":{{"{TARGET}":{{"sha256":"{digest}","size":{ARTIFACT_BYTES}}}}}}}"#
        )
        .as_bytes(),
    );
    assert_eq!(begin.status, 200, "{}", String::from_utf8_lossy(&begin.body));
    let begin: serde_json::Value = serde_json::from_slice(&begin.body).unwrap();
    let publication = begin["publication"].as_str().unwrap().to_string();

    // The upload: 12 MiB crosses the ABI as a stream. Before v4 this body would
    // have been read into the gate in full before the function saw a byte.
    let mut source = std::io::Read::take(std::io::repeat(b'z'), ARTIFACT_BYTES);
    let upload = store.reg.invoke(
        &store.lib,
        Call {
            method: "PUT",
            path: &format!("/publications/{publication}/{TARGET}"),
            query: "",
            headers: &[tiny_http::Header::from_bytes(
                &b"Content-Length"[..],
                ARTIFACT_BYTES.to_string().as_bytes(),
            )
            .unwrap()],
            body: CallBody::Stream { reader: &mut source, total: ARTIFACT_BYTES },
            auth: &auth,
            settings: &store.settings,
        },
    );
    assert_eq!(upload.status, 200, "{}", String::from_utf8_lossy(&upload.body));

    // Not visible until completion.
    assert!(!store.root.join("channels/nightly.json").exists());

    let complete = store.call("POST", &format!("/publications/{publication}/complete"), "", &auth, b"{}");
    assert_eq!(complete.status, 200, "{}", String::from_utf8_lossy(&complete.body));

    // The store re-hashed what actually landed, so a matching digest on disk
    // means the streamed bytes survived the boundary intact.
    let stored = store.root.join(format!("builds/{COMMIT}/coil-{TARGET}.tar.gz"));
    assert_eq!(std::fs::metadata(&stored).unwrap().len(), ARTIFACT_BYTES);

    // A second run at the same commit now has nothing to do — issue #5's case.
    let pre = store.call(
        "GET",
        "/publications/preflight",
        &format!("channel=nightly&commit={COMMIT}&sequence=101"),
        &auth,
        b"",
    );
    let pre: serde_json::Value = serde_json::from_slice(&pre.body).unwrap();
    assert_eq!(pre["verdict"], "current");

    // The download streams back with a declared length, which is what makes a
    // HEAD report a size rather than chunking with none.
    let reader = reader_auth();
    let get = store.call(
        "GET",
        &format!("/builds/{COMMIT}/coil-{TARGET}.tar.gz"),
        "",
        &reader,
        b"",
    );
    assert_eq!(get.status, 200);
    assert!(get.is_stream());

    // A publisher may not read artifacts, and a reader may not publish.
    let forbidden = store.call("GET", &format!("/builds/{COMMIT}/coil-{TARGET}.tar.gz"), "", &auth, b"");
    assert_eq!(forbidden.status, 403);
    let forbidden = store.call("POST", "/publications", "", &reader, b"{}");
    assert_eq!(forbidden.status, 403);

    std::fs::remove_dir_all(&store.root).unwrap();
}
