//! Transactional private release publication and download for the Coil
//! toolchain, as a Gatekeeper **function**.
//!
//! This used to be a native route target compiled into the gate, on the grounds
//! that function routes buffered request bodies and a toolchain artifact is far
//! too large to hold in memory. ABI v4 removed that constraint: a route can ask
//! for `stream_request` and pull the body through `Request::reader()`. So the
//! gate no longer knows what a Coil release is, and this ships as a dylib that
//! is dropped in and picked up with a `SIGHUP`.
//!
//! Two things the gate still supplies, because only it can:
//!
//! * **Who is calling.** `Request::auth()` is the gate's own statement about the
//!   credential it verified, including the GitHub Actions claims a publication
//!   binds itself to. A function cannot verify an OIDC token and must not try.
//! * **Where the store lives.** `Request::settings()` is the route's `settings`
//!   table, carried through verbatim.

use gatekeeper_fn::{describe, handler, Description, Endpoint, Param, Request, Response};

mod caller;
mod store;

use caller::{Caller, Settings};
use store::{Incoming, ReleaseStore};

#[handler]
fn app(mut request: Request) -> Response {
    let settings = match Settings::parse(request.settings()) {
        Ok(settings) => settings,
        // A misconfigured store must not quietly serve the wrong root.
        Err(error) => {
            eprintln!("coil-release: {error}");
            return refuse(500, "release store is misconfigured");
        }
    };
    let store = match ReleaseStore::new(settings) {
        Ok(store) => store,
        Err(error) => {
            eprintln!("coil-release: {error}");
            return refuse(500, "release store failure");
        }
    };
    // The gate admitted this caller on the route's `any_scopes`; which of the
    // two kinds they are is decided per endpoint, inside the store.
    let Some(auth) = Caller::parse(request.auth()) else {
        return refuse(401, "Unauthorized");
    };

    let method = request.method().to_string();
    let path = request.path().to_string();
    let query = request.query().to_string();
    let headers = request.headers().to_vec();
    let length = request.body_total();
    let mut body = request.reader();
    store.handle(
        &auth,
        Incoming {
            method: &method,
            rest: &path,
            query: &query,
            headers: &headers,
            body_length: length,
            body: &mut body,
        },
    )
}

/// Every refusal from this function carries the same no-store headers as a
/// successful read, so a proxy cannot retain one and replay it.
fn refuse(status: u16, message: &str) -> Response {
    Response::status(status, message)
        .header("Cache-Control", "private, no-store")
        .header("X-Content-Type-Options", "nosniff")
}


#[describe]
fn describe() -> Description {
    Description::new(
        "coil-release",
        "Transactional private release publication and download",
    )
    .endpoint(
        Endpoint::get(
            "/publications/preflight",
            "whether publishing a commit to a channel would do anything",
        )
        .param(Param::new("channel", "string", "release channel, e.g. nightly").required())
        .param(Param::new("commit", "string", "full commit SHA").required())
        .param(Param::new("sequence", "int", "the release's ordering key").required())
        .example("/publications/preflight?channel=nightly&commit=<sha>&sequence=1789793772")
        .returns("{ channel, commit, verdict: publish|current|conflict, reason }"),
    )
    .endpoint(
        Endpoint::new("/publications", "open a publication transaction", &["POST"])
            .returns("{ publication, state }"),
    )
    .endpoint(
        Endpoint::new(
            "/publications/{id}/{target}",
            "upload one target's artifact, with an exact Content-Length",
            &["PUT"],
        )
        .returns("{ target, state }"),
    )
    .endpoint(
        Endpoint::new(
            "/publications/{id}/complete",
            "verify every artifact and atomically promote the channel",
            &["POST"],
        )
        .returns("{ channel, commit, state }"),
    )
    .endpoint(
        Endpoint::new("/channels/{channel}.json", "the channel's current release", &["GET", "HEAD"])
            .returns("{ schema, channel, release, commit, sequence, published_at, targets }"),
    )
    .endpoint(Endpoint::new(
        "/builds/{commit}/coil-{target}.tar.gz",
        "download one published artifact; supports a single byte range",
        &["GET", "HEAD"],
    ))
}
