//! Example gatekeeper serverless function.
//!
//! This is the *entire* app. No ports, no ABI, no unsafe — just a handler. Build
//! it with `cargo build -p hello-fn` and point a gatekeeper route at the
//! resulting `target/debug/libhello_fn.so` via `function = "..."`.

use gatekeeper_fn::{describe, handler, Description, Endpoint, Param, Request, Response};

#[handler]
fn app(mut req: Request) -> Response {
    match req.path() {
        // Prove a body can cross the ABI without the gate holding it: count the
        // bytes as they arrive and never keep more than one chunk.
        "/drain" => {
            let mut total = 0u64;
            let mut chunk = [0u8; 8 * 1024];
            let mut reader = req.reader();
            loop {
                match std::io::Read::read(&mut reader, &mut chunk) {
                    Ok(0) => break,
                    Ok(n) => total += n as u64,
                    Err(e) => return Response::status(500, format!("read failed: {e}")),
                }
            }
            Response::json(format!(
                r#"{{"bytes":{total},"streamed":{}}}"#,
                req.is_streaming()
            ))
        }
        // Echo back what the gate said about the caller and the route, so a test
        // can prove neither is something the client could have forged.
        "/whoami" => Response::json(format!(
            r#"{{"auth":{},"settings":{}}}"#,
            if req.auth().is_empty() { "null" } else { req.auth() },
            if req.settings().is_empty() { "null" } else { req.settings() },
        )),
        "/health" | "/health/" => Response::text("ok"),
        "/echo" => Response::json(format!(
            r#"{{"method":"{}","query":"{}","body":"{}"}}"#,
            req.method(),
            req.query(),
            req.text().replace('"', "\\\"")
        )),
        "/sse" => Response::stream(
            200,
            std::io::Cursor::new(b"event: greeting\ndata: hello\n\n".to_vec()),
        )
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache"),
        "/panic" => panic!("deliberate panic to prove the gate survives it"),
        p => Response::html(format!(
            "<h1>hello from a gatekeeper function</h1><p>you asked for <code>{p}</code></p>"
        )),
    }
}

/// Self-description (optional) — shows up in `/describe`.
#[describe]
fn describe() -> Description {
    Description::new("hello", "Example gatekeeper function")
        .endpoint(Endpoint::get("/health", "liveness check, returns \"ok\""))
        .endpoint(
            Endpoint::new("/echo", "echo back the request method/query/body", &["GET", "POST"])
                .example("/echo?x=1")
                .returns("{ method, query, body }"),
        )
        .endpoint(Endpoint::get("/panic", "deliberately panics (proves the gate survives it)"))
        .endpoint(Endpoint::get("/sse", "stream an event using the native streaming ABI"))
        .endpoint(
            Endpoint::get("/<anything>", "greets you with the path")
                .param(Param::new("(none)", "n/a", "no params"))
                .returns("text/html greeting"),
        )
}
