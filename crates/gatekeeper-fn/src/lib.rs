//! Write a serverless Rust function for gatekeeper.
//!
//! Your function is a normal Rust `cdylib`. You write one handler:
//!
//! ```ignore
//! use gatekeeper_fn::{handler, Request, Response};
//!
//! #[handler]
//! fn app(req: Request) -> Response {
//!     match req.path() {
//!         "/health" => Response::text("ok"),
//!         _ => Response::json(r#"{"hello":"world"}"#),
//!     }
//! }
//! ```
//!
//! and in `Cargo.toml`:
//!
//! ```toml
//! [lib]
//! crate-type = ["cdylib"]
//! ```
//!
//! That's the whole contract. The `#[handler]` macro generates the C-ABI symbols
//! the gate loads (see [`gatekeeper_abi`]); you never touch raw pointers, ports,
//! versions, or unsafe. A panic in your handler is caught and turned into a 500
//! by the gate-facing glue, so one bad request can't take down the gate.
//!
//! The ergonomic [`Request`]/[`Response`] types here own normal Rust data; the
//! marshalling to/from the `#[repr(C)]` ABI structs happens in [`__rt`].

pub use gatekeeper_fn_macro::handler;

/// An incoming HTTP request, as seen by your handler.
///
/// Everything but the body is owned (copied out of the borrowed ABI request
/// before your code runs). The body is owned too *unless* the route asked for
/// `stream_request`, in which case it is pulled from the gate on demand through
/// [`Request::reader`] and is valid only for the duration of the call.
#[derive(Debug)]
pub struct Request {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) query: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: RequestBody,
    pub(crate) body_total: Option<u64>,
    pub(crate) auth: String,
    pub(crate) settings: String,
}

#[derive(Debug)]
pub(crate) enum RequestBody {
    Buffered { bytes: Vec<u8>, read: usize },
    Stream(GateStream),
}

/// A request body still being pulled from the gate. Reads are backpressured by
/// the client connection; the gate owns the underlying state and releases it
/// after the handler returns, so this must not outlive the call.
#[derive(Debug)]
pub(crate) struct GateStream {
    ctx: *mut std::ffi::c_void,
    read: gatekeeper_abi::GkBodyRead,
}

impl GateStream {
    pub(crate) fn new(ctx: *mut std::ffi::c_void, read: gatekeeper_abi::GkBodyRead) -> Self {
        GateStream { ctx, read }
    }
}

/// Reads a request body, whether the gate buffered it or is streaming it.
pub struct BodyReader<'a> {
    body: &'a mut RequestBody,
}

impl std::io::Read for BodyReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.body {
            RequestBody::Buffered { bytes, read } => {
                let n = buf.len().min(bytes.len() - *read);
                buf[..n].copy_from_slice(&bytes[*read..*read + n]);
                *read += n;
                Ok(n)
            }
            RequestBody::Stream(stream) => {
                if buf.is_empty() {
                    return Ok(0);
                }
                match (stream.read)(stream.ctx, buf.as_mut_ptr(), buf.len()) {
                    n @ 0.. => Ok(n as usize),
                    _ => Err(std::io::Error::other("gatekeeper: request body read failed")),
                }
            }
        }
    }
}

impl Request {
    /// HTTP method, uppercase (`GET`, `POST`, …).
    pub fn method(&self) -> &str {
        &self.method
    }
    /// Request path after the route prefix (e.g. `/users/3`); `""` if the
    /// request hit the route root exactly.
    pub fn path(&self) -> &str {
        &self.path
    }
    /// Raw query string without the leading `?` (empty if none).
    pub fn query(&self) -> &str {
        &self.query
    }
    /// All headers as (name, value) pairs, in arrival order.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }
    /// First header value matching `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    /// Raw request body bytes. Empty on a `stream_request` route, where the body
    /// has not been read yet -- use [`Request::reader`] there.
    pub fn body(&self) -> &[u8] {
        match &self.body {
            RequestBody::Buffered { bytes, .. } => bytes,
            RequestBody::Stream(_) => &[],
        }
    }
    /// Request body as UTF-8 text, lossily (invalid bytes become `�`).
    pub fn text(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(self.body())
    }
    /// Read the body, buffered or streamed, without caring which. On a
    /// `stream_request` route this is the only way to see it, and reading it in
    /// chunks is the point: the gate never holds the whole body in memory.
    pub fn reader(&mut self) -> BodyReader<'_> {
        BodyReader { body: &mut self.body }
    }
    /// Whether the body arrives as a stream rather than a complete buffer.
    pub fn is_streaming(&self) -> bool {
        matches!(self.body, RequestBody::Stream(_))
    }
    /// How many bytes the body will be, when that is known: the buffered length,
    /// or the length the client declared for a streamed one. `None` means the
    /// client declared nothing.
    ///
    /// Take it from here rather than reading `Content-Length` yourself — the gate
    /// has already reconciled the header with how it framed the body, so this
    /// cannot disagree with what you are about to read.
    pub fn body_total(&self) -> Option<u64> {
        self.body_total
    }
    /// The gate's own view of the authenticated caller, as JSON:
    /// `{"principal": "...", "scopes": [...], "claims": {...}}`.
    ///
    /// The gate builds this from the credential it verified, so -- unlike a
    /// header -- a client cannot forge it. Empty on a public route. Parse it
    /// with whatever JSON library your function already uses; the SDK
    /// deliberately has no opinion.
    pub fn auth(&self) -> &str {
        &self.auth
    }
    /// The route's `settings` table from the gate's config, as JSON. The gate
    /// carries it through without interpreting a field, so a function's
    /// configuration is the function's own business.
    pub fn settings(&self) -> &str {
        &self.settings
    }

}

/// The response your handler returns.
pub struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: ResponseBody,
}

pub(crate) enum ResponseBody {
    Buffered(Vec<u8>),
    Stream {
        reader: Box<dyn std::io::Read + Send>,
        /// Total bytes the stream will produce, when known. The gate frames a
        /// known length as `Content-Length` and an unknown one as chunked, so
        /// declaring it is what makes a download resumable and a HEAD useful.
        len: Option<u64>,
    },
}

impl Response {
    /// A response with an explicit status and raw body, no headers.
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Response {
            status,
            headers: Vec::new(),
            body: ResponseBody::Buffered(body.into()),
        }
    }
    /// A response whose body is pulled incrementally by Gatekeeper. Reads are
    /// naturally backpressured by the client connection; dropping the reader
    /// signals EOF, an error, or client disconnect.
    pub fn stream(status: u16, body: impl std::io::Read + Send + 'static) -> Self {
        Response {
            status,
            headers: Vec::new(),
            body: ResponseBody::Stream { reader: Box::new(body), len: None },
        }
    }
    /// A streamed response whose exact length is known up front, so the gate can
    /// send a real `Content-Length` instead of chunking it.
    pub fn stream_len(
        status: u16,
        body: impl std::io::Read + Send + 'static,
        len: u64,
    ) -> Self {
        Response {
            status,
            headers: Vec::new(),
            body: ResponseBody::Stream { reader: Box::new(body), len: Some(len) },
        }
    }
    /// `200 OK` with a `text/plain` body.
    pub fn text(body: impl Into<String>) -> Self {
        Response::new(200, body.into().into_bytes())
            .header("Content-Type", "text/plain; charset=utf-8")
    }
    /// `200 OK` with an `application/json` body. You supply the JSON string.
    pub fn json(body: impl Into<String>) -> Self {
        Response::new(200, body.into().into_bytes()).header("Content-Type", "application/json")
    }
    /// `200 OK` with a `text/html` body.
    pub fn html(body: impl Into<String>) -> Self {
        Response::new(200, body.into().into_bytes())
            .header("Content-Type", "text/html; charset=utf-8")
    }
    /// A bare status with a short text body (e.g. `Response::status(404, "nope")`).
    pub fn status(status: u16, msg: impl Into<String>) -> Self {
        Response::new(status, msg.into().into_bytes())
    }
    /// Add a response header (builder style).
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
    /// Override the status code (builder style).
    pub fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    /// The status this response carries. Present so a function can unit-test its
    /// own handler without going through the gate.
    pub fn status_code(&self) -> u16 {
        self.status
    }
    /// The buffered body, or empty for a streamed one.
    pub fn body_bytes(&self) -> &[u8] {
        match &self.body {
            ResponseBody::Buffered(bytes) => bytes,
            ResponseBody::Stream { .. } => &[],
        }
    }
    /// The response headers, in the order they were added.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }
}

pub mod describe;
pub use describe::{Description, Endpoint, Param};

pub use gatekeeper_fn_macro::describe;

#[doc(hidden)]
pub mod __rt;
