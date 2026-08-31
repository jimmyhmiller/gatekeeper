//! A uniform buffered-or-streaming reply so authentication and routing stay
//! transport-independent while function services can produce incremental data.

use std::io::Read;

pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    stream: Option<Box<dyn Read + Send>>,
}

impl Reply {
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Reply {
            status,
            headers: Vec::new(),
            body,
            stream: None,
        }
    }

    /// A bare status with a short text body.
    pub fn status(status: u16, msg: &str) -> Self {
        Reply::new(status, msg.as_bytes().to_vec())
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn stream(status: u16, body: Box<dyn Read + Send>) -> Self {
        Reply {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            stream: Some(body),
        }
    }

    pub fn is_stream(&self) -> bool {
        self.stream.is_some()
    }

    /// Convert to a tiny_http response and send it on the given request.
    pub fn respond(self, request: tiny_http::Request) -> std::io::Result<()> {
        let mut resp = match self.stream {
            None => tiny_http::Response::new(
                tiny_http::StatusCode(self.status),
                Vec::new(),
                Box::new(std::io::Cursor::new(self.body)) as Box<dyn Read + Send>,
                None,
                None,
            ),
            Some(body) => tiny_http::Response::new(
                tiny_http::StatusCode(self.status),
                Vec::new(),
                body,
                None,
                None,
            ),
        };
        for (name, value) in &self.headers {
            if let Ok(h) = tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()) {
                resp = resp.with_header(h);
            }
        }
        request.respond(resp)
    }
}
