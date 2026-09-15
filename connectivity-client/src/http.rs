//! A minimal hand-rolled HTTP/1.1 codec — the strict subset this wire client
//! and its test scaffolding server speak.
//!
//! Deliberately NOT an HTTP framework (the adapter stays dependency-light:
//! std TCP + serde only). The subset is:
//!
//! - requests: one request line (`GET`/`POST`), `Host`, optional
//!   `Content-Type: application/json`, always `Content-Length`, always
//!   `Connection: close`, then the body;
//! - responses: one status line (`HTTP/1.0`/`HTTP/1.1` accepted, 3-digit
//!   status), headers, then exactly `Content-Length` bytes of body;
//! - **no chunked transfer coding** (`Transfer-Encoding` is refused with a
//!   typed [`MalformedReason::ChunkedUnsupported`]);
//! - no content negotiation beyond JSON bodies, no cookies, no redirects
//!   (statuses outside the documented set surface as
//!   [`crate::AdcosError::HttpStatus`]).
//!
//! Pure bytes in / pure bytes out: everything here is platform-independent
//! (no sockets), so it compiles for `wasm32-unknown-unknown` alongside the
//! wire DTOs — only the TCP transport (`transport.rs`) is host-gated.
//!
//! Both directions live here because the test scaffolding server
//! (`src/bin/adcos_test_server.rs`) parses requests and serializes
//! responses with the same codec, so client and scaffolding cannot drift.

use crate::error::MalformedReason;

/// The two methods this wire shape uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

impl Method {
    /// Uppercase method token.
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
        }
    }

    /// Strict parse from the request-line token.
    pub fn parse(token: &str) -> Result<Method, MalformedReason> {
        match token {
            "GET" => Ok(Method::Get),
            "POST" => Ok(Method::Post),
            _ => Err(MalformedReason::BadMethod),
        }
    }
}

/// An outbound request (client side) or a parsed inbound request (server
/// side). `body` is empty exactly when there is no payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// The request method.
    pub method: Method,
    /// The absolute request path (query strings are not used by this shape).
    pub path: String,
    /// The request body bytes (JSON); empty = no body.
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Serialize to full HTTP/1.1 request bytes (request line + headers +
    /// `\r\n\r\n` + body). `host` becomes the `Host` header value.
    ///
    /// `Content-Type: application/json` is sent only when a body is present
    /// (GET requests carry none); `Content-Length` is always sent;
    /// `Connection: close` is always sent — every call is one connection,
    /// which keeps the reader minimal and honest.
    pub fn serialize(&self, host: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.body.len());
        out.extend_from_slice(self.method.as_str().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.path.as_bytes());
        out.extend_from_slice(b" HTTP/1.1\r\n");
        out.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
        if !self.body.is_empty() {
            out.extend_from_slice(b"Content-Type: application/json\r\n");
        }
        out.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());
        out.extend_from_slice(b"Connection: close\r\n\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}

/// A parsed response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// The 3-digit status code.
    pub status: u16,
    /// The status-line reason phrase (diagnostic only, never parsed).
    pub reason: String,
    /// Headers, names lowercased, in arrival order.
    pub headers: Vec<(String, String)>,
    /// The body bytes (exactly `Content-Length` of them, or empty).
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Case-insensitive header lookup.
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Whether the status is a 2xx success.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// The canonical reason phrase for the statuses this wire shape documents
/// (diagnostic only — nothing parses it).
pub fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        422 => "Unprocessable Entity",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

/// Serialize a response (server side): status line + `Content-Type` +
/// `Content-Length` + `Connection: close` + body.
pub fn serialize_response(status: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(128 + body.len());
    out.extend_from_slice(format!("HTTP/1.1 {status} {}\r\n", reason_phrase(status)).as_bytes());
    out.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
    out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(body);
    out
}

/// Parse a response head (everything up to and including the blank line).
///
/// Shared by [`parse_response`] (unit-tested full-message parse) and the
/// transport's stream reader.
pub fn parse_response_head(head: &[u8]) -> Result<(u16, String, Vec<(String, String)>), MalformedReason> {
    let text = std::str::from_utf8(head).map_err(|_| MalformedReason::BadHeaderLine)?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or(MalformedReason::BadStatusLine)?;

    // "HTTP/1.1 200 OK" — version token, exactly 3 ASCII digits, reason.
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(MalformedReason::BadStatusLine);
    }
    let code = parts.next().unwrap_or("");
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(MalformedReason::BadStatusLine);
    }
    let status: u16 = code.parse().map_err(|_| MalformedReason::BadStatusLine)?;
    let reason = parts.next().unwrap_or("").trim().to_string();

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(MalformedReason::BadHeaderLine);
        };
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }
    Ok((status, reason, headers))
}

/// Parse a request head (server side): request line + headers.
pub fn parse_request_head(head: &[u8]) -> Result<(Method, String, Vec<(String, String)>), MalformedReason> {
    let text = std::str::from_utf8(head).map_err(|_| MalformedReason::BadHeaderLine)?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(MalformedReason::BadRequestLine)?;

    // "POST /intents HTTP/1.1" — method, path, version.
    let mut parts = request_line.splitn(3, ' ');
    let method = Method::parse(parts.next().unwrap_or(""))?;
    let path = parts.next().ok_or(MalformedReason::BadRequestLine)?.to_string();
    let version = parts.next().unwrap_or("");
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(MalformedReason::BadRequestLine);
    }

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(MalformedReason::BadHeaderLine);
        };
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }
    Ok((method, path, headers))
}

/// Extract `Content-Length` under the strict rules of this subset.
///
/// `Ok(None)` = the head declares no body. `Transfer-Encoding` present is
/// refused (chunked is outside the subset). Duplicate `Content-Length`
/// headers must agree.
pub fn content_length(headers: &[(String, String)]) -> Result<Option<usize>, MalformedReason> {
    if headers
        .iter()
        .any(|(name, _)| name == "transfer-encoding")
    {
        return Err(MalformedReason::ChunkedUnsupported);
    }
    let mut found: Option<usize> = None;
    for (name, value) in headers {
        if name != "content-length" {
            continue;
        }
        let len: usize = value
            .parse()
            .map_err(|_| MalformedReason::ContentLengthInvalid)?;
        match found {
            Some(previous) if previous != len => {
                return Err(MalformedReason::DuplicateContentLength);
            }
            _ => found = Some(len),
        }
    }
    Ok(found)
}

/// Parse one complete response message (head + exactly `Content-Length`
/// body bytes). For unit tests and future non-TCP transports; the TCP
/// transport reads the head and body from the stream and assembles the
/// same [`HttpResponse`] itself.
pub fn parse_response(bytes: &[u8]) -> Result<HttpResponse, MalformedReason> {
    let Some(head_len) = find_head_terminator(bytes) else {
        return Err(MalformedReason::HeadIncomplete);
    };
    let (status, reason, headers) = parse_response_head(&bytes[..head_len])?;
    let rest = &bytes[head_len + 4..];
    match content_length(&headers)? {
        Some(expected) => {
            if rest.len() != expected {
                return Err(MalformedReason::BodyLengthMismatch {
                    expected,
                    found: rest.len(),
                });
            }
            Ok(HttpResponse {
                status,
                reason,
                headers,
                body: rest.to_vec(),
            })
        }
        None => {
            if !rest.is_empty() {
                return Err(MalformedReason::BodyLengthMismatch {
                    expected: 0,
                    found: rest.len(),
                });
            }
            Ok(HttpResponse {
                status,
                reason,
                headers,
                body: Vec::new(),
            })
        }
    }
}

/// Parse one complete request message (server-side unit tests; the
/// scaffolding server reads head + body from the stream and uses
/// [`parse_request_head`]).
pub fn parse_request(bytes: &[u8]) -> Result<HttpRequest, MalformedReason> {
    let Some(head_len) = find_head_terminator(bytes) else {
        return Err(MalformedReason::HeadIncomplete);
    };
    let (method, path, headers) = parse_request_head(&bytes[..head_len])?;
    let rest = &bytes[head_len + 4..];
    match content_length(&headers)? {
        Some(expected) => {
            if rest.len() != expected {
                return Err(MalformedReason::BodyLengthMismatch {
                    expected,
                    found: rest.len(),
                });
            }
            Ok(HttpRequest {
                method,
                path,
                body: rest.to_vec(),
            })
        }
        None => {
            if !rest.is_empty() {
                return Err(MalformedReason::BodyLengthMismatch {
                    expected: 0,
                    found: rest.len(),
                });
            }
            Ok(HttpRequest {
                method,
                path,
                body: Vec::new(),
            })
        }
    }
}

/// Offset of the `\r\n\r\n` head terminator, if present.
fn find_head_terminator(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialized_get_request_is_exact_bytes() {
        let request = HttpRequest {
            method: Method::Get,
            path: "/contracts/ab".to_string(),
            body: Vec::new(),
        };
        let bytes = request.serialize("127.0.0.1:9");
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "GET /contracts/ab HTTP/1.1\r\n\
             Host: 127.0.0.1:9\r\n\
             Content-Length: 0\r\n\
             Connection: close\r\n\
             \r\n"
        );
    }

    #[test]
    fn serialized_post_request_is_exact_bytes() {
        let request = HttpRequest {
            method: Method::Post,
            path: "/intents".to_string(),
            body: b"{\"version\":1}".to_vec(),
        };
        let bytes = request.serialize("adcos.example:8080");
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "POST /intents HTTP/1.1\r\n\
             Host: adcos.example:8080\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 13\r\n\
             Connection: close\r\n\
             \r\n\
             {\"version\":1}"
        );
    }

    #[test]
    fn request_round_trips_through_the_codec() {
        let request = HttpRequest {
            method: Method::Post,
            path: "/intents/01/02/accept".to_string(),
            body: b"{}".to_vec(),
        };
        let bytes = request.serialize("h");
        let parsed = parse_request(&bytes).expect("parse");
        assert_eq!(parsed, request);
        let get = HttpRequest {
            method: Method::Get,
            path: "/intents/01/offers".to_string(),
            body: Vec::new(),
        };
        assert_eq!(parse_request(&get.serialize("h")).unwrap(), get);
    }

    #[test]
    fn parses_a_well_formed_response_with_body() {
        let response = parse_response(
            b"HTTP/1.1 200 OK\r\n\
              Content-Type: application/json\r\n\
              Content-Length: 2\r\n\
              Connection: close\r\n\
              \r\n\
              {}",
        )
        .expect("parse");
        assert_eq!(response.status, 200);
        assert_eq!(response.reason, "OK");
        assert_eq!(response.body, b"{}");
        assert_eq!(response.header("content-type"), Some("application/json"));
        assert_eq!(response.header("CONTENT-TYPE"), Some("application/json"), "case-insensitive");
        assert_eq!(response.header("missing"), None);
        assert!(response.is_success());
    }

    #[test]
    fn parses_a_503_with_empty_reason() {
        let response = parse_response(
            b"HTTP/1.1 503\r\nContent-Length: 0\r\n\r\n",
        )
        .expect("parse");
        assert_eq!(response.status, 503);
        assert_eq!(response.reason, "");
        assert!(!response.is_success());
        assert!(response.body.is_empty());
    }

    #[test]
    fn bad_status_lines_are_typed_rejected() {
        for bad in [
            &b"HTTP/2 200 OK\r\n\r\n"[..],
            b"HTTP/1.1 20 OK\r\n\r\n",
            b"HTTP/1.1 2O0 OK\r\n\r\n",
            b"garbage\r\n\r\n",
            b"HTTP/1.1  200 OK\r\n\r\n",
            b"HTTP/1.1 2000 OK\r\n\r\n",
        ] {
            assert_eq!(
                parse_response(bad),
                Err(MalformedReason::BadStatusLine),
                "input: {:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn bad_request_lines_and_methods_are_typed_rejected() {
        assert_eq!(
            parse_request(b"PUT /x HTTP/1.1\r\n\r\n"),
            Err(MalformedReason::BadMethod)
        );
        assert_eq!(
            parse_request(b"GET /x HTTP/2\r\n\r\n"),
            Err(MalformedReason::BadRequestLine)
        );
        assert_eq!(
            parse_request(b"GET /x QQQ/1.1\r\n\r\n"),
            Err(MalformedReason::BadRequestLine)
        );
        // A header line without a colon.
        assert_eq!(
            parse_request(b"GET / HTTP/1.1\r\nbrokenheader\r\n\r\n"),
            Err(MalformedReason::BadHeaderLine)
        );
    }

    #[test]
    fn missing_head_terminator_is_typed_rejected() {
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 0"),
            Err(MalformedReason::HeadIncomplete)
        );
    }

    #[test]
    fn body_length_is_strictly_enforced() {
        // Content-Length longer than the actual bytes.
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab"),
            Err(MalformedReason::BodyLengthMismatch { expected: 5, found: 2 })
        );
        // Trailing data past the declared length.
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nab"),
            Err(MalformedReason::BodyLengthMismatch { expected: 1, found: 2 })
        );
        // No Content-Length but bytes present.
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\n\r\ntrailing"),
            Err(MalformedReason::BodyLengthMismatch { expected: 0, found: 8 })
        );
        // No Content-Length and no body: an empty body is fine.
        assert!(parse_response(b"HTTP/1.1 204 No Content\r\n\r\n").is_ok());
    }

    #[test]
    fn content_length_duplicates_and_garbage_are_typed_rejected() {
        // Conflicting duplicates are refused...
        let conflicting = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n";
        assert_eq!(
            parse_response(conflicting),
            Err(MalformedReason::DuplicateContentLength)
        );
        // ...identical duplicates are tolerated.
        let identical = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}";
        assert!(parse_response(identical).is_ok());
        // Unparsable values are refused.
        let garbage = b"HTTP/1.1 200 OK\r\nContent-Length: many\r\n\r\n";
        assert_eq!(
            parse_response(garbage),
            Err(MalformedReason::ContentLengthInvalid)
        );
    }

    #[test]
    fn transfer_encoding_chunked_is_outside_the_subset() {
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        assert_eq!(
            parse_response(chunked),
            Err(MalformedReason::ChunkedUnsupported)
        );
    }

    #[test]
    fn serialized_response_is_exact_bytes_and_round_trips() {
        let bytes = serialize_response(409, "application/json", b"{\"error\":{}}");
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            "HTTP/1.1 409 Conflict\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 12\r\n\
             Connection: close\r\n\
             \r\n\
             {\"error\":{}}"
        );
        let parsed = parse_response(&bytes).expect("parse");
        assert_eq!(parsed.status, 409);
        assert_eq!(parsed.reason, "Conflict");
        assert_eq!(parsed.body, b"{\"error\":{}}");
    }
}
