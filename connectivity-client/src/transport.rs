//! The std-TCP transport: dial, write the request, read one response —
//! with timeouts and a bounded, method-aware retry policy.
//!
//! Host-only module (`#[cfg(not(target_family = "wasm"))]` in `lib.rs`):
//! it uses `std::net`, which needs an OS socket layer. The codec
//! (`http.rs`) and the wire DTOs (`wire.rs`) stay platform-independent.
//!
//! # Retry policy (documented, deliberate)
//!
//! - `GET` requests are idempotent queries: they are retried on ANY
//!   transport failure (connect refusal, timeout, mid-call drop), bounded
//!   by `max_attempts`.
//! - `POST` requests are replayed ONLY for connect-phase failures —
//!   nothing has been sent yet, so nothing can double-apply. Once the
//!   request bytes are on the wire, a failure is terminal for the call:
//!   this wire shape has no idempotency keys, and replaying a
//!   `POST /intents` that may have already been applied could mint two
//!   intents. (A future ADCOS API with idempotency tokens can relax this;
//!   documented in the README as a known limit.)
//!
//! `attempts` on the resulting error counts the attempts consumed before
//! giving up.
//!
//! # Addressing
//!
//! By `SocketAddr` only — no DNS. A deployment fronting ADCOS with a
//! hostname resolves it before constructing the [`TransportConfig`]
//! (documented simplification; see README).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::error::{AdcosError, MalformedReason};
use crate::http::{self, HttpRequest, HttpResponse};

/// Read caps protecting the client from a hostile or broken server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportLimits {
    /// Maximum response head bytes (status line + headers).
    pub max_head_bytes: usize,
    /// Maximum response body bytes.
    pub max_body_bytes: usize,
}

impl Default for TransportLimits {
    fn default() -> Self {
        TransportLimits {
            max_head_bytes: 16 * 1024,
            max_body_bytes: 1024 * 1024,
        }
    }
}

/// Everything the transport needs; `AdcosConfig` builds one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportConfig {
    /// The ADCOS endpoint.
    pub addr: SocketAddr,
    /// Connect timeout per attempt.
    pub connect_timeout: Duration,
    /// Read/write timeout per attempt.
    pub read_timeout: Duration,
    /// Maximum connection attempts per call.
    pub max_attempts: u32,
    /// Delay between attempts.
    pub retry_delay: Duration,
    /// Read caps.
    pub limits: TransportLimits,
}

impl TransportConfig {
    /// A config for `addr` with fast defaults (suitable for loopback
    /// tests and the documented production defaults alike: 2 s connect,
    /// 3 s read, 3 attempts, 50 ms delay).
    pub fn new(addr: SocketAddr) -> TransportConfig {
        TransportConfig {
            addr,
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(3),
            max_attempts: 3,
            retry_delay: Duration::from_millis(50),
            limits: TransportLimits::default(),
        }
    }
}

/// Perform one full request/response exchange under the retry policy.
///
/// The final error (when attempts are exhausted or the failure is not
/// retryable) carries the number of attempts consumed.
pub fn exchange(config: &TransportConfig, request: &HttpRequest) -> Result<HttpResponse, AdcosError> {
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match attempt_once(config, request) {
            Ok(response) => return Ok(response),
            Err(error) => {
                let retryable = !error_sent(&error) || request.method == http::Method::Get;
                if !retryable || attempt >= config.max_attempts {
                    return Err(with_attempts(error, attempt));
                }
                std::thread::sleep(config.retry_delay);
            }
        }
    }
}

/// Whether the failed attempt had already sent request bytes (drives the
/// retry policy). Codec faults (`Malformed`) can only happen after a full
/// response head arrived, i.e. strictly after sending.
fn error_sent(error: &AdcosError) -> bool {
    matches!(
        error,
        AdcosError::TimedOut { .. } | AdcosError::ConnectionDropped { .. } | AdcosError::Malformed { .. }
    )
}

/// Stamp the consumed attempt count onto a transport-class error.
fn with_attempts(error: AdcosError, attempts: u32) -> AdcosError {
    match error {
        AdcosError::ConnectFailed { .. } => AdcosError::ConnectFailed { attempts },
        AdcosError::ConnectTimedOut { .. } => AdcosError::ConnectTimedOut { attempts },
        AdcosError::TimedOut { .. } => AdcosError::TimedOut { attempts },
        AdcosError::ConnectionDropped { .. } => AdcosError::ConnectionDropped { attempts },
        other => other,
    }
}

/// One attempt. The error of a failed attempt encodes (a) the transport
/// class and (b) whether request bytes had been sent, so the caller can
/// apply the retry policy. Since `AdcosError` itself cannot express
/// "sent", the phase is returned alongside.
fn attempt_once(
    config: &TransportConfig,
    request: &HttpRequest,
) -> Result<HttpResponse, AdcosError> {
    let mut stream = TcpStream::connect_timeout(&config.addr, config.connect_timeout).map_err(
        |error| connect_error(error),
    )?;
    stream
        .set_read_timeout(Some(config.read_timeout))
        .map_err(|_| AdcosError::ConnectFailed { attempts: 1 })?;
    stream
        .set_write_timeout(Some(config.read_timeout))
        .map_err(|_| AdcosError::ConnectFailed { attempts: 1 })?;

    let bytes = request.serialize(&config.addr.to_string());
    // Once we start writing, the request may have been applied — the
    // phase is "sent" for retry purposes even if the write fails halfway.
    let write_result = stream.write_all(&bytes);
    if let Err(error) = write_result {
        return Err(stream_error(error));
    }

    let mut reader = BufReader::new(stream);
    read_response(&mut reader, config.limits)
}

/// Map a connect-phase io error.
fn connect_error(error: std::io::Error) -> AdcosError {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            AdcosError::ConnectTimedOut { attempts: 1 }
        }
        _ => AdcosError::ConnectFailed { attempts: 1 },
    }
}

/// Map a post-connect io error (request writing or response reading).
fn stream_error(error: std::io::Error) -> AdcosError {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => AdcosError::TimedOut { attempts: 1 },
        // Everything else on an established, request-sent connection is a
        // closed/broken peer from this client's point of view.
        _ => AdcosError::ConnectionDropped { attempts: 1 },
    }
}

/// Read one response from the stream: head until `\r\n\r\n` (capped),
/// then exactly `Content-Length` body bytes (capped).
fn read_response(
    reader: &mut impl BufRead,
    limits: TransportLimits,
) -> Result<HttpResponse, AdcosError> {
    // 1. Head, line by line, under the cap.
    let mut head: Vec<u8> = Vec::with_capacity(256);
    loop {
        let remaining = limits.max_head_bytes.saturating_sub(head.len());
        if remaining == 0 {
            return Err(AdcosError::Malformed {
                reason: MalformedReason::HeadersTooLarge {
                    len: head.len(),
                    max: limits.max_head_bytes,
                },
            });
        }
        let mut line = Vec::new();
        let read = (&mut *reader).take(remaining as u64).read_until(b'\n', &mut line).map_err(stream_error)?;
        if read == 0 {
            // EOF before the head terminator: connection dropped mid-head.
            return Err(AdcosError::ConnectionDropped { attempts: 1 });
        }
        head.extend_from_slice(&line);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    // 2. Parse the head.
    let (status, reason, headers) = http::parse_response_head(&head).map_err(|reason| {
        AdcosError::Malformed { reason }
    })?;

    // 3. Body per Content-Length (strict subset: no chunked).
    let content_length = http::content_length(&headers).map_err(|reason| AdcosError::Malformed { reason })?;
    let body = match content_length {
        Some(len) => {
            if len > limits.max_body_bytes {
                return Err(AdcosError::Malformed {
                    reason: MalformedReason::BodyTooLarge {
                        len,
                        max: limits.max_body_bytes,
                    },
                });
            }
            let mut body = vec![0u8; len];
            reader.read_exact(&mut body).map_err(stream_error)?;
            body
        }
        None => Vec::new(),
    };

    Ok(HttpResponse {
        status,
        reason,
        headers,
        body,
    })
}
