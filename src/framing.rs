//! Deterministic message framing for parsed HTTP/1.x headers.
//!
//! The raw [`crate::Header`] list intentionally preserves every
//! header line exactly as it appeared on the wire, including duplicates and
//! obsolete line folding. That makes it unsuitable for deciding how a message
//! body is delimited: two implementations looking at the same raw headers can
//! legitimately reach different conclusions, which is the root cause of HTTP
//! request/response smuggling.
//!
//! This module provides a single, spec-driven ([RFC 9112]) view of the body
//! framing that is independent of whether the message is a request or a
//! response. Every combination that can be interpreted in more than one way
//! fails closed with a [`FramingError`] instead of silently picking an
//! interpretation. Raw headers remain available untouched for callers that
//! need them.
//!
//! [RFC 9112]: https://www.rfc-editor.org/rfc/rfc9112#name-message-body-length

use core::{fmt, result};

use crate::Header;

/// A specialized [`Result`](result::Result) type for framing determinations.
pub type Result<T> = result::Result<T, FramingError>;

/// How the body of a parsed HTTP/1.x message is delimited.
///
/// Returned by [`determine_framing`] and the `framing` methods on
/// [`Request`](crate::Request) and [`Response`](crate::Response).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Framing {
    /// The body is `0` bytes long; no framing headers were present.
    ///
    /// Callers that infer a body length from the request method or response
    /// status code can treat this as a hint rather than a hard rule.
    None,
    /// The body is exactly the contained number of bytes, as determined from a
    /// single, unambiguous `Content-Length` value.
    Length(u64),
    /// The body uses chunked transfer coding, as determined from a
    /// `Transfer-Encoding` header whose final coding is `chunked`.
    Chunked,
}

/// A message cannot be assigned a single, unambiguous body framing.
///
/// This is a fail-closed result: a proxy or server must treat the message as
/// malformed (for example by replying `400 Bad Request` and closing the
/// connection) instead of guessing where the body ends.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum FramingError {
    /// Both `Transfer-Encoding` and `Content-Length` are present.
    ///
    /// RFC 9112 section 6.1 requires a recipient that receives a message with
    /// both to either remove the `Content-Length` or treat the message as
    /// malformed. Because forwarding or removing it inconsistently across a
    /// chain of agents enables smuggling, this implementation fails closed.
    TransferEncodingAndContentLength,
    /// More than one `Content-Length` header line is present.
    ///
    /// Even when every line carries the same value, recipients differ on
    /// whether to merge, reject, or take the first/last value, so the framing
    /// is not unambiguous across implementations.
    DuplicateContentLength,
    /// A `Content-Length` value is not a single, unambiguous decimal length.
    InvalidContentLength,
    /// A framing header (`Content-Length` or `Transfer-Encoding`) carries
    /// obsolete line folding, or its raw value otherwise contains a bare
    /// line break.
    ///
    /// Folded framing headers are a classic smuggling vector and must be
    /// rejected rather than unfolded.
    ObsoleteFolding,
    /// A `Transfer-Encoding` header is present but does not end with the
    /// `chunked` transfer coding.
    ///
    /// HTTP/1.1 senders must use `chunked` when a body is delimited by
    /// `Transfer-Encoding`; any other final coding leaves the body length
    /// undefined for generic recipients.
    TransferEncodingNotChunked,
    /// More than one `Transfer-Encoding` header line is present, or the
    /// header is not a syntactically valid comma-separated list of transfer
    /// codings.
    InvalidTransferEncoding,
    /// A `Transfer-Encoding` header is present on an HTTP/1.0 message.
    ///
    /// Transfer coding is an HTTP/1.1 feature; HTTP/1.0 agents do not
    /// understand it, so the framing is ambiguous across a proxy chain.
    TransferEncodingOnHttp10,
}

impl fmt::Display for FramingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            FramingError::TransferEncodingAndContentLength => {
                "message contains both Transfer-Encoding and Content-Length"
            }
            FramingError::DuplicateContentLength => {
                "message contains duplicate Content-Length headers"
            }
            FramingError::InvalidContentLength => "invalid Content-Length value",
            FramingError::ObsoleteFolding => "framing header uses obsolete line folding",
            FramingError::TransferEncodingNotChunked => {
                "Transfer-Encoding does not end with chunked"
            }
            FramingError::InvalidTransferEncoding => "invalid Transfer-Encoding header",
            FramingError::TransferEncodingOnHttp10 => {
                "Transfer-Encoding is not valid on HTTP/1.0 messages"
            }
        };
        f.write_str(msg)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FramingError {}

const CONTENT_LENGTH: &str = "content-length";
const TRANSFER_ENCODING: &str = "transfer-encoding";

/// Determine the unambiguous body framing of a parsed message.
///
/// `headers` is the raw header slice produced by
/// [`Request`](crate::Request) or [`Response`](crate::Response) parsing; it is
/// never modified, so duplicate and otherwise unusual headers stay readable to
/// callers.
///
/// `is_http_11` must be `true` for HTTP/1.1 messages and `false` for
/// HTTP/1.0 messages. It controls whether `Transfer-Encoding` is legal.
///
/// Any ambiguous or malformed framing combination yields a
/// [`FramingError`]; callers should fail the message closed rather than
/// forwarding it.
///
/// # Examples
///
/// ```
/// let buf = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
/// let mut headers = [httparse::EMPTY_HEADER; 16];
/// let mut req = httparse::Request::new(&mut headers);
/// let status = req.parse(buf).unwrap();
/// assert!(status.is_complete());
///
/// assert_eq!(
///     httparse::framing::determine_framing(req.headers, req.version == Some(1)),
///     Ok(httparse::framing::Framing::Length(5)),
/// );
/// ```
pub fn determine_framing(headers: &[Header<'_>], is_http_11: bool) -> Result<Framing> {
    let mut content_length: Option<u64> = None;
    let mut transfer_encoding: Option<&[u8]> = None;

    for header in headers {
        if header.name.eq_ignore_ascii_case(CONTENT_LENGTH) {
            if contains_line_break(header.value) {
                return Err(FramingError::ObsoleteFolding);
            }
            if content_length.is_some() {
                return Err(FramingError::DuplicateContentLength);
            }
            let value = trim_ows(header.value);
            let length = parse_content_length(value).ok_or(FramingError::InvalidContentLength)?;
            content_length = Some(length);
        } else if header.name.eq_ignore_ascii_case(TRANSFER_ENCODING) {
            if contains_line_break(header.value) {
                return Err(FramingError::ObsoleteFolding);
            }
            if transfer_encoding.is_some() {
                // Multiple Transfer-Encoding lines are a single comma joined
                // list per spec, but agents disagree on how to combine them;
                // treat any repetition as ambiguous and fail closed.
                return Err(FramingError::InvalidTransferEncoding);
            }
            transfer_encoding = Some(header.value);
        }
    }

    match (transfer_encoding, content_length) {
        (Some(..), Some(..)) => Err(FramingError::TransferEncodingAndContentLength),
        (Some(encoding), None) => {
            if !is_http_11 {
                return Err(FramingError::TransferEncodingOnHttp10);
            }
            match parse_transfer_encoding(encoding) {
                Some(true) => Ok(Framing::Chunked),
                Some(false) => Err(FramingError::TransferEncodingNotChunked),
                None => Err(FramingError::InvalidTransferEncoding),
            }
        }
        (None, Some(length)) => Ok(Framing::Length(length)),
        (None, None) => Ok(Framing::None),
    }
}

#[inline]
fn contains_line_break(value: &[u8]) -> bool {
    value.iter().any(|b| *b == b'\r' || *b == b'\n')
}

#[inline]
fn trim_ows(value: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = value.len();
    while start < end && is_ows(value[start]) {
        start += 1;
    }
    while end > start && is_ows(value[end - 1]) {
        end -= 1;
    }
    &value[start..end]
}

#[inline]
fn is_ows(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Parse a Content-Length value that has already had OWS trimmed.
///
/// RFC 9112 requires a single decimal integer with no internal whitespace or
/// other characters.
fn parse_content_length(value: &[u8]) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    let mut length: u64 = 0;
    for b in value {
        let digit = match b {
            b'0'..=b'9' => (*b - b'0') as u64,
            _ => return None,
        };
        length = length.checked_mul(10)?.checked_add(digit)?;
    }
    Some(length)
}

/// Validate a `Transfer-Encoding` value as a comma-separated list of transfer
/// codings and report whether the final coding is `chunked`.
///
/// Returns `None` for any value that is not a strict, unambiguous list:
/// empty elements, empty/whitespace-only codings, or whitespace inside a
/// coding name are all rejected. A coding may carry parameters, in which case
/// only the coding name itself is inspected.
fn parse_transfer_encoding(value: &[u8]) -> Option<bool> {
    let mut chunked = false;
    let mut any = false;
    for coding in value.split(|b| *b == b',') {
        any = true;
        let coding = trim_ows(coding);
        if coding.is_empty() {
            return None;
        }
        // A transfer coding is a token name optionally followed by
        // `;`-separated parameters. Any OWS inside the name itself is
        // invalid: only OWS surrounding parameters is allowed.
        let name = match coding.iter().position(|b| *b == b';') {
            Some(index) => trim_ows(&coding[..index]),
            None => coding,
        };
        if name.is_empty() || name.iter().any(|b| is_ows(*b)) {
            return None;
        }
        chunked = name.eq_ignore_ascii_case(b"chunked");
    }
    if any {
        Some(chunked)
    } else {
        None
    }
}
