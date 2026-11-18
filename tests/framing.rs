use httparse::framing::{determine_framing, Framing, FramingError};
use httparse::{Header, Request, Response, EMPTY_HEADER};

const NUM_OF_HEADERS: usize = 16;

fn request_framing(buf: &[u8]) -> Result<Framing, FramingError> {
    let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    let mut req = Request::new(&mut headers[..]);
    let status = req.parse(buf).expect("request should parse");
    assert!(status.is_complete(), "request should be complete");
    req.framing()
}

fn response_framing(buf: &[u8]) -> Result<Framing, FramingError> {
    let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    let mut res = Response::new(&mut headers[..]);
    let status = res.parse(buf).expect("response should parse");
    assert!(status.is_complete(), "response should be complete");
    res.framing()
}

/// Runs the exact same header block through both the request and the response
/// parsing paths and asserts they reach the same framing verdict.
fn assert_both(head: &str, expected: Result<Framing, FramingError>) {
    let request = format!("POST / HTTP/1.1\r\n{head}\r\n");
    let response = format!("HTTP/1.1 200 OK\r\n{head}\r\n");
    assert_eq!(request_framing(request.as_bytes()), expected);
    assert_eq!(response_framing(response.as_bytes()), expected);
}

#[test]
fn no_framing_headers_is_none() {
    assert_both("Host: example.com\r\n", Ok(Framing::None));
}

#[test]
fn single_content_length() {
    assert_both("Content-Length: 42\r\n", Ok(Framing::Length(42)));
}

#[test]
fn content_length_trims_surrounding_ows() {
    assert_both("Content-Length: \t42 \r\n", Ok(Framing::Length(42)));
}

#[test]
fn content_length_zero() {
    assert_both("Content-Length: 0\r\n", Ok(Framing::Length(0)));
}

#[test]
fn chunked_transfer_encoding() {
    assert_both("Transfer-Encoding: chunked\r\n", Ok(Framing::Chunked));
}

#[test]
fn chunked_transfer_encoding_case_insensitive() {
    assert_both("Transfer-Encoding: ChUnKeD\r\n", Ok(Framing::Chunked));
}

#[test]
fn transfer_encoding_list_ending_in_chunked() {
    assert_both("Transfer-Encoding: gzip, chunked\r\n", Ok(Framing::Chunked));
}

#[test]
fn transfer_encoding_with_parameter_ending_in_chunked() {
    assert_both(
        "Transfer-Encoding: gzip;level=1, chunked\r\n",
        Ok(Framing::Chunked),
    );
}

#[test]
fn duplicate_ordinary_headers_remain_readable() {
    let buf = b"POST / HTTP/1.1\r\nX-A: one\r\nX-A: two\r\nContent-Length: 0\r\n\r\n";
    let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    let mut req = Request::new(&mut headers[..]);
    req.parse(buf).unwrap();

    let values: Vec<&[u8]> = req
        .headers
        .iter()
        .filter(|h| h.name == "X-A")
        .map(|h| h.value)
        .collect();
    assert_eq!(values, vec![b"one".as_slice(), b"two".as_slice()]);
    assert_eq!(req.framing(), Ok(Framing::Length(0)));
}

#[test]
fn transfer_encoding_and_content_length_fails_closed() {
    assert_both(
        "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n",
        Err(FramingError::TransferEncodingAndContentLength),
    );
    assert_both(
        "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n",
        Err(FramingError::TransferEncodingAndContentLength),
    );
}

#[test]
fn duplicate_content_length_fails_closed_even_when_identical() {
    assert_both(
        "Content-Length: 42\r\nContent-Length: 42\r\n",
        Err(FramingError::DuplicateContentLength),
    );
}

#[test]
fn duplicate_content_length_with_differing_values_fails_closed() {
    assert_both(
        "Content-Length: 42\r\nContent-Length: 43\r\n",
        Err(FramingError::DuplicateContentLength),
    );
}

#[test]
fn content_length_combined_list_fails_closed() {
    // A single header line carrying a comma-separated list is not a valid
    // Content-Length value, even though some agents split it.
    assert_both(
        "Content-Length: 42, 42\r\n",
        Err(FramingError::InvalidContentLength),
    );
}

#[test]
fn content_length_with_internal_whitespace_fails_closed() {
    assert_both(
        "Content-Length: 4 2\r\n",
        Err(FramingError::InvalidContentLength),
    );
    assert_both(
        "Content-Length: 4\t2\r\n",
        Err(FramingError::InvalidContentLength),
    );
}

#[test]
fn content_length_with_sign_or_garbage_fails_closed() {
    assert_both(
        "Content-Length: +42\r\n",
        Err(FramingError::InvalidContentLength),
    );
    assert_both(
        "Content-Length: 0x2a\r\n",
        Err(FramingError::InvalidContentLength),
    );
    assert_both(
        "Content-Length:   \r\n",
        Err(FramingError::InvalidContentLength),
    );
}

#[test]
fn content_length_overflow_fails_closed() {
    assert_both(
        "Content-Length: 999999999999999999999999999999\r\n",
        Err(FramingError::InvalidContentLength),
    );
}

#[test]
fn transfer_encoding_not_chunked_fails_closed() {
    assert_both(
        "Transfer-Encoding: gzip\r\n",
        Err(FramingError::TransferEncodingNotChunked),
    );
    assert_both(
        "Transfer-Encoding: chunked, gzip\r\n",
        Err(FramingError::TransferEncodingNotChunked),
    );
}

#[test]
fn malformed_transfer_encoding_fails_closed() {
    assert_both(
        "Transfer-Encoding: chunked,\r\n",
        Err(FramingError::InvalidTransferEncoding),
    );
    assert_both(
        "Transfer-Encoding: ,chunked\r\n",
        Err(FramingError::InvalidTransferEncoding),
    );
    assert_both(
        "Transfer-Encoding: chu nked\r\n",
        Err(FramingError::InvalidTransferEncoding),
    );
}

#[test]
fn duplicate_transfer_encoding_fails_closed() {
    assert_both(
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
        Err(FramingError::InvalidTransferEncoding),
    );
}

#[test]
fn transfer_encoding_on_http_1_0_fails_closed() {
    let request = b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n";
    let response = b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert_eq!(
        request_framing(request),
        Err(FramingError::TransferEncodingOnHttp10)
    );
    assert_eq!(
        response_framing(response),
        Err(FramingError::TransferEncodingOnHttp10)
    );
}

#[test]
fn content_length_on_http_1_0_is_accepted() {
    let request = b"POST / HTTP/1.0\r\nContent-Length: 7\r\n\r\n";
    let response = b"HTTP/1.0 200 OK\r\nContent-Length: 7\r\n\r\n";
    assert_eq!(request_framing(request), Ok(Framing::Length(7)));
    assert_eq!(response_framing(response), Ok(Framing::Length(7)));
}

#[test]
fn obs_fold_in_content_length_fails_closed() {
    let mut config = httparse::ParserConfig::default();
    let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    let mut res = Response::new(&mut headers[..]);
    let buf = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n 2\r\n\r\n";
    config
        .allow_obsolete_multiline_headers_in_responses(true)
        .parse_response(&mut res, buf)
        .expect("folded header parses when enabled");

    // The raw folded header is still exposed...
    assert_eq!(res.headers.len(), 1);
    assert_eq!(res.headers[0].name, "Content-Length");
    assert_eq!(res.headers[0].value, b"4\r\n 2");
    // ...but framing refuses to interpret it.
    assert_eq!(res.framing(), Err(FramingError::ObsoleteFolding));
}

#[test]
fn obs_fold_in_transfer_encoding_fails_closed() {
    let mut config = httparse::ParserConfig::default();
    let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    let mut res = Response::new(&mut headers[..]);
    let buf = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chu\r\n nked\r\n\r\n";
    config
        .allow_obsolete_multiline_headers_in_responses(true)
        .parse_response(&mut res, buf)
        .expect("folded header parses when enabled");

    assert_eq!(res.headers[0].value, b"chu\r\n nked");
    assert_eq!(res.framing(), Err(FramingError::ObsoleteFolding));
}

#[test]
fn framing_headers_are_case_insensitive() {
    assert_both("cOnTeNt-LeNgTh: 5\r\n", Ok(Framing::Length(5)));
    assert_both("tRaNsFeR-eNcOdInG: Chunked\r\n", Ok(Framing::Chunked));
}

#[test]
fn header_name_whitespace_obfuscation_does_not_hide_framing() {
    // A space after a header name is not part of the name, so this is still
    // recognized as Content-Length when lenient response parsing enables it.
    let buf = b"HTTP/1.1 200 OK\r\nContent-Length : 5\r\n\r\n";
    let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    let mut res = Response::new(&mut headers[..]);
    httparse::ParserConfig::default()
        .allow_spaces_after_header_name_in_responses(true)
        .parse_response(&mut res, buf)
        .expect("response parses with lenient header name spacing");
    assert_eq!(res.framing(), Ok(Framing::Length(5)));
}

#[test]
fn line_tab_in_transfer_encoding_is_rejected() {
    assert_both("Transfer-Encoding:\tchunked\r\n", Ok(Framing::Chunked));
    assert_both("Transfer-Encoding: chunked\t\r\n", Ok(Framing::Chunked));
    assert_both(
        "Transfer-Encoding: chun\tked\r\n",
        Err(FramingError::InvalidTransferEncoding),
    );
}

#[test]
fn framing_error_does_not_mutate_or_hide_raw_headers() {
    let buf = b"POST / HTTP/1.1\r\n\
        Content-Length: 4\r\n\
        Transfer-Encoding: chunked\r\n\
        X-Ordinary: kept\r\n\r\n";
    let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    let mut req = Request::new(&mut headers[..]);
    req.parse(buf).unwrap();

    assert_eq!(
        req.framing(),
        Err(FramingError::TransferEncodingAndContentLength)
    );

    // The same ambiguous raw headers remain fully visible to the caller,
    // including the unrelated ordinary header.
    let names: Vec<&str> = req.headers.iter().map(|h| h.name).collect();
    assert_eq!(
        names,
        vec!["Content-Length", "Transfer-Encoding", "X-Ordinary"]
    );

    // Calling again is deterministic: there is no hidden consumed state.
    assert_eq!(
        req.framing(),
        Err(FramingError::TransferEncodingAndContentLength)
    );
}

#[test]
fn body_offset_from_parse_is_unaffected_by_framing_check() {
    let buf = b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
    let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    let mut req = Request::new(&mut headers[..]);
    let status = req.parse(buf).unwrap();
    let body_offset = match status {
        httparse::Status::Complete(offset) => offset,
        httparse::Status::Partial => panic!("should be complete"),
    };
    assert_eq!(&buf[body_offset..], b"hello");
    assert_eq!(req.framing(), Ok(Framing::Length(5)));
}

#[test]
fn free_function_agrees_with_methods_on_raw_headers() {
    let buf = b"POST / HTTP/1.1\r\nContent-Length: 9\r\nX-Keep: a\r\n\r\n";
    let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
    let mut req = Request::new(&mut headers[..]);
    req.parse(buf).unwrap();

    assert_eq!(determine_framing(req.headers, true), Ok(Framing::Length(9)));
    assert_eq!(req.framing(), determine_framing(req.headers, true));
}

#[test]
fn empty_header_slice_is_none() {
    let headers: [Header<'_>; 0] = [];
    assert_eq!(determine_framing(&headers, true), Ok(Framing::None));
}

#[test]
fn framing_error_is_displayable() {
    let err = FramingError::TransferEncodingAndContentLength;
    assert!(!format!("{err}").is_empty());
    #[cfg(feature = "std")]
    let boxed: Box<dyn std::error::Error> = Box::new(err);
    #[cfg(feature = "std")]
    assert_eq!(
        boxed.to_string(),
        "message contains both Transfer-Encoding and Content-Length"
    );
}
