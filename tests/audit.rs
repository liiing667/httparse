use httparse::{
    Audit, Error, IgnoredFact, ParserConfig, Request, Response, RiskCategory, Status,
    EMPTY_HEADER,
};

fn audit_buf() -> [IgnoredFact; 16] {
    [IgnoredFact {
        offset: 0,
        len: 0,
        category: RiskCategory::MultipleSpacesDelimiter,
    }; 16]
}

fn categories(audit: &Audit<'_>) -> Vec<RiskCategory> {
    audit.facts().iter().map(|f| f.category).collect()
}

/// The same response input parsed under different combinations of relaxed
/// options must yield the expected ignore list and final Status each time.
const RESPONSE_INPUT: &[u8] =
    b"HTTP/1.1  200 OK\r\nFolded: a\r\n b\r\nBad Header\r\nHost: example.com\r\n\r\n";

#[test]
fn strict_default_rejects_and_records_nothing() {
    let mut headers = [EMPTY_HEADER; 16];
    let mut res = Response::new(&mut headers);
    let mut facts = audit_buf();
    let mut audit = Audit::new(&mut facts);

    let status = ParserConfig::default().parse_response_audited(&mut res, RESPONSE_INPUT, &mut audit);

    // Multiple spaces in the status line are rejected by the strict parser.
    assert_eq!(status, Err(Error::Status));
    assert!(audit.is_empty());
    assert_eq!(audit.dropped(), 0);
}

#[test]
fn multiple_spaces_only() {
    let mut headers = [EMPTY_HEADER; 16];
    let mut res = Response::new(&mut headers);
    let mut facts = audit_buf();
    let mut audit = Audit::new(&mut facts);

    let status = ParserConfig::default()
        .allow_multiple_spaces_in_response_status_delimiters(true)
        .parse_response_audited(&mut res, RESPONSE_INPUT, &mut audit);

    // The folded header is rejected next, but the spaces were already logged.
    assert_eq!(status, Err(Error::HeaderName));
    assert_eq!(
        categories(&audit),
        vec![RiskCategory::MultipleSpacesDelimiter]
    );
    assert_eq!(audit.facts()[0].offset, 9);
    assert_eq!(audit.facts()[0].len, 1);
}

#[test]
fn obs_fold_only() {
    let mut headers = [EMPTY_HEADER; 16];
    let mut res = Response::new(&mut headers);
    let mut facts = audit_buf();
    let mut audit = Audit::new(&mut facts);

    let status = ParserConfig::default()
        .allow_multiple_spaces_in_response_status_delimiters(true)
        .allow_obsolete_multiline_headers_in_responses(true)
        .parse_response_audited(&mut res, RESPONSE_INPUT, &mut audit);

    // The invalid `Bad Header` line is still rejected.
    assert_eq!(status, Err(Error::HeaderName));
    assert_eq!(
        categories(&audit),
        vec![
            RiskCategory::MultipleSpacesDelimiter,
            RiskCategory::ObsoleteLineFolding,
        ]
    );
}

#[test]
fn all_options_combined_complete_with_full_ignore_list() {
    let mut headers = [EMPTY_HEADER; 16];
    let mut res = Response::new(&mut headers);
    let mut facts = audit_buf();
    let mut audit = Audit::new(&mut facts);

    let status = ParserConfig::default()
        .allow_multiple_spaces_in_response_status_delimiters(true)
        .allow_obsolete_multiline_headers_in_responses(true)
        .ignore_invalid_headers_in_responses(true)
        .parse_response_audited(&mut res, RESPONSE_INPUT, &mut audit);

    assert_eq!(status, Ok(Status::Complete(RESPONSE_INPUT.len())));
    assert_eq!(
        categories(&audit),
        vec![
            RiskCategory::MultipleSpacesDelimiter,
            RiskCategory::ObsoleteLineFolding,
            RiskCategory::InvalidHeaderSkipped,
        ]
    );
    // The skipped header is gone from the parsed output, proving the parsed
    // message differs from the raw message on the wire.
    assert_eq!(res.headers.len(), 2);
    assert_eq!(res.headers[0].name, "Folded");
    assert_eq!(res.headers[0].value, b"a\r\n b");
    assert_eq!(res.headers[1].name, "Host");
}

#[test]
fn ignore_invalid_headers_only() {
    let input = b"HTTP/1.1 200 OK\r\nBad Header\r\nHost: example.com\r\n\r\n";
    let mut headers = [EMPTY_HEADER; 16];
    let mut res = Response::new(&mut headers);
    let mut facts = audit_buf();
    let mut audit = Audit::new(&mut facts);

    let status = ParserConfig::default()
        .ignore_invalid_headers_in_responses(true)
        .parse_response_audited(&mut res, input, &mut audit);

    assert_eq!(status, Ok(Status::Complete(input.len())));
    assert_eq!(categories(&audit), vec![RiskCategory::InvalidHeaderSkipped]);
    assert_eq!(res.headers.len(), 1);
    assert_eq!(res.headers[0].name, "Host");
}

#[test]
fn request_multiple_spaces_combinations() {
    let input = b"GET  /index  HTTP/1.1\r\nHost: example.com\r\n\r\n";

    // Strict: rejected, empty audit.
    let mut headers = [EMPTY_HEADER; 16];
    let mut req = Request::new(&mut headers);
    let mut facts = audit_buf();
    let mut audit = Audit::new(&mut facts);
    let status = ParserConfig::default().parse_request_audited(&mut req, input, &mut audit);
    assert_eq!(status, Err(Error::Token));
    assert!(audit.is_empty());

    // Relaxed: complete, one fact per tolerated multi-space delimiter.
    let mut headers = [EMPTY_HEADER; 16];
    let mut req = Request::new(&mut headers);
    let mut facts = audit_buf();
    let mut audit = Audit::new(&mut facts);
    let status = ParserConfig::default()
        .allow_multiple_spaces_in_request_line_delimiters(true)
        .parse_request_audited(&mut req, input, &mut audit);
    assert_eq!(status, Ok(Status::Complete(input.len())));
    assert_eq!(
        categories(&audit),
        vec![
            RiskCategory::MultipleSpacesDelimiter,
            RiskCategory::MultipleSpacesDelimiter,
        ]
    );
    assert_eq!((audit.facts()[0].offset, audit.facts()[0].len), (4, 1));
    assert_eq!((audit.facts()[1].offset, audit.facts()[1].len), (12, 1));
    assert_eq!(req.method, Some("GET"));
    assert_eq!(req.path, Some("/index"));
}

#[test]
fn space_before_first_header_is_audited() {
    let input = b"HTTP/1.1 200 OK\r\n Host: example.com\r\n\r\n";
    let mut headers = [EMPTY_HEADER; 16];
    let mut res = Response::new(&mut headers);
    let mut facts = audit_buf();
    let mut audit = Audit::new(&mut facts);

    let status = ParserConfig::default()
        .allow_space_before_first_header_name(true)
        .parse_response_audited(&mut res, input, &mut audit);

    assert_eq!(status, Ok(Status::Complete(input.len())));
    assert_eq!(
        categories(&audit),
        vec![RiskCategory::SpaceBeforeFirstHeader]
    );
    assert_eq!((audit.facts()[0].offset, audit.facts()[0].len), (17, 1));
}

#[test]
fn space_after_header_name_is_audited() {
    let input = b"HTTP/1.1 200 OK\r\nHost : example.com\r\n\r\n";
    let mut headers = [EMPTY_HEADER; 16];
    let mut res = Response::new(&mut headers);
    let mut facts = audit_buf();
    let mut audit = Audit::new(&mut facts);

    let status = ParserConfig::default()
        .allow_spaces_after_header_name_in_responses(true)
        .parse_response_audited(&mut res, input, &mut audit);

    assert_eq!(status, Ok(Status::Complete(input.len())));
    assert_eq!(
        categories(&audit),
        vec![RiskCategory::SpaceAfterHeaderName]
    );
    assert_eq!(res.headers[0].name, "Host");
    assert_eq!(res.headers[0].value, b"example.com");
}

#[test]
fn overflowing_audit_buffer_counts_dropped_facts() {
    let input = b"HTTP/1.1 200 OK\r\nBad One\r\nBad Two\r\nHost: example.com\r\n\r\n";
    let mut headers = [EMPTY_HEADER; 16];
    let mut res = Response::new(&mut headers);
    let mut facts = audit_buf();
    let mut audit = Audit::new(&mut facts[..1]);

    let status = ParserConfig::default()
        .ignore_invalid_headers_in_responses(true)
        .parse_response_audited(&mut res, input, &mut audit);

    assert_eq!(status, Ok(Status::Complete(input.len())));
    assert_eq!(audit.len(), 1);
    assert_eq!(audit.dropped(), 1);
    assert!(!audit.is_empty());
}

#[test]
fn existing_api_still_works_and_stays_strict() {
    // The pre-existing entry points are untouched and remain strict.
    let mut headers = [EMPTY_HEADER; 16];
    let mut req = Request::new(&mut headers);
    assert_eq!(
        req.parse(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        Ok(Status::Complete(37))
    );

    let mut headers = [EMPTY_HEADER; 16];
    let mut req = Request::new(&mut headers);
    assert_eq!(req.parse(b"GET  / HTTP/1.1\r\n\r\n"), Err(Error::Token));

    let mut headers = [EMPTY_HEADER; 16];
    let mut res = Response::new(&mut headers);
    assert_eq!(
        res.parse(b"HTTP/1.1 200 OK\r\nBad Header\r\n\r\n"),
        Err(Error::HeaderName)
    );
}
