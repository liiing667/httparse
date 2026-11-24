use httparse::{Error, ParserConfig, Request, Status, EMPTY_HEADER};

const NUM_HEADERS: usize = 4;

fn parse<'buf>(
    request: &mut Request<'_, 'buf>,
    buf: &'buf [u8],
    allow_multiple_spaces: bool,
) -> httparse::Result<usize> {
    ParserConfig::default()
        .allow_multiple_spaces_in_request_line_delimiters(allow_multiple_spaces)
        .parse_request(request, buf)
}

#[test]
fn failed_uri_parse_does_not_keep_previous_path() {
    let good = b"GET /old-path HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let bad_requests: &[&[u8]] = &[
        b"GET /foo\x7fbar HTTP/1.1\r\n\r\n",
        b"GET /foo\x80bar HTTP/1.1\r\n\r\n",
        b"GET /foo\tbar HTTP/1.1\r\n\r\n",
        b"GET /foo\x0bbar HTTP/1.1\r\n\r\n",
        b"GET /foo\x0cbar HTTP/1.1\r\n\r\n",
        b"GET /foo bar HTTP/1.1\r\n\r\n",
    ];

    for bad in bad_requests {
        for allow_multiple_spaces in [false, true] {
            let mut headers = [EMPTY_HEADER; NUM_HEADERS];
            let mut request = Request::new(&mut headers);

            assert_eq!(
                parse(&mut request, good, false),
                Ok(Status::Complete(good.len()))
            );
            assert_eq!(request.path, Some("/old-path"));

            let result = parse(&mut request, bad, allow_multiple_spaces);
            assert!(
                matches!(result, Err(Error::Token) | Err(Error::Version)),
                "unexpected result {result:?} for {bad:?}"
            );
            assert_eq!(request.path, None, "stale path for {bad:?}");
        }
    }
}

#[test]
fn reused_request_accepts_next_normal_path_after_failure() {
    let mut headers = [EMPTY_HEADER; NUM_HEADERS];
    let mut request = Request::new(&mut headers);

    assert_eq!(
        parse(&mut request, b"GET /ambiguous\x7f HTTP/1.1\r\n\r\n", false),
        Err(Error::Token)
    );
    assert_eq!(request.path, None);

    let good = b"POST /next HTTP/1.0\r\n\r\n";
    assert_eq!(
        parse(&mut request, good, false),
        Ok(Status::Complete(good.len()))
    );
    assert_eq!(request.method, Some("POST"));
    assert_eq!(request.path, Some("/next"));
    assert_eq!(request.version, Some(0));
}

#[test]
fn absolute_paths_and_multiple_space_delimiters_remain_supported() {
    struct Case {
        buf: &'static [u8],
        allow_multiple_spaces: bool,
        path: &'static str,
    }

    let cases = [
        Case {
            buf: b"GET /absolute/path?x=1 HTTP/1.1\r\n\r\n",
            allow_multiple_spaces: false,
            path: "/absolute/path?x=1",
        },
        Case {
            buf: b"GET  /absolute/path   HTTP/1.1\r\n\r\n",
            allow_multiple_spaces: true,
            path: "/absolute/path",
        },
        Case {
            buf: b"GET / HTTP/1.0\r\n\r\n",
            allow_multiple_spaces: false,
            path: "/",
        },
    ];

    for case in cases {
        let mut headers = [EMPTY_HEADER; NUM_HEADERS];
        let mut request = Request::new(&mut headers);
        assert_eq!(
            parse(&mut request, case.buf, case.allow_multiple_spaces),
            Ok(Status::Complete(case.buf.len()))
        );
        assert_eq!(request.path, Some(case.path));
    }
}
