// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::io::{Read, Write};
use std::{io, str};

use hashbrown::HashMap;
use stacks_common::util::chunked_encoding::*;

use crate::error::{EventError, RPCError};
use crate::http::{decode_http_body, decode_http_request, decode_http_response, run_http_request};

#[test]
fn test_decode_http_request_ok() {
    let tests = vec![
        ("GET /foo HTTP/1.1\r\nHost: localhost:6270\r\n\r\n",
        ("GET", "/foo", vec![("host", "localhost:6270")])),
        ("POST asdf HTTP/1.1\r\nHost: core.blockstack.org\r\nFoo: Bar\r\n\r\n",
        ("POST", "asdf", vec![("host", "core.blockstack.org"), ("foo", "Bar")])),
        ("POST asdf HTTP/1.1\r\nHost: core.blockstack.org\r\nFoo: Bar\r\n\r\n",
        ("POST", "asdf", vec![("host", "core.blockstack.org"), ("foo", "Bar")])),
        ("GET /foo HTTP/1.1\r\nConnection: close\r\nHost: localhost:6270\r\n\r\n",
        ("GET", "/foo", vec![("connection", "close"), ("host", "localhost:6270")])),
        ("POST asdf HTTP/1.1\r\nHost: core.blockstack.org\r\nConnection: close\r\nFoo: Bar\r\n\r\n",
        ("POST", "asdf", vec![("host", "core.blockstack.org"), ("connection", "close"), ("foo", "Bar")])),
        ("POST asdf HTTP/1.1\r\nHost: core.blockstack.org\r\nFoo: Bar\r\nConnection: close\r\n\r\n",
        ("POST", "asdf", vec![("host", "core.blockstack.org"), ("foo", "Bar"), ("connection", "close")])),
        ("GET /foo HTTP/1.1\r\nhOsT: localhost:6270\r\n\r\n",
        ("GET", "/foo", vec![("host", "localhost:6270")])),
        ("GET /foo HTTP/1.1\r\ncOnNeCtIoN: cLoSe\r\nhOsT: localhost:6270\r\n\r\n",
        ("GET", "/foo", vec![("connection", "cLoSe"), ("host", "localhost:6270")])),
        ("POST asdf HTTP/1.1\r\nhOsT: core.blockstack.org\r\nCOnNeCtIoN: kEeP-aLiVE\r\nFoo: Bar\r\n\r\n",
        ("POST", "asdf", vec![("host", "core.blockstack.org"), ("connection", "kEeP-aLiVE"), ("foo", "Bar")]))
    ];

    for (data, (expected_verb, expected_path, headers_list)) in tests.iter() {
        let mut expected_headers = HashMap::new();
        for (key, val) in headers_list.iter() {
            expected_headers.insert(key.to_string(), val.to_string());
        }

        let (verb, path, headers, _) = decode_http_request(data.as_bytes()).unwrap().destruct();
        assert_eq!(verb, expected_verb.to_string());
        assert_eq!(path, expected_path.to_string());
        assert_eq!(headers, expected_headers);
    }
}

#[test]
fn test_decode_http_request_err() {
    let tests = vec![
        (
            "GET /foo HTTP/1.1\r\n",
            EventError::Deserialize("".to_string()),
        ),
        (
            "GET /foo HTTP/\r\n\r\n",
            EventError::Deserialize("".to_string()),
        ),
        (
            "GET /foo HTTP/1.1\r\nHost:",
            EventError::Deserialize("".to_string()),
        ),
        (
            "GET /foo HTTP/1.1\r\nHost: foo:80\r\nHost: bar:80\r\n\r\n",
            EventError::MalformedRequest("".to_string()),
        ),
        (
            "GET /foo HTTP/1.1\r\nHost: localhost:6270\r\nfoo: \u{2764}\r\n\r\n",
            EventError::MalformedRequest("".to_string()),
        ),
    ];

    for (data, expected_err_type) in tests.iter() {
        let err = decode_http_request(data.as_bytes()).unwrap_err();
        match (err, expected_err_type) {
            (EventError::Deserialize(..), EventError::Deserialize(..)) => {}
            (EventError::MalformedRequest(..), EventError::MalformedRequest(..)) => {}
            (x, y) => {
                error!("expected error mismatch: {:?} != {:?}", &y, &x);
                panic!();
            }
        }
    }
}

#[test]
fn test_decode_http_response_ok() {
    let tests = vec![
        ("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 123\r\nX-Request-ID: 0\r\n\r\n",
        vec![("content-type", "application/octet-stream"), ("content-length", "123"), ("x-request-id", "0")]),
        ("HTTP/1.1 200 Ok\r\nContent-Type: application/octet-stream\r\nTransfer-encoding: chunked\r\nX-Request-ID: 0\r\n\r\n",
        vec![("content-type", "application/octet-stream"), ("transfer-encoding", "chunked"), ("x-request-id", "0")]),
        ("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 123\r\nConnection: close\r\nX-Request-ID: 0\r\n\r\n",
        vec![("content-type", "application/octet-stream"), ("content-length", "123"), ("connection", "close"), ("x-request-id", "0")]),
        ("HTTP/1.1 200 Ok\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nTransfer-encoding: chunked\r\nX-Request-ID: 0\r\n\r\n",
        vec![("connection", "close"), ("content-type", "application/octet-stream"), ("transfer-encoding", "chunked"), ("x-request-id", "0")])
    ];

    for (data, header_list) in tests.iter() {
        let mut expected_headers = HashMap::new();
        for (key, val) in header_list.iter() {
            expected_headers.insert(key.to_string(), val.to_string());
        }

        let (headers, _) = decode_http_response(data.as_bytes()).unwrap();
        assert_eq!(headers, expected_headers);
    }
}

#[test]
fn test_decode_http_response_err() {
    let tests = vec![
        ("HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 456\r\nFoo: Bar\r\nX-Request-ID: 0\r\n\r\n",
         RPCError::HttpError(400)),
        ("HTTP/1.1 200",
         RPCError::Deserialize("".to_string())),
        ("HTTP/1.1 200 OK\r\nfoo: \u{2764}\r\n\r\n",
         RPCError::MalformedResponse("".to_string())),
        ("HTTP/1.1 200 OK\r\nfoo: bar\r\nfoo: bar\r\n\r\n",
         RPCError::MalformedResponse("".to_string())),
    ];

    for (data, expected_err_type) in tests.iter() {
        let err_type = decode_http_response(data.as_bytes()).unwrap_err();
        match (err_type, expected_err_type) {
            (RPCError::HttpError(x), RPCError::HttpError(y)) => assert_eq!(x, *y),
            (RPCError::Deserialize(_), RPCError::Deserialize(_)) => {}
            (RPCError::MalformedResponse(_), RPCError::MalformedResponse(_)) => {}
            (x, y) => {
                error!("expected error mismatch: {:?} != {:?}", &y, &x);
                panic!();
            }
        }
    }
}

#[test]
fn test_decode_http_body() {
    let tests = [
        (true, ""),
        (true, "this is the song that never ends"),
        (false, ""),
        (false, "this is the song that never ends"),
    ];
    for (chunked, expected_body) in tests.iter() {
        let (headers, encoded_body) = if *chunked {
            let mut hdrs = HashMap::new();
            hdrs.insert("transfer-encoding".to_string(), "chunked".to_string());

            let mut state = HttpChunkedTransferWriterState::new(5);
            let mut buf = vec![];
            let body_bytes = expected_body.as_bytes().to_vec();
            let mut fd = HttpChunkedTransferWriter::from_writer_state(&mut buf, &mut state);
            fd.write_all(&body_bytes).unwrap();
            fd.flush().unwrap();
            (hdrs, buf)
        } else {
            let hdrs = HashMap::new();
            let body = expected_body.as_bytes().to_vec();
            (hdrs, body)
        };

        let body = decode_http_body(&headers, &encoded_body).unwrap();
        assert_eq!(&body[..], expected_body.as_bytes());
    }
}

/// Mock HTTP socket for testing `run_http_request()`.
/// Implements Read and Write.
/// On Read, returns a given pre-set reply.
/// Buffers all written data on Write
struct MockHTTPSocket {
    request: Vec<u8>,
    reply: Vec<u8>,
    ptr: usize,
}

impl MockHTTPSocket {
    fn new(reply: String) -> MockHTTPSocket {
        MockHTTPSocket {
            request: vec![],
            reply: reply.as_bytes().to_vec(),
            ptr: 0,
        }
    }
}

impl Read for MockHTTPSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut nr = 0;
        while nr < buf.len() && self.ptr < self.reply.len() {
            buf[nr] = self.reply[self.ptr];
            self.ptr += 1;
            nr += 1;
        }
        Ok(nr)
    }
}

impl Write for MockHTTPSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.request.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn test_run_http_request_with_body() {
    let tests = vec![
        ("GET", "/test-no-content-type-and-no-body", None, vec![]),
        (
            "GET",
            "/test-content-type-and-no-body",
            Some("application/octet-stream"),
            vec![],
        ),
        (
            "GET",
            "/test-no-content-type-and-body",
            None,
            "hello world".as_bytes().to_vec(),
        ),
        (
            "GET",
            "/test-content-type-and-body",
            Some("application/octet-stream"),
            "hello world".as_bytes().to_vec(),
        ),
    ];

    for (verb, path, content_type, payload) in tests.into_iter() {
        // test with chunking
        let mut state = HttpChunkedTransferWriterState::new(5);
        let mut buf = vec![];
        let body_bytes = "this is the song that never ends".as_bytes().to_vec();
        let mut fd = HttpChunkedTransferWriter::from_writer_state(&mut buf, &mut state);
        fd.write_all(&body_bytes).unwrap();
        fd.flush().unwrap();

        let mut msock_chunked = MockHTTPSocket::new(format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n{}", str::from_utf8(&buf).unwrap()));

        // test without chunking
        let mut msock_plain = MockHTTPSocket::new(format!(
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-type: text/plain\r\n\r\n{}",
            str::from_utf8(&body_bytes).unwrap()
        ));

        let result_chunked = run_http_request(
            &mut msock_chunked,
            "127.0.0.1:20443",
            verb,
            path,
            content_type,
            &payload,
        )
        .unwrap();
        assert_eq!(result_chunked, body_bytes);

        let result_plain = run_http_request(
            &mut msock_plain,
            "127.0.0.1:20443",
            verb,
            path,
            content_type,
            &payload,
        )
        .unwrap();
        assert_eq!(result_plain, body_bytes);
    }
}

#[test]
fn test_run_http_request_no_body() {
    let tests = vec![
        ("GET", "/test-no-content-type-and-no-body", None, vec![]),
        (
            "GET",
            "/test-content-type-and-no-body",
            Some("application/octet-stream"),
            vec![],
        ),
        (
            "GET",
            "/test-no-content-type-and-body",
            None,
            "hello world".as_bytes().to_vec(),
        ),
        (
            "GET",
            "/test-content-type-and-body",
            Some("application/octet-stream"),
            "hello world".as_bytes().to_vec(),
        ),
    ];

    for (verb, path, content_type, payload) in tests.into_iter() {
        // test with chunking
        let mut msock_chunked = MockHTTPSocket::new("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n".to_string());

        // test without chunking
        let mut msock_plain = MockHTTPSocket::new(
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-type: text/plain\r\n\r\n".to_string(),
        );

        let result_chunked = run_http_request(
            &mut msock_chunked,
            "127.0.0.1:20443",
            verb,
            path,
            content_type,
            &payload,
        )
        .unwrap();
        let result_plain = run_http_request(
            &mut msock_plain,
            "127.0.0.1:20443",
            verb,
            path,
            content_type,
            &payload,
        )
        .unwrap();

        assert_eq!(result_chunked.len(), 0);
        assert_eq!(result_plain.len(), 0);
    }
}
