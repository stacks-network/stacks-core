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

use std::io;
use std::io::Read;

use serde_json;
use stacks_common::codec::MAX_MESSAGE_LEN;
use stacks_common::util::retry::BoundReader;

use crate::net::http::response::HttpResponse;
use crate::net::http::{Error, HttpContentType, HttpResponsePayload, HttpResponsePreamble};

/// Default implementation of `try_parse_response()` for an HTTP error message that implements
/// `HttpReqeust`.
pub fn try_parse_error_response(
    status_code: u16,
    content_type: HttpContentType,
    body: &[u8],
) -> Result<HttpResponsePayload, Error> {
    if status_code < 400 || status_code > 599 {
        return Err(Error::DecodeError(
            "Inavlid response: not an error".to_string(),
        ));
    }

    if content_type == HttpContentType::Text {
        let mut error_text = String::new();
        let mut ioc = io::Cursor::new(body);
        let mut bound_fd =
            BoundReader::from_reader(&mut ioc, body.len().min(MAX_MESSAGE_LEN as usize) as u64);
        bound_fd
            .read_to_string(&mut error_text)
            .map_err(Error::ReadError)?;

        Ok(HttpResponsePayload::Text(error_text))
    } else if content_type == HttpContentType::JSON {
        let mut ioc = io::Cursor::new(body);
        let mut bound_fd =
            BoundReader::from_reader(&mut ioc, body.len().min(MAX_MESSAGE_LEN as usize) as u64);
        let json_val = serde_json::from_reader(&mut bound_fd)
            .map_err(|_| Error::DecodeError("Failed to decode JSON".to_string()))?;

        Ok(HttpResponsePayload::JSON(json_val))
    } else {
        return Err(Error::DecodeError(format!(
            "Invalid error response: expected text/plain or application/json, got {:?}",
            &content_type
        )));
    }
}

/// Decode an HTTP status code into a reason
pub fn http_reason(code: u16) -> &'static str {
    match code {
        // from RFC 2616
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Time-out",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Request Entity Too Large",
        414 => "Request-URI Too Large",
        415 => "Unsupported Media Type",
        416 => "Requested range not satisfiable",
        417 => "Expectation Failed",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Time-out",
        505 => "HTTP Version not supported",
        _ => "Custom",
    }
}

/// Make HTTP error responses distinct from HttpResponses
pub trait HttpErrorResponse {
    fn code(&self) -> u16;
    fn payload(&self) -> HttpResponsePayload;
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error>;
}

pub fn http_error_from_code_and_text(code: u16, message: String) -> Box<dyn HttpErrorResponse> {
    match code {
        400 => Box::new(HttpBadRequest::new(message)),
        401 => Box::new(HttpUnauthorized::new(message)),
        402 => Box::new(HttpPaymentRequired::new(message)),
        403 => Box::new(HttpForbidden::new(message)),
        404 => Box::new(HttpNotFound::new(message)),
        500 => Box::new(HttpServerError::new(message)),
        503 => Box::new(HttpServiceUnavailable::new(message)),
        _ => Box::new(HttpError::new(code, message)),
    }
}

/// HTTP 400
pub struct HttpBadRequest {
    error_text: String,
    content_type: HttpContentType,
}

impl HttpBadRequest {
    pub fn new(error_text: String) -> Self {
        Self {
            error_text,
            content_type: HttpContentType::Text,
        }
    }

    pub fn new_json(value: serde_json::Value) -> Self {
        Self {
            // this .expect() should never be reachable
            error_text: serde_json::to_string(&value)
                .expect("FATAL: could not serialize JSON value to string"),
            content_type: HttpContentType::JSON,
        }
    }
}

impl HttpErrorResponse for HttpBadRequest {
    fn code(&self) -> u16 {
        400
    }
    fn payload(&self) -> HttpResponsePayload {
        if self.content_type == HttpContentType::JSON {
            // the inner error_text is serialized from a JSON value, so it should always parse
            // back to JSON.
            return HttpResponsePayload::JSON(serde_json::from_str(&self.error_text)
                                                .unwrap_or(serde_json::from_str(
                                                            "{\"error\": \"Failed to decode serialized JSON text. This is a bug in the Stacks node or in serde_json.\"}"
                                                           ).expect("FATAL: failed to decode known-good constant JSON string")));
        } else {
            HttpResponsePayload::Text(self.error_text.clone())
        }
    }
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        try_parse_error_response(preamble.status_code, preamble.content_type, body)
    }
}

/// HTTP 401
pub struct HttpUnauthorized {
    error_text: String,
}

impl HttpUnauthorized {
    pub fn new(error_text: String) -> Self {
        Self { error_text }
    }
}

impl HttpErrorResponse for HttpUnauthorized {
    fn code(&self) -> u16 {
        401
    }
    fn payload(&self) -> HttpResponsePayload {
        HttpResponsePayload::Text(self.error_text.clone())
    }
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        try_parse_error_response(preamble.status_code, preamble.content_type, body)
    }
}

/// HTTP 402
pub struct HttpPaymentRequired {
    error_text: String,
}

impl HttpPaymentRequired {
    pub fn new(error_text: String) -> Self {
        Self { error_text }
    }
}

impl HttpErrorResponse for HttpPaymentRequired {
    fn code(&self) -> u16 {
        402
    }
    fn payload(&self) -> HttpResponsePayload {
        HttpResponsePayload::Text(self.error_text.clone())
    }
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        try_parse_error_response(preamble.status_code, preamble.content_type, body)
    }
}

/// HTTP 403
pub struct HttpForbidden {
    error_text: String,
}

impl HttpForbidden {
    pub fn new(error_text: String) -> Self {
        Self { error_text }
    }
}

impl HttpErrorResponse for HttpForbidden {
    fn code(&self) -> u16 {
        403
    }
    fn payload(&self) -> HttpResponsePayload {
        HttpResponsePayload::Text(self.error_text.clone())
    }
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        try_parse_error_response(preamble.status_code, preamble.content_type, body)
    }
}

/// HTTP 404
pub struct HttpNotFound {
    error_text: String,
}

impl HttpNotFound {
    pub fn new(error_text: String) -> Self {
        Self { error_text }
    }
}

impl HttpErrorResponse for HttpNotFound {
    fn code(&self) -> u16 {
        404
    }
    fn payload(&self) -> HttpResponsePayload {
        HttpResponsePayload::Text(self.error_text.clone())
    }
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        try_parse_error_response(preamble.status_code, preamble.content_type, body)
    }
}

/// HTTP 500
pub struct HttpServerError {
    error_text: String,
}

impl HttpServerError {
    pub fn new(error_text: String) -> Self {
        Self { error_text }
    }
}

impl HttpErrorResponse for HttpServerError {
    fn code(&self) -> u16 {
        500
    }
    fn payload(&self) -> HttpResponsePayload {
        HttpResponsePayload::Text(self.error_text.clone())
    }
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        try_parse_error_response(preamble.status_code, preamble.content_type, body)
    }
}

/// HTTP 503
pub struct HttpServiceUnavailable {
    error_text: String,
}

impl HttpServiceUnavailable {
    pub fn new(error_text: String) -> Self {
        Self { error_text }
    }
}

impl HttpErrorResponse for HttpServiceUnavailable {
    fn code(&self) -> u16 {
        503
    }
    fn payload(&self) -> HttpResponsePayload {
        HttpResponsePayload::Text(self.error_text.clone())
    }
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        try_parse_error_response(preamble.status_code, preamble.content_type, body)
    }
}

/// Catch-all for any other HTTP error response
pub struct HttpError {
    error: u16,
    error_text: String,
}

impl HttpError {
    pub fn new(error: u16, error_text: String) -> Self {
        Self { error, error_text }
    }
}

impl HttpErrorResponse for HttpError {
    fn code(&self) -> u16 {
        self.error
    }
    fn payload(&self) -> HttpResponsePayload {
        HttpResponsePayload::Text(self.error_text.clone())
    }
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        try_parse_error_response(preamble.status_code, preamble.content_type, body)
    }
}
