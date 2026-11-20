// Copyright (C) 2026 Stacks Open Internet Foundation
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

//! `/bench/v1/...` endpoints, only compiled with the `bench-hooks` feature.
//!
//! These are not part of the public `/v2` and `/v3` API. They control the node at runtime for
//! benchmarking, one namespace per subsystem, and require the `Authorization` header to match
//! `connection_options.auth_token` (disabled when no token is configured).

use crate::net::http::{Error, HttpRequestPreamble};

pub mod miner;

/// Reject the request unless it carries the node's auth token.
fn check_auth(auth: &Option<String>, preamble: &HttpRequestPreamble) -> Result<(), Error> {
    // If no authorization is set, then the bench endpoints are not enabled
    let Some(password) = auth else {
        return Err(Error::Http(400, "Bad Request.".into()));
    };
    let Some(auth_header) = preamble.headers.get("authorization") else {
        return Err(Error::Http(401, "Unauthorized".into()));
    };
    if auth_header != password {
        return Err(Error::Http(401, "Unauthorized".into()));
    }
    Ok(())
}
