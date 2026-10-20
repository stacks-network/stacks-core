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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::test_rpc;
use crate::bench_hooks::miner::MinerBenchCommand;
use crate::net::api::bench::miner::{
    RPCBenchMinerCommandRequestHandler, RPCBenchMinerStatusRequestHandler,
};
use crate::net::connection::ConnectionOptions;
use crate::net::http::Error as HttpError;
use crate::net::httpcore::{StacksHttp, StacksHttpRequest};
use crate::net::{Error as NetError, ProtocolFamily};

fn addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33333)
}

/// Parse `request` with `handler`, returning the HTTP status of a rejection.
fn parse_status<H: crate::net::httpcore::RPCRequestHandler>(
    handler: &mut H,
    request: &StacksHttpRequest,
) -> Result<(), u16> {
    let mut http = StacksHttp::new(addr(), &ConnectionOptions::default());
    let bytes = request.try_serialize().unwrap();
    let (preamble, offset) = http.read_preamble(&bytes).unwrap();
    let body = bytes.get(offset..).unwrap();
    match http.handle_try_parse_request(handler, &preamble.expect_request(), body) {
        Ok(_) => Ok(()),
        Err(NetError::Http(HttpError::Http(code, _))) => Err(code),
        Err(e) => panic!("unexpected parse error: {e:?}"),
    }
}

#[test]
fn test_try_parse_request() {
    let password = Some("password".to_string());

    let mut status = StacksHttpRequest::new_bench_miner_status(addr().into());
    let mut handler = RPCBenchMinerStatusRequestHandler::new(password.clone());
    // no Authorization header
    assert_eq!(parse_status(&mut handler, &status), Err(401));
    status.add_header("authorization".into(), "password".into());
    assert_eq!(parse_status(&mut handler, &status), Ok(()));
    // endpoint disabled without a configured token
    let mut disabled = RPCBenchMinerStatusRequestHandler::new(None);
    assert_eq!(parse_status(&mut disabled, &status), Err(400));

    let mut pause =
        StacksHttpRequest::new_bench_miner_command(addr().into(), MinerBenchCommand::PauseMining);
    pause.add_header("authorization".into(), "wrong".into());
    let mut handler = RPCBenchMinerCommandRequestHandler::new(password);
    assert_eq!(parse_status(&mut handler, &pause), Err(401));

    let mut pause =
        StacksHttpRequest::new_bench_miner_command(addr().into(), MinerBenchCommand::PauseMining);
    pause.add_header("authorization".into(), "password".into());
    assert_eq!(parse_status(&mut handler, &pause), Ok(()));
    assert_eq!(handler.command, Some(MinerBenchCommand::PauseMining));
}

/// Single test for every state change: the miner controls are process-wide.
#[test]
fn test_try_make_response() {
    let with_auth = |mut request: StacksHttpRequest| {
        request.add_header("authorization".into(), "password".into());
        request
    };
    let requests = vec![
        with_auth(StacksHttpRequest::new_bench_miner_status(addr().into())),
        with_auth(StacksHttpRequest::new_bench_miner_command(
            addr().into(),
            MinerBenchCommand::PauseMining,
        )),
        // pausing again is idempotent
        with_auth(StacksHttpRequest::new_bench_miner_command(
            addr().into(),
            MinerBenchCommand::PauseMining,
        )),
        with_auth(StacksHttpRequest::new_bench_miner_command(
            addr().into(),
            MinerBenchCommand::ResumeMining,
        )),
    ];

    let responses = test_rpc(function_name!(), requests);
    let statuses: Vec<_> = responses
        .into_iter()
        .map(|response| response.decode_bench_miner_status().unwrap())
        .collect();
    let [initial, paused, paused_again, resumed] = statuses.as_slice() else {
        panic!("expected 4 responses, got {}", statuses.len());
    };

    assert!(!initial.mining.paused);
    assert_eq!(initial.mining.since, None);

    assert!(paused.mining.paused);
    let since = paused.mining.since.expect("paused state has a start time");

    assert_eq!(paused_again.mining.since, Some(since));

    assert!(!resumed.mining.paused);
    assert_eq!(resumed.mining.since, None);
}
