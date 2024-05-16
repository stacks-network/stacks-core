use std::collections::BTreeMap;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use stacks_common::types::chainstate::{BurnchainHeaderHash, ConsensusHash};
use stacks_common::types::net::PeerHost;

use crate::net::api::get_tenures_fork_info::GetTenuresForkInfo;
use crate::net::api::getsortition::{GetSortitionHandler, QuerySpecifier};
use crate::net::connection::ConnectionOptions;
use crate::net::http::{HttpRequestPreamble, HttpVersion};
use crate::net::httpcore::{RPCRequestHandler, StacksHttp, StacksHttpPreamble};
use crate::net::Error as NetError;

fn make_preamble<T: Display, R: Display>(start: &T, stop: &R) -> HttpRequestPreamble {
    HttpRequestPreamble {
        version: HttpVersion::Http11,
        verb: "GET".into(),
        path_and_query_str: format!("/v3/tenures_fork_info/{start}/{stop}"),
        host: PeerHost::DNS("localhost".into(), 0),
        content_type: None,
        content_length: Some(0),
        keep_alive: false,
        headers: BTreeMap::new(),
    }
}

#[test]
fn test_parse_request() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 33333);
    let http = StacksHttp::new(addr.clone(), &ConnectionOptions::default());
    let mut handler = GetTenuresForkInfo::default();

    let tests = vec![
        (
            make_preamble(&ConsensusHash([0; 20]), &ConsensusHash([255; 20])),
            Ok((ConsensusHash([0; 20]), ConsensusHash([255; 20]))),
        ),
        (
            make_preamble(&BurnchainHeaderHash([0; 32]), &ConsensusHash([255; 20])),
            Err(NetError::NotFoundError),
        ),
        (
            make_preamble(&ConsensusHash([255; 20]), &BurnchainHeaderHash([0; 32])),
            Err(NetError::NotFoundError),
        ),
    ];

    for (inp, expected_result) in tests.into_iter() {
        handler.restart();
        let parsed_request = http.handle_try_parse_request(&mut handler, &inp, &[]);
        match expected_result {
            Ok((start, stop)) => {
                assert!(parsed_request.is_ok());
                assert_eq!(&handler.start_sortition, &Some(start));
                assert_eq!(&handler.stop_sortition, &Some(stop));
            }
            Err(e) => {
                assert_eq!(e, parsed_request.unwrap_err());
            }
        }
    }
}
