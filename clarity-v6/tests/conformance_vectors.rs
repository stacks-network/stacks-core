// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Golden-vector verification intentionally lives in an integration-test
//! binary that references no legacy-engine symbols.

use clarity_v6::Clarity6Engine;

const GOLDEN_VECTORS: &str = include_str!("vectors/clarity6-v1.json");

#[test]
fn clarity6_revision_one_matches_checked_in_vectors() {
    let suite = clarity_conformance::parse_suite(GOLDEN_VECTORS).unwrap();
    clarity_conformance::verify_suite(&Clarity6Engine, &suite).unwrap();
}
