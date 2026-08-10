// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

#![no_main]

use clarity_conformance::{VectorCase, VectorStep, run_case};
use clarity_types::ClarityVersion;
use clarity_v6::Clarity6Engine;
use libfuzzer_sys::fuzz_target;
use stacks_common::types::StacksEpochId;

const MAX_SOURCE_BYTES: usize = 64 * 1024;

fuzz_target!(|input: &[u8]| {
    let Some((&epoch_selector, source_bytes)) = input.split_first() else {
        return;
    };
    if source_bytes.len() > MAX_SOURCE_BYTES {
        return;
    }
    let Ok(source) = std::str::from_utf8(source_bytes) else {
        return;
    };
    let epoch = if epoch_selector & 1 == 0 {
        StacksEpochId::Epoch40
    } else {
        StacksEpochId::Epoch41
    };
    let case = VectorCase {
        name: "fuzzed analysis".into(),
        epoch,
        language_version: ClarityVersion::Clarity6,
        contract_name: "fuzzed".into(),
        source: source.into(),
        steps: vec![VectorStep::Analyze],
        expected: vec![],
    };

    // Parsing, analysis, diagnostics, cost restoration, and observation
    // normalization all run without linking the legacy interpreter.
    let _ = run_case(&Clarity6Engine, &case);
});
