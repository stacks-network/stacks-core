#![no_main]

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
use blockstack_lib::burnchains::bitcoin::blocks::BitcoinBlockParser;
use blockstack_lib::burnchains::bitcoin::BitcoinNetworkType;
use blockstack_lib::burnchains::MagicBytes;
use blockstack_lib::core::StacksEpochId;
use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction;
use stacks_common::deps_common::bitcoin::network::serialize::deserialize;

type Height = usize;
type Tx<'a> = &'a [u8];

#[derive(Debug)]
struct Input<'a> {
    h: Height,
    e: StacksEpochId,
    d: Tx<'a>,
}

impl<'a> Arbitrary<'a> for Input<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> libfuzzer_sys::arbitrary::Result<Self> {
        let h = u.arbitrary::<u32>()? as usize;
        let e = *u.choose(&[
            StacksEpochId::Epoch20,
            StacksEpochId::Epoch21,
            StacksEpochId::Epoch30,
            StacksEpochId::Epoch31,
            StacksEpochId::Epoch32,
        ])?;
        // Unstructured is basically a cursor over the fuzzer's input slice.
        // Each call like `u.arbitrary::<u32>()?` consumes bytes from the front
        // and advances the cursor. By the time we reach here, `u.len()` is
        // not the original length but the number of bytes still unconsumed.
        // `u.bytes(u.len())?` grabs that entire remainder and hands it to us
        // as the transaction data.
        let d = u.bytes(u.len())?;
        Ok(Self { h, e, d })
    }
}

fuzz_target!(|i: Input| {
    if let Ok(tx) = deserialize::<Transaction>(i.d) {
        let p = BitcoinBlockParser::new(BitcoinNetworkType::Mainnet, MagicBytes::default());
        let _ = p.parse_tx(&tx, i.h, i.e);
    }
});
