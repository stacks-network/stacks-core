extern crate quote;
extern crate syn;

use proc_macro::TokenStream;
use quote::{quote};
use stacks_common::types::chainstate::*;
use syn::{AttributeArgs, ItemFn, parse_macro_input, };

#[proc_macro_attribute]
pub fn generate_test_cases_for_marf_open_opts(attr: TokenStream, item: TokenStream) -> TokenStream {
    //let args = parse_macro_input!(attr as AttributeArgs);
    let item = parse_macro_input!(item as ItemFn);

    let mut opts_ts = quote! {};
    let mut _desc: String;

    for opts in ALL_MARF_OPEN_OPTS.into_iter() {
        _desc = format!("{} {} {} {}", opts.hash_calculation_mode, opts.cache_strategy, opts.external_blobs, opts.external_blob_compression_type);
        opts_ts = quote!{ 
            #[test_case(#opts ; #_desc)] 
            #opts_ts 
        };
    }

    quote! { 
        #opts_ts
        #item 
    }.into()
}

const ALL_MARF_OPEN_OPTS: &'static [MARFOpenOpts] = &[
    MARFOpenOpts::new(TrieHashCalculationMode::Immediate, TrieCachingStrategy::Noop, false, BlobCompressionType::None),
    MARFOpenOpts::new(TrieHashCalculationMode::Deferred, TrieCachingStrategy::Noop, false, BlobCompressionType::None),
    MARFOpenOpts::new(TrieHashCalculationMode::Immediate, TrieCachingStrategy::Noop, true, BlobCompressionType::None),
    MARFOpenOpts::new(TrieHashCalculationMode::Deferred, TrieCachingStrategy::Noop, true, BlobCompressionType::None),
    MARFOpenOpts::new(TrieHashCalculationMode::Immediate, TrieCachingStrategy::Everything, false, BlobCompressionType::None),
    MARFOpenOpts::new(TrieHashCalculationMode::Deferred, TrieCachingStrategy::Everything, false, BlobCompressionType::None),
    MARFOpenOpts::new(TrieHashCalculationMode::Immediate, TrieCachingStrategy::Everything, true, BlobCompressionType::None),
    MARFOpenOpts::new(TrieHashCalculationMode::Deferred, TrieCachingStrategy::Everything, true, BlobCompressionType::None),

    MARFOpenOpts::new(TrieHashCalculationMode::Immediate, TrieCachingStrategy::Noop, false, BlobCompressionType::LZ4),
    MARFOpenOpts::new(TrieHashCalculationMode::Deferred, TrieCachingStrategy::Noop, false, BlobCompressionType::LZ4),
    MARFOpenOpts::new(TrieHashCalculationMode::Immediate, TrieCachingStrategy::Noop, true, BlobCompressionType::LZ4),
    MARFOpenOpts::new(TrieHashCalculationMode::Deferred, TrieCachingStrategy::Noop, true, BlobCompressionType::LZ4),
    MARFOpenOpts::new(TrieHashCalculationMode::Immediate, TrieCachingStrategy::Everything, false, BlobCompressionType::LZ4),
    MARFOpenOpts::new(TrieHashCalculationMode::Deferred, TrieCachingStrategy::Everything, false, BlobCompressionType::LZ4),
    MARFOpenOpts::new(TrieHashCalculationMode::Immediate, TrieCachingStrategy::Everything, true, BlobCompressionType::LZ4),
    MARFOpenOpts::new(TrieHashCalculationMode::Deferred, TrieCachingStrategy::Everything, true, BlobCompressionType::LZ4),

    MARFOpenOpts::new(TrieHashCalculationMode::Immediate, TrieCachingStrategy::Noop, false, BlobCompressionType::ZStd(0)),
    MARFOpenOpts::new(TrieHashCalculationMode::Deferred, TrieCachingStrategy::Noop, false, BlobCompressionType::ZStd(0)),
    MARFOpenOpts::new(TrieHashCalculationMode::Immediate, TrieCachingStrategy::Noop, true, BlobCompressionType::ZStd(0)),
    MARFOpenOpts::new(TrieHashCalculationMode::Deferred, TrieCachingStrategy::Noop, true, BlobCompressionType::ZStd(0)),
    MARFOpenOpts::new(TrieHashCalculationMode::Immediate, TrieCachingStrategy::Everything, false, BlobCompressionType::ZStd(0)),
    MARFOpenOpts::new(TrieHashCalculationMode::Deferred, TrieCachingStrategy::Everything, false, BlobCompressionType::ZStd(0)),
    MARFOpenOpts::new(TrieHashCalculationMode::Immediate, TrieCachingStrategy::Everything, true, BlobCompressionType::ZStd(0)),
    MARFOpenOpts::new(TrieHashCalculationMode::Deferred, TrieCachingStrategy::Everything, true, BlobCompressionType::ZStd(0)),
];