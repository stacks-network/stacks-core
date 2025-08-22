#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|s: &str| {
    let _ = clarity::vm::execute_v2(s);
});
