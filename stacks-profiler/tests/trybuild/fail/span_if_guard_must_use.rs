#![deny(unused_must_use)]

use stacks_profiler::span_if;

fn main() {
    span_if!(true, "forgotten");
}
