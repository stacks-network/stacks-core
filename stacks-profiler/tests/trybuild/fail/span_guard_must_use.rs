#![deny(unused_must_use)]

use stacks_profiler::span;

fn main() {
    span!("forgotten");
}
