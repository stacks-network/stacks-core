// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate blockstack_lib;
extern crate serde_json;

use std::{env, process};

use blockstack_lib::clarity_cli as clarity;
use stacks_common::util::log;

fn main() {
    let argv: Vec<String> = env::args().collect();

    let result = clarity::invoke_command(&argv[0], &argv[1..]);
    match result {
        (exit_code, Some(output)) => {
            println!("{}", &serde_json::to_string(&output).unwrap());
            process::exit(exit_code);
        }
        (exit_code, None) => {
            process::exit(exit_code);
        }
    }
}
