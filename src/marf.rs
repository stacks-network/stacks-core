extern crate rusqlite;

use rusqlite::Connection;
use std::collections::HashMap;
use std::time::Instant;

fn main() {
    let conn = Connection::open("/data/spaces/c3/mainnet/chainstate/vm/clarity/marf.sqlite")
        .expect("couldn't open db");

    let mut int_string = HashMap::new();
    for i in 1..10001 {
        int_string.insert(i, "payload");
    }

    let map_start = Instant::now();
    for i in 1..10001 {
        int_string.get(&i);
    }
    {
        let elapsed = map_start.elapsed();
        eprintln!("map elapsed {:?}", &elapsed);
    }

    let sql_start = Instant::now();
    for i in 1..10001 {
        let result = conn.blob_open(
            rusqlite::DatabaseName::Main,
            "marf_data",
            "data",
            i.into(),
            true,
        );
        match result {
            Ok(_) => {}
            Err(e) => {
                // eprintln!("elapsed {:?}", &e);
            }
        }
    }
    {
        let elapsed = sql_start.elapsed();
        eprintln!("sql elapsed {:?}", &elapsed);
    }
}
