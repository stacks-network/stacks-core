extern crate redis;
extern crate rusqlite;

use redis::Commands;
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

    let client = redis::Client::open("redis://127.0.0.1/").expect("couldn't ocnnect");
    let mut con = client.get_connection().expect("coulnd't connect");
    let redis_start = Instant::now();
    let _: () = con.set("my_key", "test_data").unwrap();
    for _i in 1..10001 {
        let _rv: String = con.get("my_key").unwrap();
    }
    {
        let elapsed = redis_start.elapsed();
        eprintln!("redis elapsed {:?}", &elapsed);
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
