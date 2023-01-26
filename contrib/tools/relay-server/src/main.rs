use std::net::TcpListener;

use server::ServerEx;
use state::State;

mod state;
mod server;
mod http;
mod url;
mod to_io_result;

fn main() {
    let mut state = State::default();
    let listner = TcpListener::bind("127.0.0.1:9776").unwrap();
    for stream_or_error in listner.incoming() {
        let f = || stream_or_error?.update_state(&mut state);
        if let Err(e) = f() {
            eprintln!("IO error: {e}");
        }
    }
}
