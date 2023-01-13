use std::net::TcpListener;

use server::ServerEx;

use crate::state::State;

mod http;
mod server;
mod state;
mod url;

fn main() {
    let mut state = State::default();
    let listner = TcpListener::bind("127.0.0.1:9776").unwrap();
    for stream_or_error in listner.incoming() {
        stream_or_error.unwrap().update_state(&mut state);
    }
}
