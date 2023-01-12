use std::{
    io::{Read, Write},
    net::TcpListener,
    str::from_utf8,
};

use crate::{http::RequestMessageEx, state::State, url::QueryEx};

mod http;
mod state;
mod url;

fn main() {
    let mut state = State::default();
    let listner = TcpListener::bind("127.0.0.1:9776").unwrap();
    for stream_or_error in listner.incoming() {
        let mut stream = stream_or_error.unwrap();
        let rm = stream.read_http_request_message();
        match rm.method.as_str() {
            "GET" => {
                let query = *rm.url.url_query().get("id").unwrap();
                let msg = state
                    .get(query.to_string())
                    .map_or("", |v| v.as_str())
                    .as_bytes();
                let len = msg.len();
                stream.write("HTTP/1.1 200 OK\r\n".as_bytes()).unwrap();
                stream
                    .write(format!("content-length:{len}\r\n").as_bytes())
                    .unwrap();
                stream.write("\r\n".as_bytes()).unwrap();
                stream.write(msg).unwrap();
            }
            "POST" => {
                let len = rm
                    .headers
                    .get("content-length")
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                let mut buffer = Vec::new();
                buffer.resize(len, 0);
                stream.read_exact(buffer.as_mut_slice()).unwrap();
                let message = from_utf8(buffer.as_slice()).unwrap();
                state.post(message.to_string());
                stream.write("HTTP/1.1 200 OK\r\n".as_bytes()).unwrap();
                stream.write("\r\n".as_bytes()).unwrap();
            }
            _ => panic!(),
        };
        // println!("{rm:?}");
    }
    println!("Hello, world!");
}
