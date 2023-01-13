use std::{io::Write, net::TcpListener};

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
        let mut write = |text: &str| stream.write(text.as_bytes()).unwrap();
        let mut write_line = |line: &str| {
            write(line);
            write("\r\n");
        };
        let mut write_response_line = || write_line("HTTP/1.1 200 OK");
        match rm.method.as_str() {
            "GET" => {
                let query = *rm.url.url_query().get("id").unwrap();
                let msg = state
                    .get(query.to_string())
                    .map_or([].as_slice(), |v| v.as_slice());
                let len = msg.len();
                write_response_line();
                write_line(format!("content-length:{len}").as_str());
                write_line("");
                stream.write(msg).unwrap();
            }
            "POST" => {
                state.post(rm.content);
                write_response_line();
                write_line("");
            }
            _ => panic!(),
        };
    }
}
