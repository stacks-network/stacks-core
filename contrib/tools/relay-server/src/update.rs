use std::io::{Read, Write};

use crate::{http::RequestEx, url::QueryEx, state::State};

pub trait StreamEx: Read + Write + Sized {
    fn update_state(&mut self, state: &mut State) {
        let rm = self.read_http_request();
        let mut write = |text: &str| self.write(text.as_bytes()).unwrap();
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
                self.write(msg).unwrap();
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

impl<T: Read + Write + Sized> StreamEx for T {}

#[cfg(test)]
mod test {
    #[test]
    fn test() {
        
    }
}