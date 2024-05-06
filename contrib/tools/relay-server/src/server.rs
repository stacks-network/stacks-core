use std::io::{Error, ErrorKind, Read, Write};
use std::net::TcpStream;

use crate::http::RequestEx;
use crate::state::State;
use crate::to_io_result::ToIoResult;
use crate::url::QueryEx;

pub trait Stream {
    type Read: Read;
    type Write: Write;
    fn istream(&mut self) -> &mut Self::Read;
    fn ostream(&mut self) -> &mut Self::Write;
}

impl Stream for TcpStream {
    type Read = TcpStream;
    type Write = TcpStream;
    fn istream(&mut self) -> &mut Self::Read {
        self
    }
    fn ostream(&mut self) -> &mut Self::Write {
        self
    }
}

pub trait ServerEx: Stream {
    fn update_state(&mut self, state: &mut State) -> Result<(), Error> {
        let rm = self.istream().read_http_request()?;
        let ostream = self.ostream();
        let mut write = |text: &str| ostream.write(text.as_bytes());
        let mut write_line = |line: &str| {
            write(line)?;
            write("\r\n")?;
            Ok::<(), Error>(())
        };
        let mut write_response_line = || write_line("HTTP/1.1 200 OK");
        match rm.method.as_str() {
            "GET" => {
                let query = *rm.url.url_query().get("id").to_io_result("no id")?;
                let msg = state
                    .get(query.to_string())
                    .map_or([].as_slice(), |v| v.as_slice());
                let len = msg.len();
                write_response_line()?;
                write_line(format!("content-length:{len}").as_str())?;
                write_line("")?;
                ostream.write(msg)?;
            }
            "POST" => {
                state.post(rm.content);
                write_response_line()?;
                write_line("")?;
            }
            _ => return Err(Error::new(ErrorKind::InvalidData, "unknown HTTP method")),
        };
        Ok(())
    }
}

impl<T: Stream> ServerEx for T {}

#[cfg(test)]
mod test {
    use std::io::Cursor;
    use std::str::from_utf8;

    use super::Stream;
    use crate::server::ServerEx;
    use crate::state::State;

    struct MockStream {
        i: Cursor<&'static str>,
        o: Cursor<Vec<u8>>,
    }

    trait MockStreamEx {
        fn mock_stream(self) -> MockStream;
    }

    impl MockStreamEx for &'static str {
        fn mock_stream(self) -> MockStream {
            MockStream {
                i: Cursor::new(self),
                o: Default::default(),
            }
        }
    }

    impl Stream for MockStream {
        type Read = Cursor<&'static str>;
        type Write = Cursor<Vec<u8>>;
        fn istream(&mut self) -> &mut Self::Read {
            &mut self.i
        }
        fn ostream(&mut self) -> &mut Self::Write {
            &mut self.o
        }
    }

    #[test]
    fn test() {
        let mut state = State::default();
        {
            const REQUEST: &str = "\
                POST / HTTP/1.1\r\n\
                Content-Length: 6\r\n\
                \r\n\
                Hello!";
            let mut stream = REQUEST.mock_stream();
            stream.update_state(&mut state).unwrap();
            assert_eq!(stream.i.position(), REQUEST.len() as u64);
            const RESPONSE: &str = "\
                HTTP/1.1 200 OK\r\n\
                \r\n";
            assert_eq!(from_utf8(stream.o.get_ref()).unwrap(), RESPONSE);
        }
        {
            const REQUEST: &str = "\
                GET /?id=x HTTP/1.1\r\n\
                \r\n";
            let mut stream = REQUEST.mock_stream();
            stream.update_state(&mut state).unwrap();
            assert_eq!(stream.i.position(), REQUEST.len() as u64);
            const RESPONSE: &str = "\
                HTTP/1.1 200 OK\r\n\
                content-length:6\r\n\
                \r\n\
                Hello!";
            assert_eq!(from_utf8(stream.o.get_ref()).unwrap(), RESPONSE);
        }
        {
            const REQUEST: &str = "\
                GET /?id=x HTTP/1.1\r\n\
                \r\n";
            let mut stream = REQUEST.mock_stream();
            stream.update_state(&mut state).unwrap();
            assert_eq!(stream.i.position(), REQUEST.len() as u64);
            const RESPONSE: &str = "\
                HTTP/1.1 200 OK\r\n\
                content-length:0\r\n\
                \r\n";
            assert_eq!(from_utf8(stream.o.get_ref()).unwrap(), RESPONSE);
        }
    }
}
