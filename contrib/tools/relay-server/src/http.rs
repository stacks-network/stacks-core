use std::{collections::HashMap, io::Read};

#[derive(Debug)]
pub struct RequestMessage {
    pub method: String,
    pub url: String,
    pub protocol: String,
    pub headers: HashMap<String, String>,
    pub content: Vec<u8>,
}

pub trait RequestMessageEx: Read {
    fn read_http_request_message(&mut self) -> RequestMessage {
        let mut read_byte = || {
            let mut buf = [0; 1];
            self.read_exact(&mut buf).unwrap();
            buf[0]
        };

        let mut read_line = || {
            let mut result = String::new();
            loop {
                let b = read_byte();
                if b == 13 {
                    break;
                };
                result.push(b as char);
            }
            assert_eq!(read_byte(), 10);
            result
        };

        // read and parse the request line
        let request_line = read_line();
        let mut split = request_line.split(' ');
        let mut next = || split.next().unwrap().to_string();
        let method = next();
        let url = next();
        let protocol = next();

        // read and parse headers
        let mut headers = HashMap::new();
        loop {
            let line = read_line();
            if line.is_empty() {
                break;
            }
            let (name, value) = line.split_once(':').unwrap();
            headers.insert(name.to_lowercase(), value.trim().to_string());
        }

        // read content
        let content_length = headers
            .get("content-length")
            .map_or(0, |v| v.parse::<usize>().unwrap());
        let mut content = Vec::new();
        content.resize(content_length, 0);
        self.read_exact(content.as_mut_slice()).unwrap();

        // return the message
        RequestMessage {
            method,
            url,
            protocol,
            headers,
            content,
        }
    }
}

impl<T: Read> RequestMessageEx for T {}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use crate::http::RequestMessageEx;

    struct MessageRead<'a>(&'a [u8], usize);

    impl<'a> Read for MessageRead<'a> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let len = buf.len();
            let new_position = self.1 + len;
            buf.copy_from_slice(&self.0[self.1..new_position]);
            self.1 = new_position;
            Ok(len)
        }
    }

    #[test]
    fn test() {
        const MESSAGE: &str = "\
            GET /images/logo.png HTTP/1.1\r\n\
            Content-Length: 6\r\n\
            \r\n\
            Hello!";
        let mut read = MessageRead(MESSAGE.as_bytes(), 0);
        let rm = read.read_http_request_message();
        assert_eq!(rm.method, "GET");
        assert_eq!(rm.url, "/images/logo.png");
        assert_eq!(rm.protocol, "HTTP/1.1");
        assert_eq!(rm.headers.len(), 1);
        assert_eq!(rm.headers["content-length"], "6");
    }
}
