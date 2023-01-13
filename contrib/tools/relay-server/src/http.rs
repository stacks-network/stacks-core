use std::{collections::HashMap, io::Read};

#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub url: String,
    pub protocol: String,
    pub headers: HashMap<String, String>,
    pub content: Vec<u8>,
}

pub trait RequestEx: Read {
    fn read_http_request(&mut self) -> Request {
        let mut read_byte = || {
            let mut buf = [0; 1];
            self.read_exact(&mut buf).unwrap();
            buf[0]
        };

        let mut read_line = || {
            let mut result = String::default();
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
        let mut headers = HashMap::default();
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
        let mut content = vec![0; content_length];
        self.read_exact(content.as_mut_slice()).unwrap();

        // return the message
        Request {
            method,
            url,
            protocol,
            headers,
            content,
        }
    }
}

impl<T: Read> RequestEx for T {}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, str::from_utf8};

    use crate::http::RequestEx;

    #[test]
    fn test() {
        const REQUEST: &str = "\
            POST / HTTP/1.1\r\n\
            Content-Length: 6\r\n\
            \r\n\
            Hello!";
        let mut read = Cursor::new(REQUEST);
        let rm = read.read_http_request();
        assert_eq!(rm.method, "POST");
        assert_eq!(rm.url, "/");
        assert_eq!(rm.protocol, "HTTP/1.1");
        assert_eq!(rm.headers.len(), 1);
        assert_eq!(rm.headers["content-length"], "6");
        assert_eq!(from_utf8(&rm.content), Ok("Hello!"));
        assert_eq!(read.position(), REQUEST.len() as u64);
    }

    #[test]
    fn no_content_test() {
        const REQUEST: &str = "\
            GET /images/logo.png HTTP/1.1\r\n\
            \r\n";
        let mut read = Cursor::new(REQUEST);
        let rm = read.read_http_request();
        assert_eq!(rm.method, "GET");
        assert_eq!(rm.url, "/images/logo.png");
        assert_eq!(rm.protocol, "HTTP/1.1");
        assert!(rm.headers.is_empty());
        assert!(rm.content.is_empty());
        assert_eq!(read.position(), REQUEST.len() as u64);
    }
}
