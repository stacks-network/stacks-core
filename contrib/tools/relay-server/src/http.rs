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
