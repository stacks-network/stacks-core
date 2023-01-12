use std::collections::HashMap;

pub trait QueryEx {
    fn url_query(&self) -> HashMap<&str, &str>;
}

impl QueryEx for str {
    fn url_query(&self) -> HashMap<&str, &str> {
        self.split_once('?')
            .unwrap()
            .1
            .split('&')
            .map(|v| v.split_once('=').unwrap())
            .collect()
    }
}
