use hashbrown::HashMap;

pub trait QueryEx {
    fn url_query(&self) -> HashMap<&str, &str>;
}

impl QueryEx for str {
    fn url_query(&self) -> HashMap<&str, &str> {
        match self.split_once('?') {
            Some((_, right)) if !right.is_empty() => right
                .split('&')
                .map(|v| v.split_once('=').unwrap_or((v, &"")))
                .collect(),
            _ => HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::QueryEx;

    #[test]
    fn no_query_test() {
        assert!("".url_query().is_empty());
    }

    #[test]
    fn empty_test() {
        assert!("?".url_query().is_empty());
    }

    #[test]
    fn one_item_test() {
        let x = "locahost:8080/?xyz".url_query();
        assert_eq!(x.len(), 1);
        assert!(x.get("xyz").unwrap().is_empty());
    }

    #[test]
    fn two_items_test() {
        let x = "?xyz&azx".url_query();
        assert_eq!(x.len(), 2);
        assert!(x.get("xyz").unwrap().is_empty());
        assert!(x.get("azx").unwrap().is_empty());
    }

    #[test]
    fn three_items_test() {
        let x = "something.example?xyz=5&azx&id=hello".url_query();
        assert_eq!(x.len(), 3);
        assert_eq!(x.get("xyz").unwrap().to_owned(), "5");
        assert!(x.get("azx").unwrap().is_empty());
        assert_eq!(x.get("id").unwrap().to_owned(), "hello");
    }
}
