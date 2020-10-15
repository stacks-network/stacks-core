pub mod db;
pub mod bns;
pub mod zonefile;

pub use self::bns::BNSContractReader;
pub use self::db::AtlasDB;

use util::hash::Hash160;

pub const BNS_NAMESPACE_MIN_LEN: usize = 1;
pub const BNS_NAMESPACE_MAX_LEN: usize = 19;
pub const BNS_NAME_MIN_LEN: usize = 1;
pub const BNS_NAME_MAX_LEN: usize = 16;

lazy_static! {

    pub static ref BNS_NAME_REGEX: String = format!(
        r#"([a-z0-9]|[-_]){{{},{}}}\.([a-z0-9]|[-_]){{{},{}}}(\.([a-z0-9]|[-_]){{{},{}}})?"#,
        BNS_NAMESPACE_MIN_LEN,
        BNS_NAMESPACE_MAX_LEN,
        BNS_NAME_MIN_LEN,
        BNS_NAME_MAX_LEN,
        1, 128
    );
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attachment {
    pub content: String,
    pub content_hash: String
}

impl Attachment {
    pub fn new(content: String, content_hash: String) -> Attachment {
        Attachment {
            content,
            content_hash
        }
    }

    pub fn is_hash_valid(&self) -> bool {
        // let content_hash = Hash160::from_hex(&self.content_hash).unwrap(); // todo(ludo)
        true
    }
}


#[cfg(test)]
mod tests;

// todo(ludo)
// When we receive a new block, if the block contains some events related to zonefile updates
// we should:
// 1) Check if the zonefile have been buffered / staged (from the API)
// 2) Request the ZonefileInv from peers
// 3) Check if the missing are present
// 4) Build a priority queue
// 5) Fetch the missing zonefiles
// 6) Process and store the zonefiles

// 1) Ability to build a bit vector

// BNS

// High level:
// HTTP Endpoints
// - POST v2/zonefiles: Receives a Zonefile + Hash
//     - Did we reveive the zonefile?
//     - 
// - GET v2/names/{name}: serve name info
//     - Do we have an entry for that name?
//     - Do we have an entry "in flux"?

// HTTP Endpoint, 