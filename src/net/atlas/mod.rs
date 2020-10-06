pub mod db;

pub use self::db::AtlasDB;

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
