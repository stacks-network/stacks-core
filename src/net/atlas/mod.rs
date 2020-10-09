pub mod db;
pub mod zonefile;

pub use self::db::AtlasDB;

use net::connection::ConnectionOptions;
use net::Error as net_error;
use util::db::Error as db_error;
use vm::{
    clarity::ClarityConnection,
    costs::LimitedCostTracker,
    types::{PrincipalData, QualifiedContractIdentifier, StandardPrincipalData, TupleData},
    ClarityName, ContractName, Value,
    database::{
        ClarityDatabase, ClaritySerializable, MarfedKV, STXBalance,
    },

};
use chainstate::burn::db::sortdb::SortitionDB;
use chainstate::stacks::db::StacksChainState;
use chainstate::stacks::boot;
use chainstate::stacks::StacksBlockId;

use util::db::FromRow;
use rusqlite::Row;

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

pub struct ZonefileHashInventory {
    pages: Vec<ZonefileHashPage>,
}

impl ZonefileHashInventory {

    fn get_expected_inventory(sortdb: &SortitionDB,
                              chainstate: &mut StacksChainState,
                              tip: &StacksBlockId,
                              options: &ConnectionOptions) -> Result<ZonefileHashInventory, ()> {
        
        let contract_identifier = boot::boot_code_id("bns");
        let function = "get-zonefiles-inv-info";
        let map_name = "zonefiles-inv";
        let cost_track = LimitedCostTracker::new(options.read_only_call_limit.clone());
        let sender = PrincipalData::Standard(StandardPrincipalData::transient());

        let data = chainstate.maybe_read_only_clarity_tx(&sortdb.index_conn(), tip, |clarity_tx| {
            let res = clarity_tx.with_readonly_clarity_env(sender, cost_track, |env| {
                env.execute_contract(&contract_identifier, function, &vec![], true)
            });

            let data = match res {
                Ok(res) => res.expect_result_ok().expect_tuple(),
                Err(_e) => return Err(net_error::DBError(db_error::NotFoundError)),
            };
    
            let pages_count = data.get("pages-count")
                .expect(&format!("FATAL: no 'pages-count'"))
                .to_owned()
                .expect_u128() as u32;
    
            let last_page_len = data.get("last-page-len")
                .expect(&format!("FATAL: no 'last-page-len'"))
                .to_owned()
                .expect_u128() as u32;
    
            let page_size = data.get("page-size")
                .expect(&format!("FATAL: no 'page-size'"))
                .to_owned()
                .expect_u128() as u32;

            clarity_tx.with_clarity_db_readonly(|clarity_db| {
                let mut inv = ZonefileHashInventory { pages: vec![] };

                for page_index in 0..=pages_count {
                    let limit = if page_index == pages_count {
                        last_page_len
                    } else {
                        page_size
                    };
                    
                    let page = ZonefileHashPage::get_expected_zonefiles_hashes_at_page(page_index, page_size, limit, clarity_db).unwrap(); // todo(ludo)

                    inv.pages.push(page);
                }
                Ok(inv)
            })
        });
        Ok(data.unwrap())
    }
}


pub struct ZonefileHashPage {
    pub index: u32,
    pub entries: Vec<String>
}

pub struct ZonefileHash {
    pub zonefile_id: u32,
    pub hash: String,
}

impl FromRow<ZonefileHash> for ZonefileHash {
    fn from_row<'a>(row: &'a Row) -> Result<ZonefileHash, db_error> {
        let zonefile_id: u32 = row.get("zonefile_id");
        let hash: String = row.get("hash");

        Ok(ZonefileHash {
            zonefile_id,
            hash
        })
    }
}

impl ZonefileHashPage {

    fn get_one_hot_encoding_vector(expected_zonefiles_hashes: ZonefileHashPage, downloaded_zonefiles: Vec<Option<ZonefileHash>>) -> Vec<u8> {
        let mut bit_vector = vec![];
        let mut segment: u8 = 0;
        for (index, (expected, actual)) in expected_zonefiles_hashes.entries.iter().zip(downloaded_zonefiles.iter()).enumerate() {
            if index % 8 == 0 {
                bit_vector.push(segment);
                segment = 0;
            }
            let bit = match actual {
                Some(zonefile_hash) if &zonefile_hash.hash == expected => 1,
                _ => 0,
            };
            segment = segment << bit;
        }

        // todo(ludo): fix size
        bit_vector
    }

    fn get_expected_zonefiles_hashes_at_page(page_index: u32,
                                     page_size: u32,
                                     limit: u32,
                                     clarity_db: &mut ClarityDatabase) -> Result<ZonefileHashPage, ()> {
        
        let contract_identifier = boot::boot_code_id("bns");
        let map_name = "zonefiles-inv";

        let mut page = ZonefileHashPage { 
            index: page_index,
            entries: vec![]
        };

        for segment_index in  0..limit {
            
            let map_key = Value::from(
                TupleData::from_data(vec![
                    ("page".into(), Value::UInt(page_index.into())),
                    ("index".into(), Value::UInt(segment_index.into())),
                ]).unwrap()); // todo(ludo)

            let key = ClarityDatabase::make_key_for_data_map_entry(
                &contract_identifier,
                map_name,
                &map_key,
            );

            let zonefile_hash = clarity_db
                .get::<Value>(&key)
                .unwrap_or_else(|| {
                    test_debug!("No value for '{}' in {}", &key, tip);
                    Value::none()
            });

            page.entries.push(zonefile_hash.to_string()); // todo(ludo): fix
        }

        Ok(page)
    }

    fn get_downloaded_zonefiles_hashes_at_page(page_index: u32,
                                               page_size: u32,
                                               atlas_db: &AtlasDB) -> Result<Vec<Option<ZonefileHash>>, ()> {

        let min = page_size * page_index;
        let max = min + page_size;
        let mut downloaded_zonefiles = match atlas_db.get_zonefiles_hashes_in_range_desc(min, max) {
            Ok(zonefiles) => zonefiles,
            Err(e) => {
                panic!() // todo(ludo)
            }
        };

        let mut zonefiles_hashes = vec![];        
        for cursor in min..max {
            let entry = match downloaded_zonefiles.len() {
                0 => None,
                len => match downloaded_zonefiles[len - 1].zonefile_id {
                    index if index == cursor => downloaded_zonefiles.pop(),
                    _ => None,
                }
            };
            zonefiles_hashes.push(entry);
        }

        Ok(zonefiles_hashes)
    }
}

