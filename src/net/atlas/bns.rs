use super::AtlasDB;

use net::connection::ConnectionOptions;
use net::{Error as net_error};
use util::db::Error as db_error;
use vm::{
    clarity::{ClarityConnection, ClarityReadOnlyConnection},
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
use util::hash::Hash160;
use rusqlite::Row;

pub struct BNSContractReader {
}

impl BNSContractReader {

    pub fn get_zonefiles_hashes_at_page_index(page_index: u32,
                                              sortdb: &SortitionDB,
                                              chainstate: &mut StacksChainState,
                                              tip: &StacksBlockId,
                                              options: &ConnectionOptions) -> Result<ZonefileHashInventory, (/*todo(ludo)*/)> {
        chainstate.maybe_read_only_clarity_tx(&sortdb.index_conn(), tip, |clarity_tx| {
            let cost_tracker = LimitedCostTracker::new(options.read_only_call_limit.clone());

            // Get pagination informations
            let pages_info = BNSContractReader::get_zonefiles_inv_info(cost_tracker, clarity_tx)?;
            
            // Read expected_page
            let expected_page = clarity_tx.with_clarity_db_readonly(|clarity_db| {
                BNSContractReader::get_zonefiles_hashes(page_index, &pages_info, tip, clarity_db)
            })?;

            Ok(ZonefileHashInventory {
                pages_info,
                pages: vec![expected_page]
            })
        })
    }

    fn get_zonefiles_inv_info(cost_tracker: LimitedCostTracker, clarity_tx: &mut ClarityReadOnlyConnection) -> Result<ZonefilesPagesInfo, (/*todo(ludo)*/)> {

        let contract_identifier = boot::boot_code_id("bns");
        let function = "get-zonefiles-inv-info";
        let sender = PrincipalData::Standard(StandardPrincipalData::transient());

        let res = clarity_tx.with_readonly_clarity_env(sender, cost_tracker, |env| {
            env.execute_contract(&contract_identifier, function, &vec![], true)
        });

        let data = match res {
            Ok(res) => res.expect_result_ok().expect_tuple(),
            Err(_e) => panic!() // todo(ludo) return Err(net_error::DBError(db_error::NotFoundError)),
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

        Ok(ZonefilesPagesInfo {
            pages_count,
            last_page_len,
            page_size,
        })
    }

    // todo(ludo): fn get_all_inventory_pages() -> Result<Vec<ZonefileHashPage>, (/*todo(ludo)*/)>

    fn get_zonefiles_hashes(page_index: u32,
                            pages_info: &ZonefilesPagesInfo,
                            tip: &StacksBlockId,
                            clarity_db: &mut ClarityDatabase) -> Result<ZonefileHashPage, (/*todo(ludo)*/)> {
        
        let contract_identifier = boot::boot_code_id("bns");
        let map_name = "zonefiles-inv";

        let limit = if page_index == pages_info.pages_count {
            pages_info.last_page_len
        } else {
            pages_info.page_size
        };

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
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZonefilesPagesInfo {
    pages_count: u32,
    last_page_len: u32,
    page_size: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZonefileHashPage {
    pub index: u32,
    pub entries: Vec<String>
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

pub struct ZonefileHashInventory {
    pages_info: ZonefilesPagesInfo,
    pages: Vec<ZonefileHashPage>
}

impl ZonefileHashInventory {

    pub fn compute_compact_inventory(&self, atlas_db: &AtlasDB) -> Vec<u8> {
        let mut compact_inventory = vec![];
        for page in self.pages.iter() {
            let min = self.pages_info.page_size * page.index;
            let max = min + self.pages_info.page_size;
    
            let downloaded_zonefiles = atlas_db.get_processed_zonefiles_hashes_at_page(min, max);
            let mut bytes = page.compute_compact_inventory(downloaded_zonefiles);
            compact_inventory.append(&mut bytes);
        }
        compact_inventory
    }
}


impl ZonefileHashPage {

    pub fn compute_compact_inventory(&self, downloaded_zonefiles: Vec<Option<ZonefileHash>>) -> Vec<u8> {
        let mut bit_vector = vec![];
        let mut segment: u8 = 0;
        for (index, (expected, actual)) in self.entries.iter().zip(downloaded_zonefiles.iter()).enumerate() {
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

}
