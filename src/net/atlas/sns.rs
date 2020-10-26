use super::AtlasDB;
use super::inv::{ZonefileHashInventory, ZonefilesPagesInfo, ZonefileHashPage};

use net::connection::ConnectionOptions;
use net::{Error as net_error};
use util::db::Error as db_error;
use vm::{
    clarity::{ClarityConnection, ClarityReadOnlyConnection},
    costs::{LimitedCostTracker, ExecutionCost},
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

use util::hash::Hash160;
use rusqlite::Row;

use std::collections::HashMap;

pub struct SNSContractReader {
}

impl SNSContractReader {

    pub fn get_zonefiles_hashes_at_page_index(page_index: u32,
                                              sortdb: &SortitionDB,
                                              chainstate: &mut StacksChainState,
                                              tip: &StacksBlockId,
                                              options: &ConnectionOptions) -> Result<ZonefileHashInventory, (/*todo(ludo)*/)> {
        chainstate.maybe_read_only_clarity_tx(&sortdb.index_conn(), tip, |clarity_tx| {
            let cost_tracker = LimitedCostTracker::new(options.read_only_call_limit.clone());

            // Get pagination informations
            let pages_info = SNSContractReader::get_zonefiles_inv_info(cost_tracker, clarity_tx)?;
            
            // Read expected_page
            let expected_page = clarity_tx.with_clarity_db_readonly(|clarity_db| {
                SNSContractReader::get_zonefiles_hashes(page_index, &pages_info, tip, clarity_db)
            })?;

            let pages_indexes = vec![expected_page.index];
            let mut pages = HashMap::new();
            pages.insert(expected_page.index, expected_page);

            Ok(ZonefileHashInventory {
                tip: tip.clone(),
                pages_info,
                pages_indexes,
                pages,
            })
        })
    }

    pub fn get_zonefiles_inv_info(cost_tracker: LimitedCostTracker, clarity_tx: &mut ClarityReadOnlyConnection) -> Result<ZonefilesPagesInfo, (/*todo(ludo)*/)> {

        let contract_identifier = boot::boot_code_id("sns");
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

    pub fn get_attachments_inventory(
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        tip: &StacksBlockId,
    ) -> Result<ZonefileHashInventory, (/*todo(ludo)*/)> 
    {
        // todo(ludo): think about a lighter version
        chainstate.maybe_read_only_clarity_tx(&sortdb.index_conn(), tip, |clarity_tx| {
            let cost_tracker = LimitedCostTracker::new(ExecutionCost::max_value());

            // Get pagination informations
            let pages_info = SNSContractReader::get_zonefiles_inv_info(cost_tracker, clarity_tx)?;

            let (pages_indexes, pages) = clarity_tx.with_clarity_db_readonly(|clarity_db| {
                let mut pages_indexes = vec![];
                let mut pages = HashMap::new();
                for page_index in 0..pages_info.pages_count {
                    let page = SNSContractReader::get_zonefiles_hashes(page_index, &pages_info, tip, clarity_db)?;
                    pages_indexes.push(page_index);
                    pages.insert(page_index, page);
                }
                Ok((pages_indexes, pages))
            })?;

            Ok(ZonefileHashInventory {
                tip: tip.clone(),
                pages_info,
                pages_indexes,
                pages,
            })
        })
    }

    fn get_zonefiles_hashes(page_index: u32,
                            pages_info: &ZonefilesPagesInfo,
                            tip: &StacksBlockId,
                            clarity_db: &mut ClarityDatabase) -> Result<ZonefileHashPage, (/*todo(ludo)*/)> {
        
        let contract_identifier = boot::boot_code_id("sns");
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


