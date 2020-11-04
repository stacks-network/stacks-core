use super::AtlasDB;

use chainstate::burn::db::sortdb::SortitionDB;
use chainstate::stacks::boot;
use chainstate::stacks::db::StacksChainState;
use chainstate::stacks::StacksBlockId;
use net::connection::ConnectionOptions;
use net::Error as net_error;
use rusqlite::Row;
use util::db::Error as db_error;
use util::hash::Hash160;
use util::hash::MerkleHashFunc;
use vm::{
    clarity::{ClarityConnection, ClarityReadOnlyConnection},
    costs::{ExecutionCost, LimitedCostTracker},
    database::{ClarityDatabase, ClaritySerializable, MarfedKV, STXBalance},
    types::{
        PrincipalData, QualifiedContractIdentifier, SequenceData, StandardPrincipalData, TupleData,
    },
    ClarityName, ContractName, Value,
};

use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnchainAttachmentsInventory {
    pub tip: StacksBlockId,
    pub info: OnchainAttachmentsInventoryInfo,
    pub pages_indexes: Vec<u32>,
    pub pages: HashMap<u32, OnchainAttachmentPage>,
}

impl OnchainAttachmentsInventory {
    pub fn empty() -> OnchainAttachmentsInventory {
        OnchainAttachmentsInventory {
            tip: StacksBlockId([0x00; 32]),
            info: OnchainAttachmentsInventoryInfo::empty(),
            pages_indexes: vec![],
            pages: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnchainAttachmentsInventoryInfo {
    pub pages_count: u32,
    pub last_page_len: u32,
    pub page_size: u32,
}

impl OnchainAttachmentsInventoryInfo {
    pub fn empty() -> OnchainAttachmentsInventoryInfo {
        OnchainAttachmentsInventoryInfo {
            pages_count: 0,
            last_page_len: 0,
            page_size: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnchainAttachmentPage {
    pub index: u32,
    pub entries: Vec<Hash160>,
}

pub struct OnchainInventoryLookup {}

impl OnchainInventoryLookup {
    pub fn get_attachment_content_hashes_at_page_index(
        page_index: u32,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        tip: &StacksBlockId,
        options: &ConnectionOptions,
    ) -> Result<OnchainAttachmentsInventory, net_error> {
        chainstate.maybe_read_only_clarity_tx(&sortdb.index_conn(), tip, |clarity_tx| {
            let cost_tracker = LimitedCostTracker::new(options.read_only_call_limit.clone());

            // Get pagination informations
            let info = OnchainInventoryLookup::get_attachments_inv_info(cost_tracker, clarity_tx)?;

            // Read expected_page
            let expected_page = clarity_tx.with_clarity_db_readonly(|clarity_db| {
                OnchainInventoryLookup::get_attachment_content_hashes(page_index, &info, clarity_db)
            })?;

            let pages_indexes = vec![expected_page.index];
            let mut pages = HashMap::new();
            pages.insert(expected_page.index, expected_page);

            Ok(OnchainAttachmentsInventory {
                tip: tip.clone(),
                info,
                pages_indexes,
                pages,
            })
        })
    }

    pub fn get_attachments_inv_info(
        cost_tracker: LimitedCostTracker,
        clarity_tx: &mut ClarityReadOnlyConnection,
    ) -> Result<OnchainAttachmentsInventoryInfo, net_error> {
        let contract_identifier = boot::boot_code_id("sns");
        let function = "get-attachments-inv-info";
        let sender = PrincipalData::Standard(StandardPrincipalData::transient());

        let res = clarity_tx.with_readonly_clarity_env(sender, cost_tracker, |env| {
            env.execute_contract(&contract_identifier, function, &vec![], true)
        });

        let data = match res {
            Ok(res) => Ok(res.expect_result_ok().expect_tuple()),
            Err(_e) => Err(net_error::DBError(db_error::NotFoundError)),
        }?;

        let pages_count = data
            .get("pages-count")
            .expect(&format!("FATAL: no 'pages-count'"))
            .to_owned()
            .expect_u128() as u32;

        let last_page_len = data
            .get("last-page-len")
            .expect(&format!("FATAL: no 'last-page-len'"))
            .to_owned()
            .expect_u128() as u32;

        let page_size = data
            .get("page-size")
            .expect(&format!("FATAL: no 'page-size'"))
            .to_owned()
            .expect_u128() as u32;

        Ok(OnchainAttachmentsInventoryInfo {
            pages_count,
            last_page_len,
            page_size,
        })
    }

    pub fn get_attachments_inventory(
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        tip: &StacksBlockId,
    ) -> Result<OnchainAttachmentsInventory, net_error> {
        chainstate.maybe_read_only_clarity_tx(&sortdb.index_conn(), tip, |clarity_tx| {
            let cost_tracker = LimitedCostTracker::new(ExecutionCost::max_value());

            // Get pagination informations
            let info = OnchainInventoryLookup::get_attachments_inv_info(cost_tracker, clarity_tx)?;

            let (pages_indexes, pages) = clarity_tx.with_clarity_db_readonly(|clarity_db| {
                let mut pages_indexes = vec![];
                let mut pages = HashMap::new();
                for page_index in 0..info.pages_count {
                    let page = match OnchainInventoryLookup::get_attachment_content_hashes(
                        page_index, &info, clarity_db,
                    ) {
                        Ok(page) => page,
                        Err(e) => return Err(e),
                    };
                    pages_indexes.push(page_index);
                    pages.insert(page_index, page);
                }
                Ok((pages_indexes, pages))
            })?;

            Ok(OnchainAttachmentsInventory {
                tip: tip.clone(),
                info,
                pages_indexes,
                pages,
            })
        })
    }

    fn get_attachment_content_hashes(
        page_index: u32,
        info: &OnchainAttachmentsInventoryInfo,
        clarity_db: &mut ClarityDatabase,
    ) -> Result<OnchainAttachmentPage, net_error> {
        let contract_identifier = boot::boot_code_id("sns");
        let map_name = "attachments-inv";

        let limit = if page_index == info.pages_count {
            info.last_page_len
        } else {
            info.page_size
        };

        let mut page = OnchainAttachmentPage {
            index: page_index,
            entries: vec![],
        };

        for segment_index in 0..limit {
            let map_key = Value::from(
                TupleData::from_data(vec![
                    ("page".into(), Value::UInt(page_index.into())),
                    ("index".into(), Value::UInt(segment_index.into())),
                ])
                .expect("Unable to build tuple"),
            );

            let key = ClarityDatabase::make_key_for_data_map_entry(
                &contract_identifier,
                map_name,
                &map_key,
            );

            let buff = match clarity_db.get::<Value>(&key) {
                Some(Value::Sequence(SequenceData::Buffer(buff))) => buff,
                _ => return Err(net_error::ChainstateError("".to_string())),
            };

            let content_hash = if buff.data.is_empty() {
                Hash160::empty()
            } else {
                if let Some(content_hash) = Hash160::from_bytes(&buff.data[..]) {
                    content_hash
                } else {
                    // todo(ludo) error
                    return Err(net_error::ChainstateError("".to_string()));
                }
            };

            page.entries.push(content_hash);
        }

        Ok(page)
    }
}
