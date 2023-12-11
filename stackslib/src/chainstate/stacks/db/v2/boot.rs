use std::collections::{BTreeMap, btree_map::Entry};

use clarity::vm::{
    types::{PrincipalData, TupleData}, 
    database::NULL_BURN_STATE_DB, ContractName, ast::ASTRules, 
    events::{StacksTransactionEvent, STXEventType, STXMintEventData}, 
    Value, costs::ExecutionCost, clarity::TransactionConnection
};
use stacks_common::{
    types::chainstate::StacksBlockId, 
    util::hash::Hash160
};

use crate::{
    chainstate::stacks::{
            Error, events::StacksTransactionReceipt, TransactionVersion, boot, TransactionPayload, 
            TransactionSmartContract, StacksTransaction, TokenTransferMemo, StacksBlockHeader, 
            db::{StacksHeaderInfo, ChainStateBootData, v2::utils::ChainStateUtils}, 
            index::ClarityMarfTrieId
    }, 
    util_lib::{
        boot::{boot_code_addr, boot_code_tx_auth, boot_code_acc, boot_code_id}, 
        strings::StacksString
    }, 
    core::{
        BURNCHAIN_BOOT_CONSENSUS_HASH, BOOT_BLOCK_HASH, FIRST_BURNCHAIN_CONSENSUS_HASH, 
        FIRST_STACKS_BLOCK_HASH, MAINNET_2_0_GENESIS_ROOT_HASH
    }, 
    clarity_vm::clarity::ClarityConnection, net::atlas::BNS_CHARS_REGEX,
};

use super::stacks_chainstate::StacksChainState;

pub trait BootCodeInstaller {
    /// Install the boot code into the chain history.
    fn install_boot_code<CS>(
        chainstate: &mut CS,
        mainnet: bool,
        boot_data: &mut ChainStateBootData,
    ) -> Result<Vec<StacksTransactionReceipt>, Error> 
    where
        CS: StacksChainState
    {
        info!("Building genesis block");

        let tx_version = if mainnet {
            TransactionVersion::Mainnet
        } else {
            TransactionVersion::Testnet
        };

        let boot_code_address = boot_code_addr(mainnet);

        let boot_code_auth = boot_code_tx_auth(boot_code_address);

        let mut boot_code_account = boot_code_acc(boot_code_address, 0);

        let mut initial_liquid_ustx = 0u128;
        let mut receipts = vec![];

        {
            let mut clarity_tx = chainstate.genesis_block_begin(
                &NULL_BURN_STATE_DB,
                &BURNCHAIN_BOOT_CONSENSUS_HASH,
                &BOOT_BLOCK_HASH,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            );
            let boot_code = if mainnet {
                *boot::STACKS_BOOT_CODE_MAINNET
            } else {
                *boot::STACKS_BOOT_CODE_TESTNET
            };
            for (boot_code_name, boot_code_contract) in boot_code.iter() {
                debug!(
                    "Instantiate boot code contract '{}' ({} bytes)...",
                    boot_code_name,
                    boot_code_contract.len()
                );

                let smart_contract = TransactionPayload::SmartContract(
                    TransactionSmartContract {
                        name: ContractName::try_from(boot_code_name.to_string())
                            .expect("FATAL: invalid boot-code contract name"),
                        code_body: StacksString::from_str(boot_code_contract)
                            .expect("FATAL: invalid boot code body"),
                    },
                    None,
                );

                let boot_code_smart_contract = StacksTransaction::new(
                    tx_version.clone(),
                    boot_code_auth.clone(),
                    smart_contract,
                );

                let tx_receipt = clarity_tx.connection().as_transaction(|clarity| {
                    StacksChainState::process_transaction_payload(
                        clarity,
                        &boot_code_smart_contract,
                        &boot_code_account,
                        ASTRules::PrecheckSize,
                    )
                })?;
                receipts.push(tx_receipt);

                boot_code_account.nonce += 1;
            }

            let mut allocation_events: Vec<StacksTransactionEvent> = vec![];
            if boot_data.initial_balances.len() > 0 {
                warn!(
                    "Seeding {} balances coming from the config",
                    boot_data.initial_balances.len()
                );
            }
            for (address, amount) in boot_data.initial_balances.iter() {
                clarity_tx.connection().as_transaction(|clarity| {
                    chainstate.account_genesis_credit(clarity, address, (*amount).into())
                });
                initial_liquid_ustx = initial_liquid_ustx
                    .checked_add(*amount as u128)
                    .expect("FATAL: liquid STX overflow");
                let mint_event = StacksTransactionEvent::STXEvent(STXEventType::STXMintEvent(
                    STXMintEventData {
                        recipient: address.clone(),
                        amount: *amount as u128,
                    },
                ));
                allocation_events.push(mint_event);
            }

            clarity_tx.connection().as_transaction(|clarity| {
                // Balances
                if let Some(get_balances) = boot_data.get_bulk_initial_balances.take() {
                    info!("Importing accounts from Stacks 1.0");
                    let mut balances_count = 0;
                    let initial_balances = get_balances();
                    for balance in initial_balances {
                        balances_count = balances_count + 1;
                        let stx_address =
                            ChainStateUtils::parse_genesis_address(&balance.address, mainnet);
                        Self::account_genesis_credit(
                            clarity,
                            &stx_address,
                            balance.amount.into(),
                        );
                        initial_liquid_ustx = initial_liquid_ustx
                            .checked_add(balance.amount as u128)
                            .expect("FATAL: liquid STX overflow");
                        let mint_event = StacksTransactionEvent::STXEvent(
                            STXEventType::STXMintEvent(STXMintEventData {
                                recipient: stx_address,
                                amount: balance.amount.into(),
                            }),
                        );
                        allocation_events.push(mint_event);
                    }
                    info!("Seeding {} balances coming from chain dump", balances_count);
                }

                // Lockups
                if let Some(get_schedules) = boot_data.get_bulk_initial_lockups.take() {
                    info!("Initializing chain with lockups");
                    let mut lockups_per_block: BTreeMap<u64, Vec<Value>> = BTreeMap::new();
                    let initial_lockups = get_schedules();
                    for schedule in initial_lockups {
                        let stx_address =
                            ChainStateUtils::parse_genesis_address(&schedule.address, mainnet);
                        let value = Value::Tuple(
                            TupleData::from_data(vec![
                                ("recipient".into(), Value::Principal(stx_address)),
                                ("amount".into(), Value::UInt(schedule.amount.into())),
                            ])
                            .unwrap(),
                        );
                        match lockups_per_block.entry(schedule.block_height) {
                            Entry::Occupied(schedules) => {
                                schedules.into_mut().push(value);
                            }
                            Entry::Vacant(entry) => {
                                let schedules = vec![value];
                                entry.insert(schedules);
                            }
                        };
                    }

                    let lockup_contract_id = boot_code_id("lockup", mainnet);
                    let epoch = clarity.get_epoch();
                    clarity
                        .with_clarity_db(|db| {
                            for (block_height, schedule) in lockups_per_block.into_iter() {
                                let key = Value::UInt(block_height.into());
                                let value = Value::cons_list(schedule, &epoch).unwrap();
                                db.insert_entry_unknown_descriptor(
                                    &lockup_contract_id,
                                    "lockups",
                                    key,
                                    value,
                                    &epoch,
                                )?;
                            }
                            Ok(())
                        })
                        .unwrap();
                }

                // BNS Namespace
                let bns_contract_id = boot_code_id("bns", mainnet);
                if let Some(get_namespaces) = boot_data.get_bulk_initial_namespaces.take() {
                    info!("Initializing chain with namespaces");
                    let epoch = clarity.get_epoch();
                    clarity
                        .with_clarity_db(|db| {
                            let initial_namespaces = get_namespaces();
                            for entry in initial_namespaces {
                                let namespace = {
                                    if !BNS_CHARS_REGEX.is_match(&entry.namespace_id) {
                                        panic!("Invalid namespace characters");
                                    }
                                    let buffer = entry.namespace_id.as_bytes();
                                    Value::buff_from(buffer.to_vec()).expect("Invalid namespace")
                                };

                                let importer = {
                                    let address = ChainStateUtils::parse_genesis_address(
                                        &entry.importer,
                                        mainnet,
                                    );
                                    Value::Principal(address)
                                };

                                let revealed_at = Value::UInt(0);
                                let launched_at = Value::UInt(0);
                                let lifetime = Value::UInt(entry.lifetime.into());
                                let price_function = {
                                    let base = Value::UInt(entry.base.into());
                                    let coeff = Value::UInt(entry.coeff.into());
                                    let nonalpha_discount =
                                        Value::UInt(entry.nonalpha_discount.into());
                                    let no_vowel_discount =
                                        Value::UInt(entry.no_vowel_discount.into());
                                    let buckets: Vec<_> = entry
                                        .buckets
                                        .split(";")
                                        .map(|e| Value::UInt(e.parse::<u64>().unwrap().into()))
                                        .collect();
                                    assert_eq!(buckets.len(), 16);

                                    TupleData::from_data(vec![
                                        (
                                            "buckets".into(),
                                            Value::cons_list(buckets, &epoch).unwrap(),
                                        ),
                                        ("base".into(), base),
                                        ("coeff".into(), coeff),
                                        ("nonalpha-discount".into(), nonalpha_discount),
                                        ("no-vowel-discount".into(), no_vowel_discount),
                                    ])
                                    .unwrap()
                                };

                                let namespace_props = Value::Tuple(
                                    TupleData::from_data(vec![
                                        ("revealed-at".into(), revealed_at),
                                        ("launched-at".into(), Value::some(launched_at).unwrap()),
                                        ("lifetime".into(), lifetime),
                                        ("namespace-import".into(), importer),
                                        ("can-update-price-function".into(), Value::Bool(true)),
                                        ("price-function".into(), Value::Tuple(price_function)),
                                    ])
                                    .unwrap(),
                                );

                                db.insert_entry_unknown_descriptor(
                                    &bns_contract_id,
                                    "namespaces",
                                    namespace,
                                    namespace_props,
                                    &epoch,
                                )?;
                            }
                            Ok(())
                        })
                        .unwrap();
                }

                // BNS Names
                if let Some(get_names) = boot_data.get_bulk_initial_names.take() {
                    info!("Initializing chain with names");
                    let epoch = clarity.get_epoch();
                    clarity
                        .with_clarity_db(|db| {
                            let initial_names = get_names();
                            for entry in initial_names {
                                let components: Vec<_> =
                                    entry.fully_qualified_name.split(".").collect();
                                assert_eq!(components.len(), 2);

                                let namespace = {
                                    let namespace_str = components[1];
                                    if !BNS_CHARS_REGEX.is_match(&namespace_str) {
                                        panic!("Invalid namespace characters");
                                    }
                                    let buffer = namespace_str.as_bytes();
                                    Value::buff_from(buffer.to_vec()).expect("Invalid namespace")
                                };

                                let name = {
                                    let name_str = components[0].to_string();
                                    if !BNS_CHARS_REGEX.is_match(&name_str) {
                                        panic!("Invalid name characters");
                                    }
                                    let buffer = name_str.as_bytes();
                                    Value::buff_from(buffer.to_vec()).expect("Invalid name")
                                };

                                let fqn = Value::Tuple(
                                    TupleData::from_data(vec![
                                        ("namespace".into(), namespace),
                                        ("name".into(), name),
                                    ])
                                    .unwrap(),
                                );

                                let owner_address =
                                    ChainStateUtils::parse_genesis_address(&entry.owner, mainnet);

                                let zonefile_hash = {
                                    if entry.zonefile_hash.len() == 0 {
                                        Value::buff_from(vec![]).unwrap()
                                    } else {
                                        let buffer = Hash160::from_hex(&entry.zonefile_hash)
                                            .expect("Invalid zonefile_hash");
                                        Value::buff_from(buffer.to_bytes().to_vec()).unwrap()
                                    }
                                };

                                let expected_asset_type =
                                    db.get_nft_key_type(&bns_contract_id, "names")?;
                                db.set_nft_owner(
                                    &bns_contract_id,
                                    "names",
                                    &fqn,
                                    &owner_address,
                                    &expected_asset_type,
                                    &epoch,
                                )?;

                                let registered_at = Value::UInt(0);
                                let name_props = Value::Tuple(
                                    TupleData::from_data(vec![
                                        (
                                            "registered-at".into(),
                                            Value::some(registered_at).unwrap(),
                                        ),
                                        ("imported-at".into(), Value::none()),
                                        ("revoked-at".into(), Value::none()),
                                        ("zonefile-hash".into(), zonefile_hash),
                                    ])
                                    .unwrap(),
                                );

                                db.insert_entry_unknown_descriptor(
                                    &bns_contract_id,
                                    "name-properties",
                                    fqn.clone(),
                                    name_props,
                                    &epoch,
                                )?;

                                db.insert_entry_unknown_descriptor(
                                    &bns_contract_id,
                                    "owner-name",
                                    Value::Principal(owner_address),
                                    fqn,
                                    &epoch,
                                )?;
                            }
                            Ok(())
                        })
                        .unwrap();
                }
                info!("Saving Genesis block. This could take a while");
            });

            let allocations_tx = StacksTransaction::new(
                tx_version.clone(),
                boot_code_auth,
                TransactionPayload::TokenTransfer(
                    PrincipalData::Standard(boot_code_address.into()),
                    0,
                    TokenTransferMemo([0u8; 34]),
                ),
            );
            let allocations_receipt = StacksTransactionReceipt::from_stx_transfer(
                allocations_tx,
                allocation_events,
                Value::okay_true(),
                ExecutionCost::zero(),
            );
            receipts.push(allocations_receipt);

            if let Some(callback) = boot_data.post_flight_callback.take() {
                callback(&mut clarity_tx);
            }

            // Setup burnchain parameters for pox contract
            let pox_constants = &boot_data.pox_constants;
            let contract = boot_code_id("pox", mainnet);
            let sender = PrincipalData::from(contract.clone());
            let params = vec![
                Value::UInt(boot_data.first_burnchain_block_height as u128),
                Value::UInt(pox_constants.prepare_length as u128),
                Value::UInt(pox_constants.reward_cycle_length as u128),
                Value::UInt(pox_constants.pox_rejection_fraction as u128),
            ];
            clarity_tx.connection().as_transaction(|conn| {
                conn.run_contract_call(
                    &sender,
                    None,
                    &contract,
                    "set-burnchain-parameters",
                    &params,
                    |_, _| false,
                )
                .expect("Failed to set burnchain parameters in PoX contract");
            });

            clarity_tx
                .connection()
                .as_transaction(|tx| {
                    tx.with_clarity_db(|db| {
                        db.increment_ustx_liquid_supply(initial_liquid_ustx)
                            .map_err(|e| e.into())
                    })
                })
                .expect("FATAL: `ustx-liquid-supply` overflowed");

            clarity_tx.commit_to_block(&FIRST_BURNCHAIN_CONSENSUS_HASH, &FIRST_STACKS_BLOCK_HASH);
        }

        // verify that genesis root hash is as expected
        {
            let genesis_root_hash = chainstate.get_genesis_root_hash()?;

            info!("Computed Clarity state genesis"; "root_hash" => %genesis_root_hash);

            if mainnet {
                assert_eq!(
                    &genesis_root_hash.to_string(),
                    MAINNET_2_0_GENESIS_ROOT_HASH,
                    "Incorrect root hash for genesis block computed. expected={} computed={}",
                    MAINNET_2_0_GENESIS_ROOT_HASH,
                    genesis_root_hash.to_string()
                )
            }
        }

        {
            // add a block header entry for the boot code
            let mut tx = chainstate.index_tx_begin()?;
            let parent_hash = StacksBlockId::sentinel();
            let first_index_hash = StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            );

            test_debug!(
                "Boot code headers index_put_begin {}-{}",
                &parent_hash,
                &first_index_hash
            );

            let first_root_hash =
                tx.put_indexed_all(&parent_hash, &first_index_hash, &vec![], &vec![])?;

            test_debug!(
                "Boot code headers index_commit {}-{}",
                &parent_hash,
                &first_index_hash
            );

            let first_tip_info = StacksHeaderInfo::genesis(
                first_root_hash,
                &boot_data.first_burnchain_block_hash,
                boot_data.first_burnchain_block_height,
                boot_data.first_burnchain_block_timestamp as u64,
            );

            chainstate.insert_stacks_block_header(
                &mut tx,
                &parent_hash,
                &first_tip_info,
                &ExecutionCost::zero(),
                0,
            )?;
            tx.commit()?;
        }

        debug!("Finish install boot code");
        Ok(receipts)
    }
}