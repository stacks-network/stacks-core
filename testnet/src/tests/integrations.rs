use std::collections::HashMap;

use stacks::vm::{
    database::ClaritySerializable,
    types::{QualifiedContractIdentifier, TupleData},
    analysis::{mem_type_check, contract_interface_builder::{build_contract_interface, ContractInterface}},
    Value };
use stacks::chainstate::stacks::{
    db::StacksChainState, StacksPrivateKey, StacksAddress };
use stacks::chainstate::burn::VRFSeed;
use stacks::burnchains::Address;
use stacks::net::{AccountEntryResponse, ContractSrcResponse, CallReadOnlyRequestBody};
use stacks::vm::clarity::ClarityConnection;

use crate::config::InitialBalance;
use crate::helium::RunLoop;

use super::{make_contract_publish, make_contract_call, make_stacks_transfer, SK_1, SK_2, SK_3, ADDR_4, to_addr};

use reqwest;

const GET_INFO_CONTRACT: &'static str = "
        (define-map block-data 
          ((height uint))
          ((stacks-hash (buff 32)) 
           (id-hash (buff 32))
           (btc-hash (buff 32))
           (vrf-seed (buff 32))
           (burn-block-time uint)
           (stacks-miner principal)))
        (define-private (test-1) (get-block-info? time u1))
        (define-private (test-2) (get-block-info? time block-height))
        (define-private (test-3) (get-block-info? time u100000))
        (define-private (test-4 (x uint)) (get-block-info? header-hash x))
        (define-private (test-5) (get-block-info? header-hash (- block-height u1)))
        (define-private (test-6) (get-block-info? burnchain-header-hash u1))
        (define-private (test-7) (get-block-info? vrf-seed u1))
        (define-private (test-8) (get-block-info? miner-address u1))
        (define-private (test-9) (get-block-info? miner-address block-height))
        (define-private (test-10) (get-block-info? miner-address u100000))

        (define-private (get-block-id-hash (height uint)) (unwrap-panic
          (get id-hash (map-get? block-data ((height height))))))

        ;; should always return true!
        ;;   evaluates 'block-height' at the block in question.
        ;;   NOTABLY, this would fail if the MARF couldn't figure out
        ;;    the height of the 'current chain tip'.
        (define-private (exotic-block-height (height uint))
          (is-eq (at-block (get-block-id-hash height) block-height)
                 height))
        (define-read-only (get-exotic-data-info (height uint))
          (unwrap-panic (map-get? block-data { height: height })))

        (define-private (exotic-data-checks (height uint))
          (let ((block-to-check (unwrap-panic (get-block-info? id-header-hash height)))
                (block-info (unwrap-panic (map-get? block-data ((height (- height u1)))))))
            (and (is-eq (print (unwrap-panic (at-block block-to-check (get-block-info? id-header-hash (- block-height u1)))))
                        (print (get id-hash block-info)))
                 (is-eq (print (unwrap-panic (at-block block-to-check (get-block-info? header-hash (- block-height u1)))))
                        (print (unwrap-panic (get-block-info? header-hash (- height u1))))
                        (print (get stacks-hash block-info)))
                 (is-eq (print (unwrap-panic (at-block block-to-check (get-block-info? vrf-seed (- block-height u1)))))
                        (print (unwrap-panic (get-block-info? vrf-seed (- height u1))))
                        (print (get vrf-seed block-info)))
                 (is-eq (print (unwrap-panic (at-block block-to-check (get-block-info? burnchain-header-hash (- block-height u1)))))
                        (print (unwrap-panic (get-block-info? burnchain-header-hash (- height u1))))
                        (print (get btc-hash block-info)))
                 (is-eq (print (unwrap-panic (at-block block-to-check (get-block-info? time (- block-height u1)))))
                        (print (unwrap-panic (get-block-info? time (- height u1))))
                        (print (get burn-block-time block-info)))
                 (is-eq (print (unwrap-panic (at-block block-to-check (get-block-info? miner-address (- block-height u1)))))
                        (print (unwrap-panic (get-block-info? miner-address (- height u1))))
                        (print (get stacks-miner block-info))))))

        (define-private (inner-update-info (height uint))
            (let ((value (tuple 
              (stacks-hash (unwrap-panic (get-block-info? header-hash height)))
              (id-hash (unwrap-panic (get-block-info? id-header-hash height)))
              (btc-hash (unwrap-panic (get-block-info? burnchain-header-hash height)))
              (vrf-seed (unwrap-panic (get-block-info? vrf-seed height)))
              (burn-block-time (unwrap-panic (get-block-info? time height)))
              (stacks-miner (unwrap-panic (get-block-info? miner-address height))))))
             (ok (map-set block-data ((height height)) value))))

        (define-public (update-info)
          (begin
            (inner-update-info (- block-height u2))
            (inner-update-info (- block-height u1))))
       ";


use std::sync::Mutex;

lazy_static! {
    static ref HTTP_BINDING: Mutex<Option<String>> = Mutex::new(None);
}

#[test]
fn integration_test_get_info() {
    let mut conf = super::new_test_conf();
    let spender_addr = to_addr(&StacksPrivateKey::from_hex(SK_3).unwrap()).into();

    conf.initial_balances.push(InitialBalance { 
        address: spender_addr,
        amount: 100300
    });

    conf.burnchain.commit_anchor_block_within = 1500;

    let num_rounds = 4;

    let mut run_loop = RunLoop::new(conf);

    { 
        let mut http_opt = HTTP_BINDING.lock().unwrap();
        http_opt.replace(format!("http://{}", &run_loop.node.config.node.rpc_bind));
    }

    run_loop.callbacks.on_new_tenure(|round, _burnchain_tip, chain_tip, tenure| {
        let contract_sk = StacksPrivateKey::from_hex(SK_1).unwrap();
        let principal_sk = StacksPrivateKey::from_hex(SK_2).unwrap();
        let spender_sk = StacksPrivateKey::from_hex(SK_3).unwrap();
        let header_hash = chain_tip.block.block_hash();
        let burn_header_hash = chain_tip.metadata.burn_header_hash;

        if round == 1 { // block-height = 2
            let publish_tx = make_contract_publish(&contract_sk, 0, 0, "get-info", GET_INFO_CONTRACT);
            eprintln!("Tenure in 1 started!");
            tenure.mem_pool.submit_raw(&burn_header_hash, &header_hash,publish_tx).unwrap();
        } else if round >= 2 { // block-height > 2
            let tx = make_contract_call(&principal_sk, (round - 2).into(), 0, &to_addr(&contract_sk), "get-info", "update-info", &[]);
            tenure.mem_pool.submit_raw(&burn_header_hash, &header_hash,tx).unwrap();
        }

        if round >= 1 {
            let tx_xfer = make_stacks_transfer(&spender_sk, (round - 1).into(), 0,
                                               &StacksAddress::from_string(ADDR_4).unwrap().into(), 100);
            tenure.mem_pool.submit_raw(&burn_header_hash, &header_hash,tx_xfer).unwrap();
        }

        return
    });

    run_loop.callbacks.on_new_stacks_chain_state(|round, _burnchain_tip, chain_tip, chain_state| {
        let contract_addr = to_addr(&StacksPrivateKey::from_hex(SK_1).unwrap());
        let contract_identifier =
            QualifiedContractIdentifier::parse(&format!("{}.{}", &contract_addr, "get-info")).unwrap();

        let http_origin = {
            HTTP_BINDING.lock().unwrap().clone().unwrap()
        };

        match round {
            1 => {
                // - Chain length should be 2.
                let mut blocks = StacksChainState::list_blocks(&chain_state.blocks_db).unwrap();
                blocks.sort();
                assert!(chain_tip.metadata.block_height == 2);
                
                // Block #1 should have 3 txs
                assert!(chain_tip.block.txs.len() == 3);

                let parent = chain_tip.block.header.parent_block;
                let bhh = &chain_tip.metadata.index_block_hash();
                eprintln!("Current Block: {}       Parent Block: {}", bhh, parent);
                let parent_val = Value::buff_from(parent.as_bytes().to_vec()).unwrap();

                // find header metadata
                let mut headers = vec![];
                for block in blocks.iter() {
                    let header = StacksChainState::get_anchored_block_header_info(&chain_state.headers_db, &block.0, &block.1).unwrap().unwrap();
                    headers.push(header);
                }

                let _tip_header_info = headers.last().unwrap();

                // find miner metadata
                let mut miners = vec![];
                for block in blocks.iter() {
                    let miner = StacksChainState::get_miner_info(&chain_state.headers_db, &block.0, &block.1).unwrap().unwrap();
                    miners.push(miner);
                }

                let _tip_miner = miners.last().unwrap();

                assert_eq!(
                    chain_state.clarity_eval_read_only(
                        bhh, &contract_identifier, "block-height"),
                    Value::UInt(2));

                assert_eq!(
                    chain_state.clarity_eval_read_only(
                        bhh, &contract_identifier, "(test-1)"),
                    Value::some(Value::UInt(headers[0].burn_header_timestamp as u128)).unwrap());
                
                assert_eq!(
                    chain_state.clarity_eval_read_only(
                        bhh, &contract_identifier, "(test-2)"),
                    Value::none());

                assert_eq!(
                    chain_state.clarity_eval_read_only(
                        bhh, &contract_identifier, "(test-3)"),
                    Value::none());
                
                assert_eq!(
                    chain_state.clarity_eval_read_only(
                        bhh, &contract_identifier, "(test-4 u1)"),
                    Value::some(parent_val.clone()).unwrap());

                assert_eq!(
                    chain_state.clarity_eval_read_only(
                        bhh, &contract_identifier, "(test-5)"),
                    Value::some(parent_val).unwrap());

                // test-6 and test-7 return the block at height 1's VRF-seed,
                //   which in this integration test, should be blocks[0]
                let last_tip = blocks[0];
                eprintln!("Last block info: stacks: {}, burn: {}", last_tip.1, last_tip.0);
                let last_block = StacksChainState::load_block(&chain_state.blocks_path, &last_tip.0, &last_tip.1).unwrap().unwrap();
                assert_eq!(parent, last_block.header.block_hash());

                let last_vrf_seed = VRFSeed::from_proof(&last_block.header.proof).as_bytes().to_vec();
                let last_burn_header = last_tip.0.as_bytes().to_vec();

                assert_eq!(
                    chain_state.clarity_eval_read_only(
                        bhh, &contract_identifier, "(test-6)"),
                    Value::some(Value::buff_from(last_burn_header).unwrap()).unwrap());
                assert_eq!(
                    chain_state.clarity_eval_read_only(
                        bhh, &contract_identifier, "(test-7)"),
                    Value::some(Value::buff_from(last_vrf_seed).unwrap()).unwrap());

                // verify that we can get the block miner
                assert_eq!(
                    chain_state.clarity_eval_read_only(
                        bhh, &contract_identifier, "(test-8)"),
                    Value::some(Value::Principal(miners[0].address.to_account_principal())).unwrap());

                assert_eq!(
                    chain_state.clarity_eval_read_only(
                        bhh, &contract_identifier, "(test-9)"),
                    Value::none());

                assert_eq!(
                    chain_state.clarity_eval_read_only(
                        bhh, &contract_identifier, "(test-10)"),
                    Value::none());
                    
            },
            3 => {
                let bhh = &chain_tip.metadata.index_block_hash();

                assert_eq!(Value::Bool(true), chain_state.clarity_eval_read_only(
                    bhh, &contract_identifier, "(exotic-block-height u1)"));
                assert_eq!(Value::Bool(true), chain_state.clarity_eval_read_only(
                    bhh, &contract_identifier, "(exotic-block-height u2)"));
                assert_eq!(Value::Bool(true), chain_state.clarity_eval_read_only(
                    bhh, &contract_identifier, "(exotic-block-height u3)"));

                assert_eq!(Value::Bool(true), chain_state.clarity_eval_read_only(
                    bhh, &contract_identifier, "(exotic-data-checks u2)"));
                assert_eq!(Value::Bool(true), chain_state.clarity_eval_read_only(
                    bhh, &contract_identifier, "(exotic-data-checks u3)"));

                let client = reqwest::blocking::Client::new();
                let path = format!("{}/v2/map_entry/{}/{}/{}",
                                   &http_origin, &contract_addr, "get-info", "block-data");

                let key: Value = TupleData::from_data(vec![("height".into(), Value::UInt(1))])
                    .unwrap().into();

                eprintln!("Test: POST {}", path);
                let res = client.post(&path)
                    .json(&key.serialize())
                    .send()
                    .unwrap().json::<HashMap<String, String>>().unwrap();
                let result_data = Value::try_deserialize_hex_untyped(&res["data"][2..]).unwrap();
                let expected_data = chain_state.clarity_eval_read_only(bhh, &contract_identifier,
                                                                       "(some (get-exotic-data-info u1))");
                assert!(res.get("proof").is_some());

                assert_eq!(result_data, expected_data);

                let key: Value = TupleData::from_data(vec![("height".into(), Value::UInt(100))])
                    .unwrap().into();

                eprintln!("Test: POST {}", path);
                let res = client.post(&path)
                    .json(&key.serialize())
                    .send()
                    .unwrap().json::<HashMap<String, String>>().unwrap();
                let result_data = Value::try_deserialize_hex_untyped(&res["data"][2..]).unwrap();
                assert_eq!(result_data, Value::none());

                let sender_addr = to_addr(&StacksPrivateKey::from_hex(SK_3).unwrap());

                // now, let's use a query string to get data without a proof
                let path = format!("{}/v2/map_entry/{}/{}/{}?proof=0",
                                   &http_origin, &contract_addr, "get-info", "block-data");

                let key: Value = TupleData::from_data(vec![("height".into(), Value::UInt(1))])
                    .unwrap().into();

                eprintln!("Test: POST {}", path);
                let res = client.post(&path)
                    .json(&key.serialize())
                    .send()
                    .unwrap().json::<HashMap<String, String>>().unwrap();

                assert!(res.get("proof").is_none());
                let result_data = Value::try_deserialize_hex_untyped(&res["data"][2..]).unwrap();
                let expected_data = chain_state.clarity_eval_read_only(bhh, &contract_identifier,
                                                                       "(some (get-exotic-data-info u1))");
                eprintln!("{}", serde_json::to_string(&res).unwrap());

                assert_eq!(result_data, expected_data);

                // now, let's use a query string to get data _with_ a proof
                let path = format!("{}/v2/map_entry/{}/{}/{}?proof=1",
                                   &http_origin, &contract_addr, "get-info", "block-data");

                let key: Value = TupleData::from_data(vec![("height".into(), Value::UInt(1))])
                    .unwrap().into();

                eprintln!("Test: POST {}", path);
                let res = client.post(&path)
                    .json(&key.serialize())
                    .send()
                    .unwrap().json::<HashMap<String, String>>().unwrap();

                assert!(res.get("proof").is_some());
                let result_data = Value::try_deserialize_hex_untyped(&res["data"][2..]).unwrap();
                let expected_data = chain_state.clarity_eval_read_only(bhh, &contract_identifier,
                                                                       "(some (get-exotic-data-info u1))");
                eprintln!("{}", serde_json::to_string(&res).unwrap());

                assert_eq!(result_data, expected_data);

                // account with a nonce entry + a balance entry
                let path = format!("{}/v2/accounts/{}",
                                   &http_origin, &sender_addr);
                eprintln!("Test: GET {}", path);
                let res = client.get(&path).send().unwrap().json::<AccountEntryResponse>().unwrap();
                assert_eq!(u128::from_str_radix(&res.balance[2..], 16).unwrap(), 100000);
                assert_eq!(res.nonce, 3);
                assert!(res.nonce_proof.is_some());
                assert!(res.balance_proof.is_some());

                // account with a nonce entry but not a balance entry
                let path = format!("{}/v2/accounts/{}",
                                   &http_origin, &contract_addr);
                eprintln!("Test: GET {}", path);
                let res = client.get(&path).send().unwrap().json::<AccountEntryResponse>().unwrap();
                assert_eq!(u128::from_str_radix(&res.balance[2..], 16).unwrap(), 0);
                assert_eq!(res.nonce, 1);
                assert!(res.nonce_proof.is_some());
                assert!(res.balance_proof.is_some());

                // account with a balance entry but not a nonce entry
                let path = format!("{}/v2/accounts/{}",
                                   &http_origin, ADDR_4);
                eprintln!("Test: GET {}", path);
                let res = client.get(&path).send().unwrap().json::<AccountEntryResponse>().unwrap();
                assert_eq!(u128::from_str_radix(&res.balance[2..], 16).unwrap(), 300);
                assert_eq!(res.nonce, 0);
                assert!(res.nonce_proof.is_some());
                assert!(res.balance_proof.is_some());

                // account with neither!
                let path = format!("{}/v2/accounts/{}.get-info",
                                   &http_origin, &contract_addr);
                eprintln!("Test: GET {}", path);
                let res = client.get(&path).send().unwrap().json::<AccountEntryResponse>().unwrap();
                assert_eq!(u128::from_str_radix(&res.balance[2..], 16).unwrap(), 0);
                assert_eq!(res.nonce, 0);
                assert!(res.nonce_proof.is_some());
                assert!(res.balance_proof.is_some());

                let path = format!("{}/v2/accounts/{}?proof=0",
                                   &http_origin, ADDR_4);
                eprintln!("Test: GET {}", path);
                let res = client.get(&path).send().unwrap().json::<AccountEntryResponse>().unwrap();
                assert_eq!(u128::from_str_radix(&res.balance[2..], 16).unwrap(), 300);
                assert_eq!(res.nonce, 0);
                assert!(res.nonce_proof.is_none());
                assert!(res.balance_proof.is_none());

                let path = format!("{}/v2/accounts/{}?proof=1",
                                   &http_origin, ADDR_4);
                eprintln!("Test: GET {}", path);
                let res = client.get(&path).send().unwrap().json::<AccountEntryResponse>().unwrap();
                assert_eq!(u128::from_str_radix(&res.balance[2..], 16).unwrap(), 300);
                assert_eq!(res.nonce, 0);
                assert!(res.nonce_proof.is_some());
                assert!(res.balance_proof.is_some());

                // let's try getting the transfer cost
                let path = format!("{}/v2/fees/transfer", &http_origin);
                eprintln!("Test: GET {}", path);
                let res = client.get(&path).send().unwrap().json::<u64>().unwrap();
                assert!(res > 0);

                // let's get a contract ABI

                let path = format!("{}/v2/contracts/interface/{}/{}", &http_origin, &contract_addr, "get-info");
                eprintln!("Test: GET {}", path);
                let res = client.get(&path).send().unwrap().json::<ContractInterface>().unwrap();

                let contract_analysis = mem_type_check(GET_INFO_CONTRACT).unwrap().1;
                let expected_interface = build_contract_interface(&contract_analysis);

                eprintln!("{}", serde_json::to_string(&expected_interface).unwrap());

                assert_eq!(res, expected_interface);

                // a missing one?

                let path = format!("{}/v2/contracts/interface/{}/{}", &http_origin, &contract_addr, "not-there");
                eprintln!("Test: GET {}", path);
                assert_eq!(client.get(&path).send().unwrap().status(), 404);

                // let's get a contract SRC

                let path = format!("{}/v2/contracts/source/{}/{}", &http_origin, &contract_addr, "get-info");
                eprintln!("Test: GET {}", path);
                let res = client.get(&path).send().unwrap().json::<ContractSrcResponse>().unwrap();

                assert_eq!(res.source, GET_INFO_CONTRACT);
                assert_eq!(res.publish_height, 2);
                assert!(res.marf_proof.is_some());


                let path = format!("{}/v2/contracts/source/{}/{}?proof=0", &http_origin, &contract_addr, "get-info");
                eprintln!("Test: GET {}", path);
                let res = client.get(&path).send().unwrap().json::<ContractSrcResponse>().unwrap();

                assert_eq!(res.source, GET_INFO_CONTRACT);
                assert_eq!(res.publish_height, 2);
                assert!(res.marf_proof.is_none());

                // a missing one?

                let path = format!("{}/v2/contracts/source/{}/{}", &http_origin, &contract_addr, "not-there");
                eprintln!("Test: GET {}", path);
                assert_eq!(client.get(&path).send().unwrap().status(), 404);


                // how about a read-only function call!
                let path = format!("{}/v2/contracts/call-read/{}/{}/{}", &http_origin, &contract_addr, "get-info", "get-exotic-data-info");
                eprintln!("Test: POST {}", path);

                let body = CallReadOnlyRequestBody {
                    sender: "'SP139Q3N9RXCJCD1XVA4N5RYWQ5K9XQ0T9PKQ8EE5".into(),
                    arguments: vec![Value::UInt(1).serialize()]
                };

                let res = client.post(&path)
                    .json(&body)
                    .send()
                    .unwrap().json::<serde_json::Value>().unwrap();
                assert!(res.get("cause").is_none());
                assert!(res["okay"].as_bool().unwrap());

                let result_data = Value::try_deserialize_hex_untyped(&res["result"].as_str().unwrap()[2..]).unwrap();
                let expected_data = chain_state.clarity_eval_read_only(bhh, &contract_identifier,
                                                                       "(get-exotic-data-info u1)");
                assert_eq!(result_data, expected_data);

                // let's have a runtime error!
                let path = format!("{}/v2/contracts/call-read/{}/{}/{}", &http_origin, &contract_addr, "get-info", "get-exotic-data-info");
                eprintln!("Test: POST {}", path);

                let body = CallReadOnlyRequestBody {
                    sender: "'SP139Q3N9RXCJCD1XVA4N5RYWQ5K9XQ0T9PKQ8EE5".into(),
                    arguments: vec![Value::UInt(100).serialize()]
                };

                let res = client.post(&path)
                    .json(&body)
                    .send()
                    .unwrap().json::<serde_json::Value>().unwrap();

                assert!(res.get("result").is_none());
                assert!(!res["okay"].as_bool().unwrap());
                assert!(res["cause"].as_str().unwrap().contains("UnwrapFailure"));

                // let's have a runtime error!
                let path = format!("{}/v2/contracts/call-read/{}/{}/{}", &http_origin, &contract_addr, "get-info", "update-info");
                eprintln!("Test: POST {}", path);

                let body = CallReadOnlyRequestBody {
                    sender: "'SP139Q3N9RXCJCD1XVA4N5RYWQ5K9XQ0T9PKQ8EE5".into(),
                    arguments: vec![]
                };

                let res = client.post(&path)
                    .json(&body)
                    .send()
                    .unwrap().json::<serde_json::Value>().unwrap();

                eprintln!("{}", res["cause"].as_str().unwrap());
                assert!(res.get("result").is_none());
                assert!(!res["okay"].as_bool().unwrap());
                assert!(res["cause"].as_str().unwrap().contains("NotReadOnly"));
            },
            _ => {},
        }
    });

    run_loop.start(num_rounds);
}

const FAUCET_CONTRACT: &'static str = "
  (define-public (spout)
    (let ((recipient tx-sender))
      (print (as-contract (stx-transfer? u1 .faucet recipient)))))
";

#[test]
fn contract_stx_transfer() {
    let mut conf = super::new_test_conf();

    let sk_3 = StacksPrivateKey::from_hex(SK_3).unwrap();
    let addr_3 = to_addr(&sk_3);

    conf.burnchain.commit_anchor_block_within = 1500;
    conf.add_initial_balance(addr_3.to_string(), 100000);

    let num_rounds = 5;

    let mut run_loop = RunLoop::new(conf);
    run_loop.callbacks.on_new_tenure(|round, _burnchain_tip, chain_tip, tenure| {
        let contract_sk = StacksPrivateKey::from_hex(SK_1).unwrap();
        let sk_2 = StacksPrivateKey::from_hex(SK_2).unwrap();
        let sk_3 = StacksPrivateKey::from_hex(SK_3).unwrap();
        let header_hash = chain_tip.block.block_hash();
        let burn_header_hash = chain_tip.metadata.burn_header_hash;

        let contract_identifier =
            QualifiedContractIdentifier::parse(&format!("{}.{}",
                                                        to_addr(
                                                            &StacksPrivateKey::from_hex(SK_1).unwrap()).to_string(),
                                                        "faucet")).unwrap();

        if round == 1 { // block-height = 2
            let xfer_to_contract = make_stacks_transfer(&sk_3, 0, 0, &contract_identifier.into(), 1000);
            tenure.mem_pool.submit_raw(&burn_header_hash, &header_hash,xfer_to_contract).unwrap();
        } else if round == 2 { // block-height > 2
            let publish_tx = make_contract_publish(&contract_sk, 0, 0, "faucet", FAUCET_CONTRACT);
            tenure.mem_pool.submit_raw(&burn_header_hash, &header_hash,publish_tx).unwrap();
        } else if round == 3 {
            // try to publish again
            //   TODO: disabled, pending resolution of issue #1376
            // let publish_tx = make_contract_publish(&contract_sk, 1, 0, "faucet", FAUCET_CONTRACT);
            // tenure.mem_pool.submit(publish_tx);

            let tx = make_contract_call(&sk_2, 0, 0, &to_addr(&contract_sk), "faucet", "spout", &[]);
            tenure.mem_pool.submit_raw(&burn_header_hash, &header_hash,tx).unwrap();
        } else if round == 4 {
            // transfer to the contract again.
            let xfer_to_contract = make_stacks_transfer(&sk_3, 1, 0, &contract_identifier.into(), 1000);
            tenure.mem_pool.submit_raw(&burn_header_hash, &header_hash,xfer_to_contract).unwrap();
        }

        return
    });

    run_loop.callbacks.on_new_stacks_chain_state(|round, _burnchain_tip, chain_tip, chain_state| {
        let contract_identifier =
            QualifiedContractIdentifier::parse(&format!("{}.{}",
                                                        to_addr(
                                                            &StacksPrivateKey::from_hex(SK_1).unwrap()).to_string(),
                                                        "faucet")).unwrap();

        match round {
            1 => {
                assert!(chain_tip.metadata.block_height == 2);
                // Block #1 should have 2 txs -- coinbase + transfer
                assert!(chain_tip.block.txs.len() == 2);

                let cur_tip = (chain_tip.metadata.burn_header_hash.clone(), chain_tip.metadata.anchored_header.block_hash());
                // check that 1000 stx _was_ transfered to the contract principal
                assert_eq!(
                    chain_state.with_read_only_clarity_tx(&cur_tip.0, &cur_tip.1, |conn| {
                        conn.with_clarity_db_readonly(|db| {
                            db.get_account_stx_balance(&contract_identifier.clone().into())
                        })
                    }),
                    1000);
                // check that 1000 stx _was_ debited from SK_3
                let sk_3 = StacksPrivateKey::from_hex(SK_3).unwrap();
                let addr_3 = to_addr(&sk_3).into();
                assert_eq!(
                    chain_state.with_read_only_clarity_tx(&cur_tip.0, &cur_tip.1, |conn| {
                        conn.with_clarity_db_readonly(|db| {
                            db.get_account_stx_balance(&addr_3)
                        })
                    }),
                    99000);
            },
            2 => {
                assert!(chain_tip.metadata.block_height == 3);
                // Block #2 should have 2 txs -- coinbase + publish
                assert!(chain_tip.block.txs.len() == 2);
            },
            3 => {
                assert!(chain_tip.metadata.block_height == 4);
                // Block #3 should have 2 txs -- coinbase + contract-call,
                //   the second publish _should have been rejected_
                assert!(chain_tip.block.txs.len() == 2);

                // check that 1 stx was transfered to SK_2 via the contract-call
                let cur_tip = (chain_tip.metadata.burn_header_hash.clone(), chain_tip.metadata.anchored_header.block_hash());

                let sk_2 = StacksPrivateKey::from_hex(SK_2).unwrap();
                let addr_2 = to_addr(&sk_2).into();
                assert_eq!(
                    chain_state.with_read_only_clarity_tx(&cur_tip.0, &cur_tip.1, |conn| {
                        conn.with_clarity_db_readonly(|db| {
                            db.get_account_stx_balance(&addr_2)
                        })
                    }),
                    1);

                assert_eq!(
                    chain_state.with_read_only_clarity_tx(&cur_tip.0, &cur_tip.1, |conn| {
                        conn.with_clarity_db_readonly(|db| {
                            db.get_account_stx_balance(&contract_identifier.clone().into())
                        })
                    }),
                    999);
            },
            4 => {
                assert!(chain_tip.metadata.block_height == 5);
                assert!(chain_tip.block.txs.len() == 2);

                let cur_tip = (chain_tip.metadata.burn_header_hash.clone(), chain_tip.metadata.anchored_header.block_hash());

                // check that 1000 stx were sent to the contract
                assert_eq!(
                    chain_state.with_read_only_clarity_tx(&cur_tip.0, &cur_tip.1, |conn| {
                        conn.with_clarity_db_readonly(|db| {
                            db.get_account_stx_balance(&contract_identifier.clone().into())
                        })
                    }),
                    1999);
                // check that 1000 stx _was_ debited from SK_3
                let sk_3 = StacksPrivateKey::from_hex(SK_3).unwrap();
                let addr_3 = to_addr(&sk_3).into();
                assert_eq!(
                    chain_state.with_read_only_clarity_tx(&cur_tip.0, &cur_tip.1, |conn| {
                        conn.with_clarity_db_readonly(|db| {
                            db.get_account_stx_balance(&addr_3)
                        })
                    }),
                    98000);
            },

            _ => {},
        }
    });

    run_loop.start(num_rounds);
}
