use vm::{
    database::HeadersDB,
    types::QualifiedContractIdentifier,
    Value, ClarityName, ContractName, errors::RuntimeErrorType, errors::Error as ClarityError };
use chainstate::stacks::{
    db::StacksChainState, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
    StacksPrivateKey, TransactionSpendingCondition, TransactionAuth, TransactionVersion,
    StacksPublicKey, TransactionPayload, StacksTransactionSigner,
    StacksTransaction, TransactionSmartContract, TransactionContractCall, StacksAddress };
use chainstate::burn::VRFSeed;
use burnchains::Address;
use address::AddressHashMode;
use net::{Error as NetError, StacksMessageCodec};
use util::{log, strings::StacksString, hash::hex_bytes, hash::to_hex};

use util::db::{DBConn, FromRow};

use testnet;
use testnet::mem_pool::MemPool;

fn serialize_sign_standard_single_sig_tx(payload: TransactionPayload,
                                         sender: &StacksPrivateKey, nonce: u64) -> Vec<u8> {
    let mut spending_condition = TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(sender))
        .expect("Failed to create p2pkh spending condition from public key.");
    spending_condition.set_nonce(nonce);
    spending_condition.set_fee_rate(0);
    let auth = TransactionAuth::Standard(spending_condition);
    let unsigned_tx = StacksTransaction::new(TransactionVersion::Testnet, auth, payload);
    let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);
    tx_signer.sign_origin(sender).unwrap();
    tx_signer.get_tx().unwrap().serialize()    
}

fn make_contract_publish(sender: &StacksPrivateKey, nonce: u64, contract_name: &str, contract_content: &str) -> Vec<u8> {
    let name = ContractName::from(contract_name);
    let code_body = StacksString::from_string(&contract_content.to_string()).unwrap();

    let payload = TransactionSmartContract { name, code_body };

    serialize_sign_standard_single_sig_tx(payload.into(), sender, nonce)
}

fn make_contract_call(
    sender: &StacksPrivateKey, nonce: u64,
    contract_addr: &StacksAddress, contract_name: &str,
    function_name: &str, function_args: &[Value]) -> Vec<u8> {

    let contract_name = ContractName::from(contract_name);
    let function_name = ClarityName::from(function_name);

    let payload = TransactionContractCall {
        address: contract_addr.clone(),
        contract_name, function_name,
        function_args: function_args.iter().map(|x| x.clone()).collect()
    };

    serialize_sign_standard_single_sig_tx(payload.into(), sender, nonce)
}

fn to_addr(sk: &StacksPrivateKey) -> StacksAddress {
    StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG, &AddressHashMode::SerializeP2PKH, 1, &vec![StacksPublicKey::from_private(sk)])
        .unwrap()
}

const GET_INFO_CONTRACT: &'static str = "
        (define-map block-data 
          ((height uint))
          ((stacks-hash (buff 32)) 
           (id-hash (buff 32))
           (btc-hash (buff 32))
           (vrf-seed (buff 32))))
        (define-private (test-1) (get-block-info? time u1))
        (define-private (test-2) (get-block-info? time block-height))
        (define-private (test-3) (get-block-info? time u100000))
        (define-private (test-4 (x uint)) (get-block-info? header-hash x))
        (define-private (test-5) (get-block-info? header-hash (- block-height u1)))
        (define-private (test-6) (get-block-info? burnchain-header-hash u1))
        (define-private (test-7) (get-block-info? vrf-seed u1))

        (define-private (get-block-id-hash (height uint)) (unwrap-panic
          (get id-hash (map-get? block-data ((height height))))))

        ;; should always return true!
        ;;   evaluates 'block-height' at the block in question.
        ;;   NOTABLY, this would fail if the MARF couldn't figure out
        ;;    the height of the 'current chain tip'.
        (define-private (exotic-block-height (height uint))
          (is-eq (at-block (get-block-id-hash height) block-height)
                 height))

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
                        (print (get btc-hash block-info))))))

        (define-private (inner-update-info (height uint))
            (let ((value (tuple 
              (stacks-hash (unwrap-panic (get-block-info? header-hash height)))
              (id-hash (unwrap-panic (get-block-info? id-header-hash height)))
              (btc-hash (unwrap-panic (get-block-info? burnchain-header-hash height)))
              (vrf-seed (unwrap-panic (get-block-info? vrf-seed height))))))
             (ok (map-set block-data ((height height)) value))))

        (define-public (update-info)
          (begin
            (inner-update-info (- block-height u2))
            (inner-update-info (- block-height u1))))
       ";

const SK_1: &'static str = "a1289f6438855da7decf9b61b852c882c398cff1446b2a0f823538aa2ebef92e01";
const SK_2: &'static str = "4ce9a8f7539ea93753a36405b16e8b57e15a552430410709c2b6d65dca5c02e201";
const SK_3: &'static str = "cb95ddd0fe18ec57f4f3533b95ae564b3f1ae063dbf75b46334bd86245aef78501";

#[test]
fn integration_test_get_info() {
    let mut conf = testnet::tests::new_test_conf();

    conf.burnchain_block_time = 1500;

    let contract_sk = StacksPrivateKey::new();

    let num_rounds = 4;
    let contract_addr = to_addr(&contract_sk);

    let mut run_loop = testnet::RunLoop::new(conf);
    run_loop.apply_on_new_tenures(|round, tenure| {
        let contract_sk = StacksPrivateKey::from_hex(SK_1).unwrap();
        let principal_sk = StacksPrivateKey::from_hex(SK_2).unwrap();

        if round == 1 { // block-height = 2
            let publish_tx = make_contract_publish(&contract_sk, 0, "get-info", GET_INFO_CONTRACT);
            eprintln!("Tenure in 1 started!");
            tenure.mem_pool.submit(publish_tx);
        } else if round >= 2 { // block-height > 2
            let tx = make_contract_call(&principal_sk, (round - 2).into(), &to_addr(&contract_sk), "get-info", "update-info", &[]);
            tenure.mem_pool.submit(tx);
        }

        return
    });

    run_loop.apply_on_new_chain_states(|round, ref mut chain_state, bhh| {
        let contract_identifier =
            QualifiedContractIdentifier::parse(&format!("{}.{}",
                                                        to_addr(
                                                            &StacksPrivateKey::from_hex(SK_1).unwrap()).to_string(),
                                                        "get-info")).unwrap();

        match round {
            1 => {
                // - Chain length should be 2.
                let mut blocks = StacksChainState::list_blocks(&chain_state.blocks_db, &chain_state.blocks_path).unwrap();
                blocks.sort();
                assert!(blocks.len() == 2);
                
                // Block #1 should only have 2 txs
                let chain_tip = blocks.last().unwrap();
                let block = StacksChainState::load_block(&chain_state.blocks_path, &chain_tip.0, &chain_tip.1).unwrap().unwrap();
                assert!(block.txs.len() == 2);

                let parent = block.header.parent_block;
                eprintln!("Current Block: {}       Parent Block: {}", bhh, parent);
                let parent_val = Value::buff_from(parent.as_bytes().to_vec()).unwrap();

                assert_eq!(
                    chain_state.clarity_eval_read_only(
                        bhh, &contract_identifier, "block-height"),
                    Value::UInt(2));

                assert_eq!(
                    chain_state.clarity_eval_read_only(
                        bhh, &contract_identifier, "(test-4 u1)"),
                    Value::some(parent_val.clone()));

                assert_eq!(
                    chain_state.clarity_eval_read_only(
                        bhh, &contract_identifier, "(test-5)"),
                    Value::some(parent_val));

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
                    Value::some(Value::buff_from(last_burn_header).unwrap()));
                assert_eq!(
                    chain_state.clarity_eval_read_only(
                        bhh, &contract_identifier, "(test-7)"),
                    Value::some(Value::buff_from(last_vrf_seed).unwrap()));
            },
            3 => {
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

            },
            _ => {},
        }
    });

    run_loop.start(num_rounds);
}
