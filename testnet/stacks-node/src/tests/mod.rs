use std::convert::TryInto;

use rand::{Rng, RngCore};

use stacks::chainstate::burn::ConsensusHash;
use stacks::chainstate::stacks::{
    db::StacksChainState, miner::BlockBuilderSettings, miner::StacksMicroblockBuilder,
    CoinbasePayload, StacksBlock, StacksMicroblock, StacksMicroblockHeader, StacksPrivateKey,
    StacksPublicKey, StacksTransaction, StacksTransactionSigner, TokenTransferMemo,
    TransactionAnchorMode, TransactionAuth, TransactionContractCall, TransactionPayload,
    TransactionPostConditionMode, TransactionSmartContract, TransactionSpendingCondition,
    TransactionVersion, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use stacks::codec::StacksMessageCodec;
use stacks::core::LAYER_1_CHAIN_ID_TESTNET;
use stacks::types::chainstate::StacksAddress;
use stacks::util::get_epoch_time_secs;
use stacks::util::hash::hex_bytes;
use stacks::util_lib::strings::StacksString;
use stacks::vm::database::BurnStateDB;
use stacks::vm::types::PrincipalData;
use stacks::vm::{ClarityName, ContractName, Value};
use stacks::{address::AddressHashMode, util::hash::to_hex};

use super::Config;

// mod mempool;
pub mod forking;
pub mod l1_observer_test;
#[allow(dead_code)]
pub mod neon_integrations;

// $ cat /tmp/out.clar
pub const STORE_CONTRACT: &str = r#"(define-map store { key: (string-ascii 32) } { value: (string-ascii 32) })
 (define-public (get-value (key (string-ascii 32)))
    (begin
      (print (concat "Getting key " key))
      (match (map-get? store { key: key })
        entry (ok (get value entry))
        (err 0))))
 (define-public (set-value (key (string-ascii 32)) (value (string-ascii 32)))
    (begin
        (print (concat "Setting key " key))
        (map-set store { key: key } { value: value })
        (ok true)))"#;
// ./blockstack-cli --testnet publish 043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3 0 0 store /tmp/out.clar

pub const SK_1: &'static str = "a1289f6438855da7decf9b61b852c882c398cff1446b2a0f823538aa2ebef92e01";
pub const SK_2: &'static str = "4ce9a8f7539ea93753a36405b16e8b57e15a552430410709c2b6d65dca5c02e201";
pub const SK_3: &'static str = "cb95ddd0fe18ec57f4f3533b95ae564b3f1ae063dbf75b46334bd86245aef78501";

pub const ADDR_4: &'static str = "ST31DA6FTSJX2WGTZ69SFY11BH51NZMB0ZZ239N96";

pub fn serialize_sign_sponsored_sig_tx_anchor_mode_version(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    payer: &StacksPrivateKey,
    chain_id: u32,
    sender_nonce: u64,
    payer_nonce: u64,
    tx_fee: u64,
    anchor_mode: TransactionAnchorMode,
    version: TransactionVersion,
) -> Vec<u8> {
    serialize_sign_tx_anchor_mode_version(
        payload,
        sender,
        Some(payer),
        chain_id,
        sender_nonce,
        Some(payer_nonce),
        tx_fee,
        anchor_mode,
        version,
    )
}

pub fn serialize_sign_standard_single_sig_tx(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    chain_id: u32,
    nonce: u64,
    tx_fee: u64,
) -> Vec<u8> {
    serialize_sign_standard_single_sig_tx_anchor_mode(
        payload,
        sender,
        chain_id,
        nonce,
        tx_fee,
        TransactionAnchorMode::OnChainOnly,
    )
}

pub fn serialize_sign_standard_single_sig_tx_anchor_mode(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    chain_id: u32,
    nonce: u64,
    tx_fee: u64,
    anchor_mode: TransactionAnchorMode,
) -> Vec<u8> {
    serialize_sign_standard_single_sig_tx_anchor_mode_version(
        payload,
        sender,
        chain_id,
        nonce,
        tx_fee,
        anchor_mode,
        TransactionVersion::Testnet,
    )
}

pub fn serialize_sign_standard_single_sig_tx_anchor_mode_version(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    chain_id: u32,
    nonce: u64,
    tx_fee: u64,
    anchor_mode: TransactionAnchorMode,
    version: TransactionVersion,
) -> Vec<u8> {
    serialize_sign_tx_anchor_mode_version(
        payload,
        sender,
        None,
        chain_id,
        nonce,
        None,
        tx_fee,
        anchor_mode,
        version,
    )
}

pub fn serialize_sign_tx_anchor_mode_version(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    payer: Option<&StacksPrivateKey>,
    chain_id: u32,
    sender_nonce: u64,
    payer_nonce: Option<u64>,
    tx_fee: u64,
    anchor_mode: TransactionAnchorMode,
    version: TransactionVersion,
) -> Vec<u8> {
    let mut sender_spending_condition =
        TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(sender))
            .expect("Failed to create p2pkh spending condition from public key.");
    sender_spending_condition.set_nonce(sender_nonce);

    let auth = match (payer, payer_nonce) {
        (Some(payer), Some(payer_nonce)) => {
            let mut payer_spending_condition = TransactionSpendingCondition::new_singlesig_p2pkh(
                StacksPublicKey::from_private(payer),
            )
            .expect("Failed to create p2pkh spending condition from public key.");
            payer_spending_condition.set_nonce(payer_nonce);
            payer_spending_condition.set_tx_fee(tx_fee);
            TransactionAuth::Sponsored(sender_spending_condition, payer_spending_condition)
        }
        _ => {
            sender_spending_condition.set_tx_fee(tx_fee);
            TransactionAuth::Standard(sender_spending_condition)
        }
    };
    let mut unsigned_tx = StacksTransaction::new(version, auth, payload);
    unsigned_tx.anchor_mode = anchor_mode;
    unsigned_tx.post_condition_mode = TransactionPostConditionMode::Allow;
    unsigned_tx.chain_id = chain_id;

    let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);
    tx_signer.sign_origin(sender).unwrap();
    if let (Some(payer), Some(_)) = (payer, payer_nonce) {
        tx_signer.sign_sponsor(payer).unwrap();
    }

    let mut buf = vec![];
    tx_signer
        .get_tx()
        .unwrap()
        .consensus_serialize(&mut buf)
        .unwrap();
    buf
}

pub fn make_contract_publish(
    sender: &StacksPrivateKey,
    chain_id: u32,
    nonce: u64,
    tx_fee: u64,
    contract_name: &str,
    contract_content: &str,
) -> Vec<u8> {
    let name = ContractName::from(contract_name);
    let code_body = StacksString::from_string(&contract_content.to_string()).unwrap();

    let payload = TransactionSmartContract { name, code_body };

    serialize_sign_standard_single_sig_tx(payload.into(), sender, chain_id, nonce, tx_fee)
}

pub fn make_contract_publish_microblock_only(
    sender: &StacksPrivateKey,
    chain_id: u32,
    nonce: u64,
    tx_fee: u64,
    contract_name: &str,
    contract_content: &str,
) -> Vec<u8> {
    let name = ContractName::from(contract_name);
    let code_body = StacksString::from_string(&contract_content.to_string()).unwrap();

    let payload = TransactionSmartContract { name, code_body };

    serialize_sign_standard_single_sig_tx_anchor_mode(
        payload.into(),
        sender,
        chain_id,
        nonce,
        tx_fee,
        TransactionAnchorMode::OffChainOnly,
    )
}

pub fn new_test_conf() -> Config {
    // secretKey: "b1cf9cee5083f421c84d7cb53be5edf2801c3c78d63d53917aee0bdc8bd160ee01",
    // publicKey: "03e2ed46873d0db820e8c6001aabc082d72b5b900b53b7a1b9714fe7bde3037b81",
    // stacksAddress: "ST2VHM28V9E5QCRD6C73215KAPSBKQGPWTEE5CMQT"
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; 8];
    rng.fill_bytes(&mut buf);

    let mut conf = Config::default();
    conf.node.working_dir = format!(
        "/tmp/hyperchain-node-tests/integrations-neon/{}-{}",
        to_hex(&buf),
        get_epoch_time_secs()
    );
    conf.node.seed =
        hex_bytes("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
    conf.add_initial_balance(
        "ST2VHM28V9E5QCRD6C73215KAPSBKQGPWTEE5CMQT".to_string(),
        10000,
    );

    let rpc_port = u16::from_be_bytes(buf[0..2].try_into().unwrap()).saturating_add(1025) - 1; // use a non-privileged port between 1024 and 65534
    let p2p_port = u16::from_be_bytes(buf[2..4].try_into().unwrap()).saturating_add(1025) - 1; // use a non-privileged port between 1024 and 65534

    let localhost = "127.0.0.1";
    conf.node.rpc_bind = format!("{}:{}", localhost, rpc_port);
    conf.node.p2p_bind = format!("{}:{}", localhost, p2p_port);
    conf.node.data_url = format!("https://{}:{}", localhost, rpc_port);
    conf.node.p2p_address = format!("{}:{}", localhost, p2p_port);

    conf.node.chain_id = rng.gen_range(0u32, u32::MAX);
    info!("Using random L2 chain_id: {}", conf.node.chain_id);

    conf.node.wait_before_first_anchored_block = 1_000;

    conf
}

pub fn to_addr(sk: &StacksPrivateKey) -> StacksAddress {
    StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(sk)],
    )
    .unwrap()
}

pub fn make_stacks_transfer(
    sender: &StacksPrivateKey,
    chain_id: u32,
    nonce: u64,
    tx_fee: u64,
    recipient: &PrincipalData,
    amount: u64,
) -> Vec<u8> {
    let payload =
        TransactionPayload::TokenTransfer(recipient.clone(), amount, TokenTransferMemo([0; 34]));
    serialize_sign_standard_single_sig_tx(payload.into(), sender, chain_id, nonce, tx_fee)
}

pub fn make_sponsored_stacks_transfer_on_testnet(
    sender: &StacksPrivateKey,
    payer: &StacksPrivateKey,
    chain_id: u32,
    sender_nonce: u64,
    payer_nonce: u64,
    tx_fee: u64,
    recipient: &PrincipalData,
    amount: u64,
) -> Vec<u8> {
    let payload =
        TransactionPayload::TokenTransfer(recipient.clone(), amount, TokenTransferMemo([0; 34]));
    serialize_sign_sponsored_sig_tx_anchor_mode_version(
        payload.into(),
        sender,
        payer,
        chain_id,
        sender_nonce,
        payer_nonce,
        tx_fee,
        TransactionAnchorMode::OnChainOnly,
        TransactionVersion::Testnet,
    )
}

pub fn make_stacks_transfer_mblock_only(
    sender: &StacksPrivateKey,
    chain_id: u32,
    nonce: u64,
    tx_fee: u64,
    recipient: &PrincipalData,
    amount: u64,
) -> Vec<u8> {
    let payload =
        TransactionPayload::TokenTransfer(recipient.clone(), amount, TokenTransferMemo([0; 34]));
    serialize_sign_standard_single_sig_tx_anchor_mode(
        payload.into(),
        sender,
        chain_id,
        nonce,
        tx_fee,
        TransactionAnchorMode::OffChainOnly,
    )
}

pub fn make_poison(
    sender: &StacksPrivateKey,
    chain_id: u32,
    nonce: u64,
    tx_fee: u64,
    header_1: StacksMicroblockHeader,
    header_2: StacksMicroblockHeader,
) -> Vec<u8> {
    let payload = TransactionPayload::PoisonMicroblock(header_1, header_2);
    serialize_sign_standard_single_sig_tx(payload.into(), sender, chain_id, nonce, tx_fee)
}

pub fn make_coinbase(sender: &StacksPrivateKey, chain_id: u32, nonce: u64, tx_fee: u64) -> Vec<u8> {
    let payload = TransactionPayload::Coinbase(CoinbasePayload([0; 32]));
    serialize_sign_standard_single_sig_tx(payload.into(), sender, chain_id, nonce, tx_fee)
}

pub fn make_contract_call(
    sender: &StacksPrivateKey,
    chain_id: u32,
    nonce: u64,
    tx_fee: u64,
    contract_addr: &StacksAddress,
    contract_name: &str,
    function_name: &str,
    function_args: &[Value],
) -> Vec<u8> {
    let contract_name = ContractName::from(contract_name);
    let function_name = ClarityName::from(function_name);

    let payload = TransactionContractCall {
        address: contract_addr.clone(),
        contract_name,
        function_name,
        function_args: function_args.iter().map(|x| x.clone()).collect(),
    };

    serialize_sign_standard_single_sig_tx(payload.into(), sender, chain_id, nonce, tx_fee)
}

pub fn make_contract_call_mblock_only(
    sender: &StacksPrivateKey,
    chain_id: u32,
    nonce: u64,
    tx_fee: u64,
    contract_addr: &StacksAddress,
    contract_name: &str,
    function_name: &str,
    function_args: &[Value],
) -> Vec<u8> {
    let contract_name = ContractName::from(contract_name);
    let function_name = ClarityName::from(function_name);

    let payload = TransactionContractCall {
        address: contract_addr.clone(),
        contract_name,
        function_name,
        function_args: function_args.iter().map(|x| x.clone()).collect(),
    };

    serialize_sign_standard_single_sig_tx_anchor_mode(
        payload.into(),
        sender,
        chain_id,
        nonce,
        tx_fee,
        TransactionAnchorMode::OffChainOnly,
    )
}

#[allow(dead_code)]
fn make_microblock(
    privk: &StacksPrivateKey,
    chainstate: &mut StacksChainState,
    burn_dbconn: &dyn BurnStateDB,
    consensus_hash: ConsensusHash,
    block: StacksBlock,
    txs: Vec<StacksTransaction>,
) -> StacksMicroblock {
    let mut block_bytes = vec![];
    block.consensus_serialize(&mut block_bytes).unwrap();

    let mut microblock_builder = StacksMicroblockBuilder::new(
        block.block_hash(),
        consensus_hash.clone(),
        chainstate,
        burn_dbconn,
        BlockBuilderSettings::max_value(),
    )
    .unwrap();
    let mempool_txs: Vec<_> = txs
        .into_iter()
        .map(|tx| {
            // TODO: better fee estimation
            let mut tx_bytes = vec![];
            tx.consensus_serialize(&mut tx_bytes).unwrap();
            (tx, tx_bytes.len() as u64)
        })
        .collect();

    // NOTE: we intentionally do not check the block's microblock pubkey hash against the private
    // key, because we may need to test that microblocks get rejected due to bad signatures.
    let microblock = microblock_builder
        .mine_next_microblock_from_txs(mempool_txs, privk)
        .unwrap();
    microblock
}
