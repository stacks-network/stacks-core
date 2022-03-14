use std::cmp;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
};
use std::{env, thread};

use stacks::burnchains::bitcoin::indexer::{
    BitcoinIndexer, BitcoinIndexerConfig, BitcoinIndexerRuntime,
};
use stacks::burnchains::BurnchainParameters;
use stacks::burnchains::{Address, Burnchain};
use stacks::chainstate::stacks::StacksPrivateKey;
use stacks::net::RPCPeerInfoData;
use stacks::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, StacksAddress, TrieHash};
use stacks::util::hash::hex_bytes;
use stacks::util_lib::strings::StacksString;
use stacks::util::{get_epoch_time_secs, sleep_ms};
use stacks::vm::types::PrincipalData;
use stacks::vm::types::QualifiedContractIdentifier;
use stacks::vm::types::StandardPrincipalData;
use stacks::vm::ContractName;
use stacks::{
    chainstate::burn::db::sortdb::SortitionDB, chainstate::burn::db::sortdb::SortitionHandleConn,
    chainstate::burn::ConsensusHash,
};

use crate::{config::InitialBalance, neon, BitcoinRegtestController, BurnchainController, Config};

use super::bitcoin_regtest::BitcoinCoreController;
use super::{make_contract_publish, to_addr, SK_1};
use crate::tests::neon_integrations::*;

use crate::stacks::vm::types::StacksAddressExtensions;

fn neon_integration_test_appchain_conf(
    host_chain_conf: &Config,
    mining_contract_id: QualifiedContractIdentifier,
    node_p2p_port: u16,
    node_data_port: u16,
    boot_code: &Vec<(ContractName, StacksString)>,
    genesis_hash: TrieHash,
) -> (Config, StacksAddress) {
    let (mut conf, miner_account) = neon_integration_test_conf();

    let mut boot_code_map = HashMap::new();
    for (contract_name, code) in boot_code.iter() {
        boot_code_map.insert(contract_name.clone(), code.clone());
    }

    conf.burnchain.mining_contract = Some(mining_contract_id);
    conf.burnchain.peer_port = host_chain_conf
        .node
        .p2p_bind
        .to_socket_addrs()
        .unwrap()
        .collect::<Vec<_>>()
        .pop()
        .unwrap()
        .port();
    conf.burnchain.rpc_port = host_chain_conf
        .node
        .rpc_bind
        .to_socket_addrs()
        .unwrap()
        .collect::<Vec<_>>()
        .pop()
        .unwrap()
        .port();

    conf.burnchain.genesis_hash = genesis_hash;

    conf.node.rpc_bind = format!("0.0.0.0:{}", node_data_port);
    conf.node.p2p_bind = format!("0.0.0.0:{}", node_p2p_port);
    conf.node.data_url = format!("http://127.0.0.1:{}", node_data_port);
    conf.node.p2p_address = format!("127.0.0.1:{}", node_p2p_port);
    conf.miner.min_tx_fee = 500;
    conf.burnchain.poll_time_secs = 1;

    conf.boot_into_appchain(&boot_code_map);
    (conf, miner_account)
}

fn next_appchain_block_and_wait(appchain_blocks_processed: &Arc<AtomicU64>) {
    let current = appchain_blocks_processed.load(Ordering::SeqCst);
    eprintln!("Waiting for appchain block bump from ({})", current);

    let start = Instant::now();
    while appchain_blocks_processed.load(Ordering::SeqCst) <= current {
        if start.elapsed() > Duration::from_secs(PANIC_TIMEOUT_SECS) {
            error!("Timed out waiting for appchain block to process, trying to continue test");
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    eprintln!(
        "Appchain block bumped at {} ({})",
        get_epoch_time_secs(),
        appchain_blocks_processed.load(Ordering::SeqCst)
    );
}

fn get_last_stacks_block_mined_at_bitcoin_block_height(
    conf: &Config,
    burn_height: u64,
) -> (ConsensusHash, BlockHeaderHash) {
    let burnchain = Burnchain::regtest(&conf.get_burn_db_path());
    let indexer = {
        let (network, network_id) = conf.burnchain.get_bitcoin_network();
        let burnchain_params = BurnchainParameters::from_params(&conf.burnchain.chain, &network)
            .expect("Bitcoin network unsupported");

        let indexer_conf = BitcoinIndexerConfig {
            peer_host: conf.burnchain.peer_host.clone(),
            peer_port: conf.burnchain.peer_port,
            rpc_port: conf.burnchain.rpc_port,
            rpc_ssl: conf.burnchain.rpc_ssl,
            username: conf.burnchain.username.clone(),
            password: conf.burnchain.password.clone(),
            timeout: conf.burnchain.timeout,
            spv_headers_path: conf.get_spv_headers_file_path(),
            first_block: burnchain_params.first_block_height,
            magic_bytes: conf.burnchain.magic_bytes.clone(),
            epochs: conf.burnchain.epochs.clone(),
        };
        let indexer_runtime = BitcoinIndexerRuntime::new(network_id);
        let burnchain_indexer = BitcoinIndexer {
            config: indexer_conf,
            runtime: indexer_runtime,
        };
        burnchain_indexer
    };
    let (sortdb, _) = burnchain
        .connect_db(
            &indexer,
            true,
            BurnchainHeaderHash::from_hex(
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
            )
            .unwrap(),
            0,
        )
        .unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    let ic = sortdb.index_conn();
    let handle = SortitionHandleConn::open_reader(&ic, &tip.sortition_id).unwrap();
    let sn = handle
        .get_last_snapshot_with_sortition(cmp::min(tip.block_height, burn_height))
        .unwrap();
    eprintln!(
        "Last snapshot with sortition as of min({},{}) = {}: {}/{}",
        tip.block_height,
        burn_height,
        cmp::min(tip.block_height, burn_height),
        &sn.consensus_hash,
        &sn.winning_stacks_block_hash
    );
    (sn.consensus_hash, sn.winning_stacks_block_hash)
}

const APPCHAIN_MINING_CONTRACT: &str = r#"
(define-constant ERR_NO_RECIPIENTS u0)
(define-constant ERR_NO_COMMIT_SPEND u1)
(define-constant ERR_INSUFFICIENT_BALANCE u2)
(define-constant ERR_BLOCK_FULL u3)

;; Schema version. Required by the appchain client.
(define-data-var appchain-version uint u1)

;; List of appchain block ops, grouped by host chain block
(define-map appchain
    ;; host chain chain block height
    uint
    ;; list of burnchain operations at that height
    (list 128 {
        ;; miner
        sender: principal,
        ;; is this operation chained to the last one?  Only applies to block-commits
        chained?: bool,
        ;; burnchain op payload (serialized)
        data: (buff 80),
        ;; amount of parent tokens destroyed
        burnt: uint,
        ;; total amount of tokens transferred
        transferred: uint,
        ;; PoX recipients on parent chain
        recipients: (list 2 principal)
    })
)

(define-data-var appchain-config
    {
        ;; 32-bit unique chain identifier (goes into the chain's transactions)
        chain-id: uint,
        ;; height on the host chain at which the appchain's blocks start
        start-height: uint,
        ;; list of boot nodes' public keys, p2p addresses, and rpc addresses
        boot-nodes: (list 16 { public-key: (buff 33), host: (buff 16), port: (buff 2), data-host: (buff 16), data-port: (buff 2) }),
        ;; PoX config for the appchain
        pox: {
            reward-cycle-length: uint,
            prepare-length: uint,
            anchor-threshold: uint,
            pox-rejection-fraction: uint,
            pox-participation-threshold-pct: uint,
            sunset-start: uint,
            sunset-end: uint
        },
        ;; Block limit for the app chain
        block-limit: {
            write-length: uint,
            write-count: uint,
            read-length: uint,
            read-count: uint,
            runtime: uint
        },
        ;; List of contract names that will execute as part of the appchain boot code.
        boot-code: (list 128 (string-ascii 128)),
        ;; List of initial balances to be allocated in the appchain genesis block
        initial-balances: (list 128 { recipient: principal, amount: uint })
    }
    {
        chain-id: u2147483650,   ;; 0x80000002
        start-height: block-height,
        boot-nodes: (list
            {
                ;; private key: 9f1f85a512a96a244e4c0d762788500687feb97481639572e3bffbd6860e6ab001
                public-key: 0x038cc1dc238b5b6f8d0a8b38baf5c52280396f8a209cc4de33caff2daefe756c23, 
                ;; 127.0.0.1:14300
                host: 0x00000000000000000000ffff7f000001,
                port: 0x37dc,
                ;; 127.0.0.1:14301
                data-host: 0x00000000000000000000ffff7f000001,
                data-port: 0x37dd
            }
        ),
        pox: {
            reward-cycle-length: u5,
            prepare-length: u3,
            anchor-threshold: u2,
            pox-rejection-fraction: u25,
            pox-participation-threshold-pct: u5,
            sunset-start: u18446744073709551615,
            sunset-end: u18446744073709551615
        },
        block-limit: {
            write-length: u15000000,
            write-count: u7750,
            read-length: u100000000,
            read-count: u7750,
            runtime: u5000000000
        },
        boot-code: (list
            "hello-world"
        ),
        initial-balances: (list
            {
                ;; private key: 4ad9ee7104e83c17b8c99f32384b61947952434d4c9f2a5185284469719ea61301
                recipient: 'ST310DN3W42RNTYDQBVFYPA1ZBE40ENNG49ZM58X1,
                amount: u1000000000
            }
        )
    }
)

(define-map last-mined-heights
    ;; sender
    principal
    ;; height at which a block-commit was last sent
    uint
)

(define-private (add-nonmining-block-op (payload (buff 80)) (recipients (list 2 principal)))
    (let (
       (op-list (default-to (list ) (map-get? appchain block-height)))
    )
       (asserts! (< (len op-list) u128)
           (err ERR_BLOCK_FULL))

       (map-set appchain block-height 
           (unwrap-panic
               (as-max-len? (append op-list {
                   sender: tx-sender,
                   chained?: true,
                   data: payload,
                   burnt: u0,
                   transferred: u0,
                   recipients: recipients
               })
               u128)
           )
       )
       (print { msg: "Submitted block operation", data: payload, recipients: recipients, block-height: block-height })
       (ok true)
    )
)

;; Register a VRF public key.  The payload key-op is identical to the VRF public key
;; registration that would go into a Bitcoin OP_RETURN.
(define-public (register-vrf-key (key-op (buff 80)))
    (add-nonmining-block-op key-op (list ))
)

(define-private (send-to-recipient (recipient principal) (amount uint))
    (begin
        (unwrap-panic
            (if (not (is-eq tx-sender recipient))
                (stx-transfer? amount tx-sender recipient)
                (ok true)
            )
        )
        amount
    )
)

;; Mine a block -- register a block-commit and pay out to the PoX recipients.
;; The block-op buff is identical to the block-commit data that goes into a Bitcoin OP_RETURN.
;; The to-burn value is the PoX sunset burn to be burnt.
;; The recipients list is the list of PoX payouts, who will receive uSTX.
;; The recipient-amount is the amount of uSTX to be sent to each recipient.
(define-public (mine-block (block-op (buff 80)) (to-burn uint) (recipients (list 2 principal)) (recipient-amount uint))
    (let (
        (op-list (default-to (list ) (map-get? appchain block-height)))
        ;; pessimistic take: consider block-commits chained only if the miner mined in the last two blocks
        (chained? (<= block-height (+ u2 (default-to u0 (map-get? last-mined-heights tx-sender)))))
    )
        (asserts! (> (len recipients) u0)
            (err ERR_NO_RECIPIENTS))

        (asserts! (> recipient-amount u0)
            (err ERR_NO_COMMIT_SPEND))

        (asserts! (>= (stx-get-balance tx-sender) (+ to-burn (* (len recipients) recipient-amount)))
            (err ERR_INSUFFICIENT_BALANCE))
       
        (asserts! (< (len op-list) u128)
            (err ERR_BLOCK_FULL))

        ;; everything from here on out should just work
        
        (if (> to-burn u0)
            (unwrap-panic (stx-burn? to-burn tx-sender))
            true
        )

        (fold send-to-recipient recipients recipient-amount)

        (map-set appchain block-height
            (unwrap-panic
                (as-max-len? (append op-list {
                    sender: tx-sender,
                    chained?: chained?,
                    data: block-op,
                    burnt: to-burn,
                    transferred: (* (len recipients) recipient-amount),
                    recipients: recipients
                })
                u128)
            )
        )
        (map-set last-mined-heights tx-sender block-height)
        (ok true)
    )
)

;; Register a PreSTX operation in order to carry out a STX-transfer or Stack-STX operation on the host chain.
;; The payload argument is identical to the payload that would be sent in a Bitcoin OP_RETURN for PreSTX
(define-public (prestx (payload (buff 80)))
    (add-nonmining-block-op payload (list ))
)

;; Stack tokens on the appchain, bypassing the appchain miners.
;; The stack-pyaload argument is identical to the StackStx Bitcoin OP_RETURN.
;; The pox-addr argument is the address to which uSTX payouts will be sent.
(define-public (stack-appchain-stx (stack-payload (buff 80)) (pox-addr principal))
    (add-nonmining-block-op stack-payload (list pox-addr))
)

;; Transfer tokens on the appchain, bypassing the appchain miners.
;; The transfer-payload argument is identical to the TransferStx Bitcoin OP_RETURN.
;; The recipient argument is the address on the appchain that will receive the tokens.
(define-public (transfer-appchain-stx (transfer-payload (buff 80)) (recipient principal))
    (add-nonmining-block-op transfer-payload (list recipient))
)
"#;

const HELLO_WORLD_CONTRACT: &str = r#"
(print "Hello appchains!")
"#;

#[test]
#[ignore]
fn appchain_integration_test() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let spender_sk = StacksPrivateKey::new();
    let addr = to_addr(&spender_sk);

    let tx = make_contract_publish(
        &spender_sk,
        0,
        10000,
        "appchain-mvp",
        &APPCHAIN_MINING_CONTRACT,
    );

    let (mut conf, miner_account) = neon_integration_test_conf();
    conf.initial_balances.push(InitialBalance {
        address: addr.to_account_principal(),
        amount: 10000000,
    });

    let appchain_miner_sk = StacksPrivateKey::from_hex(SK_1).unwrap();
    let appchain_miner_stx_addr: StacksAddress = to_addr(&appchain_miner_sk);
    let appchain_miner_addr: PrincipalData = appchain_miner_stx_addr.clone().into();

    conf.initial_balances.push(InitialBalance {
        address: appchain_miner_addr.clone(),
        amount: 10000000,
    });

    let prom_bind = format!("{}:{}", "127.0.0.1", 6000);
    conf.node.prometheus_bind = Some(prom_bind.clone());

    let mut btcd_controller = BitcoinCoreController::new(conf.clone());
    btcd_controller
        .start_bitcoind()
        .map_err(|_e| ())
        .expect("Failed starting bitcoind");

    let mut btc_regtest_controller = BitcoinRegtestController::new(conf.clone(), None);
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    btc_regtest_controller.bootstrap_chain(201);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf.clone());
    let blocks_processed = run_loop.get_blocks_processed_arc();

    let channel = run_loop.get_coordinator_channel().unwrap();

    thread::spawn(move || run_loop.start(None, 0));

    // give the run loop some time to start up!
    wait_for_runloop(&blocks_processed);

    // first block wakes up the run loop
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // first block will hold our VRF registration
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // second block will be the first mined Stacks block
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // let's query the miner's account nonce:

    eprintln!("Miner account: {}", miner_account);

    let account = get_account(&http_origin, &miner_account);
    assert_eq!(account.nonce, 1);

    let account = get_account(&http_origin, &addr);
    assert_eq!(account.nonce, 0);
    assert_eq!(account.balance, 10000000);

    eprintln!("Deploying mining contract");
    // deploy the mining contract
    submit_tx(&http_origin, &tx);

    for _i in 0..10 {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
        let account = get_account(&http_origin, &addr);
        if account.nonce == 1 {
            // accepted
            break;
        }
    }

    let account = get_account(&http_origin, &addr);
    assert_eq!(account.nonce, 1, "Did not mine appchain mining contract");

    eprintln!("Mining contract deployed!");

    // one more block so that it confirms
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // boot the appchain
    let contract_id = QualifiedContractIdentifier {
        issuer: StandardPrincipalData(addr.version, addr.bytes.clone().0),
        name: "appchain-mvp".into(),
    };
    let (mut appchain_conf, _) = neon_integration_test_appchain_conf(
        &conf,
        contract_id,
        14300,
        14301,
        &vec![(
            "hello-world".into(),
            StacksString::from_str(HELLO_WORLD_CONTRACT).unwrap(),
        )],
        TrieHash::from_hex("6ecdc6648ae90a729cca36ce7cb13b2e51eb44ccaed8f9305fbed00e8bfb9f61")
            .unwrap(),
    );

    appchain_conf.node.seed = hex_bytes(&SK_1).unwrap();

    let appchain_http_origin = format!("http://{}", appchain_conf.node.rpc_bind);

    let mut appchain_runloop = neon::RunLoop::new(appchain_conf);
    let appchain_blocks_processed = appchain_runloop.get_blocks_processed_arc();

    let appchain_channel = appchain_runloop.get_coordinator_channel().unwrap();

    thread::spawn(move || {
        eprintln!("Start appchain runloop");
        appchain_runloop.start(None, 0)
    });

    // give the appchain run loop some time to start up!
    eprintln!("Booting appchain");
    wait_for_runloop(&appchain_blocks_processed);

    // first appchain block wakes up the run loop
    eprintln!("First appchain block");
    next_appchain_block_and_wait(&appchain_blocks_processed);
    sleep_ms(30_000);

    // first appchain block will hold our VRF registration
    eprintln!("Second burnchain block of appchain block");
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    eprintln!("Second appchain block");
    next_appchain_block_and_wait(&appchain_blocks_processed);
    sleep_ms(30_000);

    // second block will be the first appchain block
    eprintln!("Third burnchain block of appchain block");
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    eprintln!("Third appchain block");
    next_appchain_block_and_wait(&appchain_blocks_processed);

    // there is now an appchain tip
    let client = reqwest::blocking::Client::new();

    eprintln!("Appchain running at {}", &appchain_http_origin);

    let path = format!("{}/v2/info", &appchain_http_origin);
    let tip_info = client
        .get(&path)
        .send()
        .unwrap()
        .json::<RPCPeerInfoData>()
        .unwrap();

    eprintln!("tip: {:?}", &tip_info);
    assert_eq!(tip_info.network_id, 0x80000002);
    assert_eq!(tip_info.parent_network_id, 0x80000000);
    assert_eq!(tip_info.stacks_tip_height, 1);

    // initial account was set up
    let initial_account = get_account(
        &appchain_http_origin,
        &StacksAddress::from_string("ST310DN3W42RNTYDQBVFYPA1ZBE40ENNG49ZM58X1").unwrap(),
    );
    eprintln!("initial account: {:?}", &initial_account);

    assert_eq!(initial_account.nonce, 0);
    assert_eq!(initial_account.balance, 1000000000);

    eprintln!("Booting appchain peer");

    // try booting *another* appchain peer, and see that it syncs up.
    // Note that no boot code is given -- it will be downloaded from the peer appchain node
    let contract_id = QualifiedContractIdentifier {
        issuer: StandardPrincipalData(addr.version, addr.bytes.clone().0),
        name: "appchain-mvp".into(),
    };

    eprintln!("Make appchain peer conf");
    let (appchain_peer_conf, _) = neon_integration_test_appchain_conf(
        &conf,
        contract_id,
        14302,
        14303,
        &vec![],
        TrieHash::from_hex("6ecdc6648ae90a729cca36ce7cb13b2e51eb44ccaed8f9305fbed00e8bfb9f61")
            .unwrap(),
    );

    let appchain_peer_http_origin = format!("http://{}", appchain_peer_conf.node.rpc_bind);

    eprintln!("Make appchain peer runloop");

    let mut appchain_peer_runloop = neon::RunLoop::new(appchain_peer_conf);
    let appchain_peer_blocks_processed = appchain_peer_runloop.get_blocks_processed_arc();
    let appchain_peer_channel = appchain_peer_runloop.get_coordinator_channel().unwrap();

    eprintln!("Make appchain peer thread");

    thread::spawn(move || {
        eprintln!("Start appchain peer runloop");
        warn!("Start appchain peer runloop");
        appchain_peer_runloop.start(None, 0)
    });

    eprintln!("Waiting for appchain peer to sync up");

    wait_for_runloop(&appchain_peer_blocks_processed);

    for _i in 0..300 {
        let path = format!("{}/v2/info", &appchain_peer_http_origin);
        let peer_tip_info = client
            .get(&path)
            .send()
            .unwrap()
            .json::<RPCPeerInfoData>()
            .unwrap();

        eprintln!("appchain peer_tip: {:?}", &peer_tip_info);
        assert_eq!(peer_tip_info.network_id, 0x80000002);
        assert_eq!(peer_tip_info.parent_network_id, 0x80000000);

        if peer_tip_info.stacks_tip_height < 1 {
            sleep_ms(1000);
            continue;
        }

        assert_eq!(peer_tip_info.stacks_tip_height, 1);
        assert_eq!(peer_tip_info, tip_info);
        break;
    }

    eprintln!("Test complete! Shutting down");

    test_observer::clear();

    appchain_peer_channel.stop_chains_coordinator();
    appchain_channel.stop_chains_coordinator();
    channel.stop_chains_coordinator();
}

#[test]
#[ignore]
fn appchain_forking_integration_test() {
    // make the underlying stacks chain fork
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let spender_sk = StacksPrivateKey::new();
    let addr = to_addr(&spender_sk);

    let tx = make_contract_publish(
        &spender_sk,
        0,
        10000,
        "appchain-mvp",
        &APPCHAIN_MINING_CONTRACT,
    );

    let (mut conf, miner_account) = neon_integration_test_conf();
    conf.initial_balances.push(InitialBalance {
        address: addr.to_account_principal(),
        amount: 10000000,
    });

    let appchain_miner_sk = StacksPrivateKey::from_hex(SK_1).unwrap();
    let appchain_miner_stx_addr: StacksAddress = to_addr(&appchain_miner_sk);
    let appchain_miner_addr: PrincipalData = appchain_miner_stx_addr.clone().into();

    conf.initial_balances.push(InitialBalance {
        address: appchain_miner_addr.clone(),
        amount: 10000000,
    });

    let prom_bind = format!("{}:{}", "127.0.0.1", 6000);
    conf.node.prometheus_bind = Some(prom_bind.clone());

    let mut btcd_controller = BitcoinCoreController::new(conf.clone());
    btcd_controller
        .start_bitcoind()
        .map_err(|_e| ())
        .expect("Failed starting bitcoind");

    let mut btc_regtest_controller = BitcoinRegtestController::new(conf.clone(), None);
    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    btc_regtest_controller.bootstrap_chain(201);

    eprintln!("Chain bootstrapped...");

    let mut run_loop = neon::RunLoop::new(conf.clone());
    let blocks_processed = run_loop.get_blocks_processed_arc();

    let channel = run_loop.get_coordinator_channel().unwrap();

    thread::spawn(move || run_loop.start(None, 0));

    // give the run loop some time to start up!
    wait_for_runloop(&blocks_processed);

    // first block wakes up the run loop
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // first block will hold our VRF registration
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // second block will be the first mined Stacks block
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // let's query the miner's account nonce:

    eprintln!("Miner account: {}", miner_account);

    let account = get_account(&http_origin, &miner_account);
    assert_eq!(account.nonce, 1);

    let account = get_account(&http_origin, &addr);
    assert_eq!(account.nonce, 0);
    assert_eq!(account.balance, 10000000);

    eprintln!("Deploying mining contract");
    // deploy the mining contract
    submit_tx(&http_origin, &tx);

    for _i in 0..10 {
        next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
        let account = get_account(&http_origin, &addr);
        if account.nonce == 1 {
            // accepted
            break;
        }
    }

    let account = get_account(&http_origin, &addr);
    assert_eq!(account.nonce, 1, "Did not mine appchain mining contract");

    eprintln!("Mining contract deployed!");

    // one more block so that it confirms
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    // boot the appchain
    let contract_id = QualifiedContractIdentifier {
        issuer: StandardPrincipalData(addr.version, addr.bytes.clone().0),
        name: "appchain-mvp".into(),
    };
    let (mut appchain_conf, _appchain_miner_account) = neon_integration_test_appchain_conf(
        &conf,
        contract_id,
        14300,
        14301,
        &vec![(
            "hello-world".into(),
            StacksString::from_str(HELLO_WORLD_CONTRACT).unwrap(),
        )],
        TrieHash([0u8; 32]),
    );

    appchain_conf.node.seed = hex_bytes(&SK_1).unwrap();

    let appchain_http_origin = format!("http://{}", appchain_conf.node.rpc_bind);

    // make the appchain mine all the time
    appchain_conf.miner.first_attempt_time_ms = 100;
    appchain_conf.miner.subsequent_attempt_time_ms = 100;

    let mut appchain_runloop = neon::RunLoop::new(appchain_conf);
    let appchain_blocks_processed = appchain_runloop.get_blocks_processed_arc();

    let appchain_channel = appchain_runloop.get_coordinator_channel().unwrap();

    thread::spawn(move || {
        eprintln!("Start appchain runloop");
        appchain_runloop.start(None, 0)
    });

    // give the appchain run loop some time to start up!
    eprintln!("Booting appchain");
    wait_for_runloop(&appchain_blocks_processed);

    // first appchain block wakes up the run loop
    eprintln!("Appchain key registration block");
    next_appchain_block_and_wait(&appchain_blocks_processed);
    sleep_ms(30_000);

    // first appchain burn block will hold our VRF registration
    eprintln!("Second burnchain block of appchain block");
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    eprintln!("First appchain block");
    next_appchain_block_and_wait(&appchain_blocks_processed);
    sleep_ms(30_000);

    // get the canonical chain tip so we can reorg it later
    let client = reqwest::blocking::Client::new();
    let path = format!("{}/v2/info", &http_origin);
    let reorg_tip_info = client
        .get(&path)
        .send()
        .unwrap()
        .json::<RPCPeerInfoData>()
        .unwrap();

    // third burnchain block will be the first appchain block
    eprintln!("Third burnchain block of appchain block");
    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);
    eprintln!("Second appchain block");
    next_appchain_block_and_wait(&appchain_blocks_processed);
    sleep_ms(30_000);

    // there is now an appchain tip
    eprintln!("Appchain running at {}", &appchain_http_origin);

    let path = format!("{}/v2/info", &appchain_http_origin);
    let tip_info = client
        .get(&path)
        .send()
        .unwrap()
        .json::<RPCPeerInfoData>()
        .unwrap();

    eprintln!("appchain tip: {:?}", &tip_info);
    assert_eq!(tip_info.network_id, 0x80000002);
    assert_eq!(tip_info.parent_network_id, 0x80000000);
    assert_eq!(tip_info.stacks_tip_height, 1);

    // initial account was set up
    let initial_account = get_account(
        &appchain_http_origin,
        &StacksAddress::from_string("ST310DN3W42RNTYDQBVFYPA1ZBE40ENNG49ZM58X1").unwrap(),
    );
    eprintln!("initial account: {:?}", &initial_account);

    assert_eq!(initial_account.nonce, 0);
    assert_eq!(initial_account.balance, 1000000000);

    eprintln!("Begin reorg test");

    // get the canonical chain tip
    let path = format!("{}/v2/info", &http_origin);
    let tip_info = client
        .get(&path)
        .send()
        .unwrap()
        .json::<RPCPeerInfoData>()
        .unwrap();

    // force the stacks burnchain to reorg
    eprintln!(
        "Set initial miner environment for {}: {}/{}",
        tip_info.burn_block_height + 1,
        &reorg_tip_info.stacks_tip_consensus_hash,
        &reorg_tip_info.stacks_tip
    );
    std::env::set_var(
        format!(
            "STX_MINER_CONSENSUS_HASH_{}",
            tip_info.burn_block_height + 1
        ),
        format!("{}", &reorg_tip_info.stacks_tip_consensus_hash),
    );
    std::env::set_var(
        format!("STX_MINER_BLOCK_HASH_{}", tip_info.burn_block_height + 1),
        format!("{}", &reorg_tip_info.stacks_tip),
    );

    for i in 0..20 {
        eprintln!("Burnchain block {} of appchain block", i + 3);
        btc_regtest_controller.build_next_block(1);
        sleep_ms(10_000);

        let path = format!("{}/v2/info", &http_origin);
        let tip_info = client
            .get(&path)
            .send()
            .unwrap()
            .json::<RPCPeerInfoData>()
            .unwrap();

        let target_burn_height = if i % 5 == 0 {
            tip_info.burn_block_height - 2
        } else {
            tip_info.burn_block_height
        };

        let (ch, bhh) =
            get_last_stacks_block_mined_at_bitcoin_block_height(&conf, target_burn_height);

        // force the stacks burnchain to continue the reorg
        eprintln!(
            "Set miner environment at {} for {}: {}/{}",
            tip_info.burn_block_height + 1,
            target_burn_height,
            &ch,
            &bhh
        );
        std::env::set_var(
            format!(
                "STX_MINER_CONSENSUS_HASH_{}",
                tip_info.burn_block_height + 1
            ),
            format!("{}", &ch),
        );
        std::env::set_var(
            format!("STX_MINER_BLOCK_HASH_{}", tip_info.burn_block_height + 1),
            format!("{}", &bhh),
        );

        let appchain_path = format!("{}/v2/info", &appchain_http_origin);
        let appchain_tip_info = client
            .get(&appchain_path)
            .send()
            .unwrap()
            .json::<RPCPeerInfoData>()
            .unwrap();

        eprintln!("stacks tip for appchain is {:?}", &tip_info);
        eprintln!("appchain tip is {:?}", &appchain_tip_info);
    }

    for _i in 0..10 {
        let path = format!("{}/v2/info", &http_origin);
        let tip_info = client
            .get(&path)
            .send()
            .unwrap()
            .json::<RPCPeerInfoData>()
            .unwrap();

        // mine linearly
        eprintln!(
            "Burnchain block {} of appchain block",
            tip_info.burn_block_height
        );
        btc_regtest_controller.build_next_block(1);
        sleep_ms(10_000);
    }

    let path = format!("{}/v2/info", &appchain_http_origin);
    let tip_info = client
        .get(&path)
        .send()
        .unwrap()
        .json::<RPCPeerInfoData>()
        .unwrap();

    eprintln!("Final appchain tip is {:?}", &tip_info);
    assert!(tip_info.stacks_height >= 9);

    test_observer::clear();

    appchain_channel.stop_chains_coordinator();
    channel.stop_chains_coordinator();
}
