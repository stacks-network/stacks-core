#[macro_use]
extern crate serde_derive;

use std::collections::VecDeque;
use std::env;
use std::fs::File;
use std::io::{BufReader, Read};
use std::sync::{Arc, Mutex};
use std::thread::{self, sleep};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use async_h1::client;
use async_std::net::{TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use base64::encode;
use http_types::{headers, Method, Request, Response, StatusCode, Url};
use serde::Deserialize;
use serde_json::Deserializer;
use toml;

use rand::{thread_rng, Rng};

#[async_std::main]
async fn main() -> http_types::Result<()> {
    let argv: Vec<String> = env::args().collect();

    // Guard: config missing
    if argv.len() != 2 {
        panic!("Config argument missing");
    }

    // Generating block
    // Baseline: 150 for miner, 150 for faucet
    let config = ConfigFile::from_path(&argv[1]);
    let block_time = Duration::from_millis(config.network.block_time);
    let mut num_blocks = 0;

    if is_chain_bootstrap_required(&config).await? {
        println!("Bootstrapping chain");

        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(dur) => dur,
            Err(err) => err.duration(),
        }
        .as_secs() as u64;

        let genesis_timestamp = if env::var("DYNAMIC_GENESIS_TIMESTAMP") == Ok("1".into()) {
            println!(
                "INFO: detected DYNAMIC_GENESIS_TIMESTAMP, will set the genesis timestamp to {}",
                now
            );
            now.clone()
        } else {
            match std::env::var("STATIC_GENESIS_TIMESTAMP") {
                Ok(val) => match val.parse::<u64>() {
                    Ok(val) => val,
                    Err(err) => {
                        println!("WARN: parsing STATIC_GENESIS_TIMESTAMP failed ({:?}), falling back on {}", err, config.network.genesis_timestamp);
                        config.network.genesis_timestamp
                    }
                },
                _ => config.network.genesis_timestamp,
            }
        };

        let time_since_genesis = now - genesis_timestamp;

        // If the testnet crashed, we need to generate a chain that would be
        // longer that the previous chain.
        let num_blocks_required = time_since_genesis / block_time.as_secs();
        let num_blocks_for_miner = 150 + num_blocks_required;
        let num_blocks_for_faucet = 150;

        // Generate blocks for the network faucet
        let faucet_address = config.network.faucet_address.clone();
        generate_blocks(num_blocks_for_faucet, faucet_address, &config).await;

        // Generate blocks for the network miner
        let miner_address = config.network.miner_address.clone();
        generate_blocks(num_blocks_for_miner, miner_address, &config).await;

        num_blocks = num_blocks_for_miner + num_blocks_for_faucet;

        // By blocking here, we ensure that the http server does not start
        // serving requests with a bitcoin chain still being constructed.
        while is_chain_bootstrap_required(&config).await? {
            println!("Waiting on initial blocks to be available");
            let backoff = Duration::from_millis(1_000);
            sleep(backoff)
        }
    }

    // Start a loop in a separate thread, generating new blocks
    // on a given frequence (coming from config).
    let boot_height = num_blocks;
    let block_height_reader = Arc::new(Mutex::new(num_blocks));
    let block_height_writer = block_height_reader.clone();
    let conf = config.clone();
    thread::spawn(move || {
        let miner_address = conf.network.miner_address.clone();

        loop {
            let delay = {
                let mut block_height = block_height_writer.lock().unwrap();
                let effective_height = *block_height - num_blocks;
                *block_height += 1;
                let block_time = conf.get_block_time_at_height(effective_height);
                let will_ignore = conf.should_ignore_transactions(effective_height);
                let behavior = if will_ignore {
                    "buffering"
                } else {
                    "accepting"
                };
                println!(
                    "Assembled block {}. Will be {} incoming transactions for the next {}ms, then assemble block {}.",
                    *block_height, behavior, block_time, *block_height + 1
                );
                block_time
            };
            async_std::task::block_on(async {
                generate_blocks(1, miner_address.clone(), &conf).await;
            });

            thread::sleep(Duration::from_millis(delay));
        }
    });

    // Open up a TCP connection and create a URL.
    let bind_addr = config.network.rpc_bind.clone();
    let listener = TcpListener::bind(bind_addr).await?;
    let addr = format!("http://{}", listener.local_addr()?);
    println!("Listening on {}", addr);

    // For each incoming TCP connection, spawn a task and call `accept`.
    let mut incoming = listener.incoming();
    let mut buffered_requests = VecDeque::new();
    while let Some(stream) = incoming.next().await {
        let block_height = block_height_reader.lock().unwrap();
        let effective_block_height = *block_height - boot_height;
        let should_ignore_txs = config.should_ignore_transactions(effective_block_height - 1);

        let stream = stream?;

        if should_ignore_txs {
            // Returns ok
            println!("Buffering request from {}", stream.peer_addr()?);
            async_h1::accept(stream.clone(), |_| async {
                Ok(Response::new(StatusCode::Ok))
            })
            .await?;
            // Enqueue request
            buffered_requests.push_back(stream);
        } else {
            // Dequeue all the requests we've been buffering
            while let Some(stream) = buffered_requests.pop_front() {
                let config = config.clone();
                task::spawn(async move {
                    println!(
                        "Dequeuing buffered request from {}",
                        stream.peer_addr().unwrap()
                    );
                    if let Err(err) = accept(stream, &config).await {
                        eprintln!("{}", err);
                    }
                });
            }
            // Then handle the request
            let config = config.clone();
            task::spawn(async move {
                println!("Handling request from {}", stream.peer_addr().unwrap());
                if let Err(err) = accept(stream, &config).await {
                    eprintln!("{}", err);
                }
            });
        }
    }
    Ok(())
}

// Take a TCP stream, and convert it into sequential HTTP request / response pairs.
async fn accept(stream: TcpStream, config: &ConfigFile) -> http_types::Result<()> {
    async_h1::accept(stream.clone(), |mut req| async {
        match (
            req.method(),
            req.url().path(),
            req.header(&headers::CONTENT_TYPE),
        ) {
            (Method::Get, "/ping", Some(_content_type)) => Ok(Response::new(StatusCode::Ok)),
            (Method::Post, "/", Some(_content_types)) => {
                let (res, buffer) = async_std::task::block_on(async move {
                    let mut buffer = Vec::new();
                    let mut body = req.take_body();
                    let res = body.read_to_end(&mut buffer).await;
                    (res, buffer)
                });

                // Guard: can't be read
                if res.is_err() {
                    return Ok(Response::new(StatusCode::MethodNotAllowed));
                }

                let mut deserializer = Deserializer::from_slice(&buffer);

                // Guard: can't be parsed
                let rpc_req: RPCRequest = match RPCRequest::deserialize(&mut deserializer) {
                    Ok(rpc_req) => rpc_req,
                    _ => return Ok(Response::new(StatusCode::MethodNotAllowed)),
                };

                println!("{:?}", rpc_req);

                let authorized_methods = &config.network.whitelisted_rpc_calls;

                // Guard: unauthorized method
                if !authorized_methods.contains(&rpc_req.method) {
                    return Ok(Response::new(StatusCode::MethodNotAllowed));
                }

                // Forward the request
                let stream = TcpStream::connect(config.network.bitcoind_rpc_host.clone()).await?;
                let body = serde_json::to_vec(&rpc_req).unwrap();
                let req = build_request(&config, body);
                let response = match client::connect(stream.clone(), req).await {
                    Ok(ref mut res) => {
                        let mut response = Response::new(res.status());
                        let _ = response.append_header("Content-Type", "application/json");
                        response.set_body(res.take_body());
                        response
                    }
                    Err(err) => {
                        println!("Unable to reach host: {:?}", err);
                        return Ok(Response::new(StatusCode::MethodNotAllowed));
                    }
                };
                Ok(response)
            }
            _ => Ok(Response::new(StatusCode::MethodNotAllowed)),
        }
    })
    .await?;

    Ok(())
}

async fn is_chain_bootstrap_required(config: &ConfigFile) -> http_types::Result<bool> {
    let req = RPCRequest::is_chain_bootstrapped();

    let mut backoff: f64 = 1.0;
    let mut rng = thread_rng();
    let mut resp = loop {
        backoff = (2.0 * backoff + (backoff * rng.gen_range(0.0, 1.0))).min(60.0);
        let duration = Duration::from_millis((backoff * 1_000.0) as u64);

        let stream = match TcpStream::connect(config.network.bitcoind_rpc_host.clone()).await {
            Ok(stream) => stream,
            Err(e) => {
                println!(
                    "Error while trying to connect to {}: {:?}",
                    config.network.bitcoind_rpc_host, e
                );
                sleep(duration);
                continue;
            }
        };

        let body = serde_json::to_vec(&req).unwrap();
        let response = client::connect(stream, build_request(&config, body)).await;

        match response {
            Ok(response) => {
                break response;
            }
            Err(e) => {
                println!("Error: {:?}", e);
                sleep(duration);
            }
        };
    };

    let (res, buffer) = async_std::task::block_on(async move {
        let mut buffer = Vec::new();
        let mut body = resp.take_body();
        let res = body.read_to_end(&mut buffer).await;
        (res, buffer)
    });

    // Guard: can't be read
    if res.is_err() {
        panic!("Chain height could not be determined")
    }
    // let mut deserializer = Deserializer::from_slice(&buffer);

    let mut deserializer = Deserializer::from_slice(&buffer);

    // Guard: can't be parsed
    let rpc_resp: RPCResult = match RPCResult::deserialize(&mut deserializer) {
        Ok(rpc_req) => rpc_req,
        _ => panic!("Chain height could not be determined"),
    };

    match (rpc_resp.result, rpc_resp.error) {
        (Some(_), None) => return Ok(false),
        (None, Some(error)) => {
            if let Some(keys) = error.as_object() {
                if let Some(message) = keys.get("message") {
                    if let Some(message) = message.as_str() {
                        if message == "Block height out of range" {
                            return Ok(true);
                        }
                    }
                }
            }
        }
        (_, _) => {}
    }

    panic!("Chain height could not be determined")
}

async fn generate_blocks(blocks_count: u64, address: String, config: &ConfigFile) {
    let rpc_addr = config.network.bitcoind_rpc_host.clone();

    let rpc_req = RPCRequest::generate_next_block_req(blocks_count, address);

    let stream = match TcpStream::connect(rpc_addr).await {
        Ok(stream) => stream,
        Err(err) => {
            println!("ERROR: connection failed  - {:?}", err);
            return;
        }
    };
    let body = match serde_json::to_vec(&rpc_req) {
        Ok(body) => body,
        Err(err) => {
            println!("ERROR: serialization failed  - {:?}", err);
            return;
        }
    };
    let req = build_request(&config, body);
    match client::connect(stream.clone(), req).await {
        Ok(_) => {}
        Err(err) => {
            println!("ERROR: rpc invokation failed  - {:?}", err);
            return;
        }
    };
}

fn build_request(config: &ConfigFile, body: Vec<u8>) -> Request {
    let url = Url::parse(&format!("http://{}/", config.network.bitcoind_rpc_host)).unwrap();
    let mut req = Request::new(Method::Post, url);
    req.append_header("Authorization", config.network.authorization_token());
    req.append_header("Content-Type", "application/json");
    req.append_header("Host", format!("{}", config.network.bitcoind_rpc_host));
    req.set_body(body);
    req
}

#[derive(Debug, Clone, Deserialize, Serialize)]
/// JSONRPC Request
pub struct RPCRequest {
    /// The name of the RPC call
    pub method: String,
    /// Parameters to the RPC call
    pub params: serde_json::Value,
    /// Identifier for this Request, which should appear in the response
    pub id: serde_json::Value,
    /// jsonrpc field, MUST be "2.0"
    pub jsonrpc: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RPCResult {
    /// The error returned by the RPC call
    pub error: Option<serde_json::Value>,
    /// The value returned by the RPC call
    pub result: Option<serde_json::Value>,
}

impl RPCRequest {
    pub fn generate_next_block_req(blocks_count: u64, address: String) -> RPCRequest {
        RPCRequest {
            method: "generatetoaddress".to_string(),
            params: serde_json::Value::Array(vec![blocks_count.into(), address.into()]),
            id: 0.into(),
            jsonrpc: "2.0".to_string().into(),
        }
    }

    pub fn is_chain_bootstrapped() -> RPCRequest {
        RPCRequest {
            method: "getblockhash".to_string(),
            params: serde_json::Value::Array(vec![200.into()]),
            id: 0.into(),
            jsonrpc: "2.0".to_string().into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigFile {
    /// Regtest node
    network: NetworkConfig,
    /// List of blocks config
    blocks: Vec<BlocksRangeConfig>,
}

impl ConfigFile {
    pub fn from_path(path: &str) -> ConfigFile {
        let path = File::open(path).unwrap();
        let mut config_reader = BufReader::new(path);
        let mut config = vec![];
        config_reader.read_to_end(&mut config).unwrap();
        toml::from_slice(&config[..]).unwrap()
    }

    pub fn should_ignore_transactions(&self, block_height: u64) -> bool {
        match self.get_blocks_config_at_height(block_height) {
            Some(conf) => conf.ignore_txs,
            None => false,
        }
    }

    pub fn get_block_time_at_height(&self, block_height: u64) -> u64 {
        match self.get_blocks_config_at_height(block_height) {
            Some(conf) => conf.block_time,
            None => self.network.block_time,
        }
    }

    pub fn get_blocks_config_at_height(&self, block_height: u64) -> Option<&BlocksRangeConfig> {
        if self.blocks.len() == 0 {
            return None;
        }

        let mut cursor = 0;
        for block in self.blocks.iter() {
            if block_height >= cursor && block_height < (cursor + block.count) {
                return Some(block);
            }
            cursor += block.count;
        }
        return None;
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkConfig {
    /// Proxy's port
    rpc_bind: String,
    /// Duration between blocks
    block_time: u64,
    /// Address receiving coinbases and mining fee
    miner_address: String,
    /// Address receiving coinbases and mining fee
    faucet_address: String,
    /// RPC address used by bitcoind
    bitcoind_rpc_host: String,
    /// Credential - username
    bitcoind_rpc_user: String,
    /// Credential - password
    bitcoind_rpc_pass: String,
    /// Used for deducting the right amount of blocks
    genesis_timestamp: u64,
    /// List of whitelisted RPC calls
    whitelisted_rpc_calls: Vec<String>,
}

impl NetworkConfig {
    pub fn authorization_token(&self) -> String {
        let token = encode(format!(
            "{}:{}",
            self.bitcoind_rpc_user, self.bitcoind_rpc_pass
        ));
        format!("Basic {}", token)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlocksRangeConfig {
    /// Number of blocks to mine
    count: u64,
    /// Delay between blocks
    block_time: u64,
    /// Should transaction be included in next block
    ignore_txs: bool,
}
