use crate::ChainTip;
use async_std::net::TcpListener;
use async_std::stream::StreamExt;
use async_std::task::block_on;
use http_types::mime::JSON;
use http_types::{Method, Response, StatusCode};
use std::io;
use std::io::{Error, Write};
use std::ops::{Add, DerefMut};
use std::sync::{Arc, Mutex};
use std::thread::{sleep, Builder, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct PuppetControl {
    pub current_block: u64,
    pub target_block: u64,
    pub next_block_time: SystemTime,
    pub block_interval: Duration,
}

impl Default for PuppetControl {
    fn default() -> Self {
        let default_interval = Duration::from_secs(600);
        Self {
            current_block: 0,
            target_block: 1,
            next_block_time: SystemTime::now().add(default_interval),
            block_interval: default_interval,
        }
    }
}

pub struct PuppetController {
    inner: Arc<Mutex<PuppetControl>>,
    bind_addr: String,
    join_handle: Option<JoinHandle<Result<(), Error>>>,
}

impl PuppetController {
    pub fn new(bind_addr: &str) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PuppetControl::default())),
            bind_addr: bind_addr.to_string(),
            join_handle: None,
        }
    }

    pub fn start(&mut self) {
        if self.join_handle.is_some() {
            warn!("Puppet mode control server is already started");
            return;
        }
        info!("Starting puppet mode control server..");
        let puppet_control = Arc::clone(&self.inner);
        let puppet_bind = self.bind_addr.to_string();
        self.join_handle = Some(
            Builder::new()
                .name("puppet".into())
                .spawn(move || {
                    block_on(async {
                        let listener = TcpListener::bind(puppet_bind).await?;
                        info!(
                            "Start puppet mode control server on: {}",
                            listener.local_addr()?
                        );

                        // For each incoming TCP connection, spawn a task and call `accept`.
                        let mut incoming = listener.incoming();
                        while let Some(stream) = incoming.next().await {
                            if stream.is_err() {
                                return Err(stream.unwrap_err());
                            }
                            let stream = stream?;
                            async_h1::accept(stream.clone(), |req| async {
                                let mut req = req;
                                match (req.method(), req.url().path()) {
                                    (Method::Get, "/") => Ok(Response::new(StatusCode::Ok)),
                                    (Method::Post, "/puppet/v1/kick") => {
                                        let mut puppet_control = puppet_control.lock().unwrap();
                                        if puppet_control.target_block <= puppet_control.current_block {
                                            puppet_control.target_block =
                                                puppet_control.current_block + 1;
                                        }
                                        Ok(Response::new(StatusCode::Ok))
                                    }
                                    (Method::Put, "/puppet/v1/duration") => {
                                        let body = req.body_string().await;
                                        match body {
                                            Ok(x) => {
                                                let v = x.parse::<u64>().unwrap_or(0);
                                                if v > 0 {
                                                    println!("Setting duration to {}", v);
                                                    io::stdout().flush().unwrap();
                                                    let mut puppet_control =
                                                        puppet_control.lock().unwrap();
                                                    puppet_control.block_interval =
                                                        Duration::from_secs(v);
                                                    puppet_control.next_block_time =
                                                        SystemTime::now()
                                                            .add(puppet_control.block_interval);
                                                }
                                            }
                                            _ => (),
                                        }
                                        Ok(Response::new(StatusCode::Ok))
                                    }
                                    (Method::Put, "/puppet/v1/until") => {
                                        let body = req.body_string().await;
                                        match body {
                                            Ok(x) => {
                                                let v = x.parse::<u64>().unwrap_or(0);
                                                if v > 0 {
                                                    let mut puppet_control =
                                                        puppet_control.lock().unwrap();
                                                    puppet_control.target_block = if puppet_control.current_block >= v {
                                                        puppet_control.current_block
                                                    } else {
                                                        v
                                                    };
                                                    println!("Setting target block to {}", puppet_control.target_block);
                                                    io::stdout().flush().unwrap();
                                                }
                                            }
                                            _ => (),
                                        }
                                        Ok(Response::new(StatusCode::Ok))
                                    }
                                    (Method::Get, "/puppet/v1/status") => {
                                        let mut response = Response::new(StatusCode::Ok);
                                        let puppet_control = puppet_control.lock().unwrap();
                                        response.set_content_type(JSON);
                                        response.set_body(
                                          format!(
                                            "{{\"current_block\":{},\"target_block\":{},\"duration\":{},\"next_block_time\":{}}}",
                                            puppet_control.current_block,
                                            puppet_control.target_block,
                                            puppet_control.block_interval.as_secs(),
                                            puppet_control.next_block_time.duration_since(UNIX_EPOCH).unwrap().as_secs()));
                                        Ok(response)
                                    }
                                    _ => {
                                        let mut rs = Response::new(StatusCode::BadRequest);
                                        rs.set_body(format!(
                                            "[{}] {}",
                                            req.method(),
                                            req.url().path()
                                        ));
                                        Ok(rs)
                                    }
                                }
                            })
                            .await
                            .unwrap_or(())
                        }
                        Ok(())
                    })
                })
                .unwrap(),
        )
    }

    fn with_lock<F, R>(&self, func: F) -> R
    where
        F: FnOnce(&mut PuppetControl) -> R,
    {
        let mut puppet_control = self.inner.lock().unwrap();
        func(puppet_control.deref_mut())
    }

    pub fn block_on(&self, chain_tip: &ChainTip) {
        if self.join_handle.is_none() {
            return;
        }
        info!(
            "Waiting on block height {}",
            chain_tip.metadata.stacks_block_height
        );

        self.with_lock(|puppet_control| {
            puppet_control.current_block = chain_tip.metadata.stacks_block_height;
        });
        loop {
            let should_break = self.with_lock(|puppet_control| {
                if puppet_control.target_block > puppet_control.current_block
                    || puppet_control.next_block_time.le(&SystemTime::now())
                {
                    puppet_control.next_block_time =
                        SystemTime::now().add(puppet_control.block_interval);
                    return true;
                }
                false
            });
            if should_break {
                break;
            }
            sleep(Duration::from_millis(100));
        }
    }
}
