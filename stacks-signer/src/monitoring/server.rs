// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::net::SocketAddr;
use std::time::Instant;

use clarity::util::hash::to_hex;
use clarity::util::secp256k1::Secp256k1PublicKey;
use slog::{slog_debug, slog_error, slog_info, slog_warn};
use stacks_common::{debug, error, info, warn};
use tiny_http::{Response as HttpResponse, Server as HttpServer};

use super::{update_reward_cycle, update_signer_stx_balance};
use crate::client::{ClientError, StacksClient};
use crate::config::{GlobalConfig, Network};
use crate::monitoring::prometheus::gather_metrics_string;
use crate::monitoring::{update_signer_nonce, update_stacks_tip_height};

#[derive(Debug)]
/// Monitoring server errors
pub enum MonitoringError {
    /// Already bound to an address
    AlreadyBound,
    /// Server terminated
    Terminated,
    /// No endpoint configured
    EndpointNotConfigured,
    /// Error fetching metrics from stacks node
    FetchError(ClientError),
}

/// Metrics and monitoring server
pub struct MonitoringServer {
    http_server: HttpServer,
    local_addr: SocketAddr,
    stacks_client: StacksClient,
    last_metrics_poll: Instant,
    network: Network,
    public_key: Secp256k1PublicKey,
}

impl MonitoringServer {
    pub fn new(
        http_server: HttpServer,
        local_addr: SocketAddr,
        stacks_client: StacksClient,
        network: Network,
        public_key: Secp256k1PublicKey,
    ) -> Self {
        Self {
            http_server,
            local_addr,
            stacks_client,
            last_metrics_poll: Instant::now(),
            network,
            public_key,
        }
    }

    /// Start and run the metrics server
    pub fn start(config: &GlobalConfig) -> Result<(), MonitoringError> {
        let Some(endpoint) = config.metrics_endpoint else {
            return Err(MonitoringError::EndpointNotConfigured);
        };
        let stacks_client = StacksClient::from(config);
        let http_server = HttpServer::http(endpoint).map_err(|_| MonitoringError::AlreadyBound)?;
        let public_key = Secp256k1PublicKey::from_private(&config.stacks_private_key);
        let mut server = MonitoringServer::new(
            http_server,
            endpoint,
            stacks_client,
            config.network.clone(),
            public_key,
        );
        server.update_metrics()?;
        server.main_loop()
    }

    // /// Start and run the metrics server
    // pub fn run(endpoint: SocketAddr, stacks_client: StacksClient) -> Result<(), MonitoringError> {
    //     let http_server = HttpServer::http(endpoint).map_err(|_| MonitoringError::AlreadyBound)?;
    //     let mut server = PrometheusMetrics::new(http_server, endpoint, stacks_client);
    //     server.main_loop()
    // }

    /// Main listener loop of metrics server
    pub fn main_loop(&mut self) -> Result<(), MonitoringError> {
        info!("{}: Starting Prometheus metrics server", self);
        loop {
            if let Err(err) = self.refresh_metrics() {
                error!("Monitoring: Error refreshing metrics: {:?}", err);
            }
            let request = match self.http_server.recv() {
                Ok(request) => request,
                Err(err) => {
                    error!("Monitoring: Error receiving request: {:?}", err);
                    return Err(MonitoringError::Terminated);
                }
            };

            debug!("{}: received request {}", self, request.url());

            if request.url() == "/metrics" {
                let response = HttpResponse::from_string(gather_metrics_string());
                request.respond(response).expect("Failed to send response");
                continue;
            }

            // unknown request, return 200 ok
            request
                .respond(HttpResponse::from_string(self.get_info_response()))
                .expect("Failed to respond to request");
        }
    }

    /// Check to see if metrics need to be refreshed
    fn refresh_metrics(&mut self) -> Result<(), MonitoringError> {
        let now = Instant::now();
        if now.duration_since(self.last_metrics_poll).as_secs() > 60 {
            self.last_metrics_poll = now;
            self.update_metrics()?;
        }
        Ok(())
    }

    /// Update metrics by making RPC calls to the Stacks node
    fn update_metrics(&self) -> Result<(), MonitoringError> {
        debug!("{}: Updating metrics", self);
        let peer_info = self
            .stacks_client
            .get_peer_info()
            .map_err(|e| MonitoringError::FetchError(e))?;
        if let Ok(height) = i64::try_from(peer_info.stacks_tip_height) {
            update_stacks_tip_height(height);
        } else {
            warn!(
                "Failed to parse stacks tip height: {}",
                peer_info.stacks_tip_height
            );
        }
        let pox_info = self
            .stacks_client
            .get_pox_data()
            .map_err(|e| MonitoringError::FetchError(e))?;
        if let Ok(reward_cycle) = i64::try_from(pox_info.reward_cycle_id) {
            update_reward_cycle(reward_cycle);
        }
        let signer_stx_addr = self.stacks_client.get_signer_address();
        let account_entry = self
            .stacks_client
            .get_account_entry(&signer_stx_addr)
            .map_err(|e| MonitoringError::FetchError(e))?;
        let balance = i64::from_str_radix(&account_entry.balance[2..], 16).map_err(|e| {
            MonitoringError::FetchError(ClientError::MalformedClarityValue(format!(
                "Failed to parse balance: {} with err: {}",
                &account_entry.balance, e,
            )))
        })?;
        if let Ok(nonce) = u64::try_from(account_entry.nonce) {
            update_signer_nonce(nonce);
        } else {
            warn!("Failed to parse nonce: {}", account_entry.nonce);
        }
        update_signer_stx_balance(balance);
        Ok(())
    }

    /// Build a JSON response for non-metrics requests
    fn get_info_response(&self) -> String {
        // let public_key = Secp256k1PublicKey::from_private(&self.stacks_client.publ);
        serde_json::to_string(&serde_json::json!({
            "signerPublicKey": to_hex(&self.public_key.to_bytes_compressed()),
            "network": self.network.to_string(),
            "stxAddress": self.stacks_client.get_signer_address().to_string(),
        }))
        .expect("Failed to serialize JSON")
    }
}

impl std::fmt::Display for MonitoringServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signer monitoring server ({})", self.local_addr)
    }
}
