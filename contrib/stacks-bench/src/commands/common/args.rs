// Copyright (C) 2025-2026 Stacks Open Internet Foundation
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

use std::fmt::{LowerHex, UpperHex};
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use clarity::vm::representations::{ClarityName, ContractName};
use serde::{Deserialize, Serialize};
use stacks_bench::{Network, StacksBlockRef};
use stacks_common::types::Address;
use stacks_common::types::chainstate::StacksAddress;

pub trait IndexerArgs {
    fn start_at(&self) -> Option<&StacksBlockRef>;
    fn end_at(&self) -> Option<&StacksBlockRef>;
    fn block_count(&self) -> Option<u32>;
    fn tip(&self) -> Option<&StacksBlockRef>;
    fn network(&self) -> Option<Network>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxIdArg([u8; 32]);

impl FromStr for TxIdArg {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).with_context(|| format!("invalid hex in txid '{s}'"))?;
        if bytes.len() != 32 {
            bail!(
                "invalid txid length: expected 32 bytes, got {} bytes",
                bytes.len()
            );
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(TxIdArg(arr))
    }
}

impl std::fmt::Display for TxIdArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl LowerHex for TxIdArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl UpperHex for TxIdArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl TxIdArg {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A `--contract ADDR.NAME[.FN]` filter argument. Round-trips through its
/// string display form for serde so stored `args_json` records the same shape
/// the user typed on the CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractArg {
    pub address: StacksAddress,
    pub contract_name: ContractName,
    /// `None` matches any function call on this contract; `Some(fn)` restricts
    /// to a specific function name.
    pub function_name: Option<ClarityName>,
}

impl FromStr for ContractArg {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(3, '.');
        let addr_str = parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("contract '{s}': missing address before first '.'"))?;
        let name_str = parts.next().filter(|s| !s.is_empty()).ok_or_else(|| {
            anyhow::anyhow!("contract '{s}': expected ADDR.NAME[.FN], missing contract name")
        })?;
        let fn_str = parts.next();

        let address = StacksAddress::from_string(addr_str)
            .with_context(|| format!("contract '{s}': invalid Stacks address '{addr_str}'"))?;
        let contract_name = ContractName::try_from(name_str.to_string())
            .map_err(|e| anyhow::anyhow!("contract '{s}': invalid contract name: {e}"))?;
        let function_name = match fn_str {
            None => None,
            Some("") => bail!("contract '{s}': empty function name after '.'"),
            Some(f) => Some(
                ClarityName::try_from(f.to_string())
                    .map_err(|e| anyhow::anyhow!("contract '{s}': invalid function name: {e}"))?,
            ),
        };

        Ok(ContractArg {
            address,
            contract_name,
            function_name,
        })
    }
}

impl std::fmt::Display for ContractArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.address, self.contract_name.as_str())?;
        if let Some(fn_name) = &self.function_name {
            write!(f, ".{}", fn_name.as_str())?;
        }
        Ok(())
    }
}

impl Serialize for ContractArg {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ContractArg {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Normalize a contract filter list: drop exact duplicates, and within each
/// `(address, contract_name)` group collapse to a single "match any function"
/// entry whenever one is present (it strictly covers the per-function entries).
/// Preserves first-appearance order of surviving entries so error messages and
/// stored args remain predictable.
pub fn normalize_contract_args(input: Vec<ContractArg>) -> Vec<ContractArg> {
    use std::collections::HashMap;

    // Pass 1: find which (address, contract_name) groups have a wide matcher.
    let mut group_has_wide: HashMap<(StacksAddress, ContractName), bool> = HashMap::new();
    for c in &input {
        let key = (c.address.clone(), c.contract_name.clone());
        let entry = group_has_wide.entry(key).or_insert(false);
        if c.function_name.is_none() {
            *entry = true;
        }
    }

    // Pass 2: emit first-occurrence survivors, suppressing per-function entries
    // when their group has a wide matcher, and dropping exact duplicates.
    let mut emitted_wide: std::collections::HashSet<(StacksAddress, ContractName)> =
        std::collections::HashSet::new();
    let mut emitted_specific: std::collections::HashSet<(
        StacksAddress,
        ContractName,
        ClarityName,
    )> = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(input.len());
    for c in input {
        let key = (c.address.clone(), c.contract_name.clone());
        let group_wide = group_has_wide.get(&key).copied().unwrap_or(false);
        match &c.function_name {
            None => {
                if emitted_wide.insert(key) {
                    out.push(c);
                }
            }
            Some(fn_name) => {
                if group_wide {
                    continue;
                }
                let spec_key = (c.address.clone(), c.contract_name.clone(), fn_name.clone());
                if emitted_specific.insert(spec_key) {
                    out.push(c);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> StacksAddress {
        StacksAddress::from_string("ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940").unwrap()
    }

    fn arg(s: &str) -> ContractArg {
        s.parse().unwrap()
    }

    #[test]
    fn contract_arg_parses_addr_and_name() {
        let c: ContractArg = "ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940.my-contract"
            .parse()
            .unwrap();
        assert_eq!(c.address, addr());
        assert_eq!(c.contract_name.as_str(), "my-contract");
        assert!(c.function_name.is_none());
    }

    #[test]
    fn contract_arg_parses_addr_name_and_function() {
        let c: ContractArg = "ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940.my-contract.do-thing"
            .parse()
            .unwrap();
        assert_eq!(c.address, addr());
        assert_eq!(c.contract_name.as_str(), "my-contract");
        assert_eq!(c.function_name.as_ref().unwrap().as_str(), "do-thing");
    }

    #[test]
    fn contract_arg_round_trips_display() {
        for s in [
            "ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940.my-contract",
            "ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940.my-contract.do-thing",
        ] {
            let c: ContractArg = s.parse().unwrap();
            assert_eq!(c.to_string(), s);
        }
    }

    #[test]
    fn contract_arg_round_trips_serde_json() {
        let c: ContractArg = "ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940.my-contract.do-thing"
            .parse()
            .unwrap();
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(
            json,
            "\"ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940.my-contract.do-thing\""
        );
        let back: ContractArg = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn contract_arg_rejects_bad_address() {
        let err = "NOT_AN_ADDRESS.my-contract"
            .parse::<ContractArg>()
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid Stacks address"), "got: {err}");
    }

    #[test]
    fn contract_arg_rejects_missing_contract_name() {
        let err = "ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940"
            .parse::<ContractArg>()
            .unwrap_err()
            .to_string();
        assert!(err.contains("missing contract name"), "got: {err}");
    }

    #[test]
    fn contract_arg_rejects_empty_function() {
        let err = "ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940.my-contract."
            .parse::<ContractArg>()
            .unwrap_err()
            .to_string();
        assert!(err.contains("empty function name"), "got: {err}");
    }

    #[test]
    fn contract_arg_rejects_invalid_contract_name() {
        let err = "ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940.0bad"
            .parse::<ContractArg>()
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid contract name"), "got: {err}");
    }

    #[test]
    fn normalize_drops_specific_when_wide_is_present() {
        let input = vec![
            arg("ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940.my-contract"),
            arg("ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940.my-contract.fn1"),
        ];
        let out = normalize_contract_args(input);
        assert_eq!(out.len(), 1);
        assert!(out[0].function_name.is_none());
    }

    #[test]
    fn normalize_drops_specific_when_wide_appears_later() {
        let input = vec![
            arg("ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940.my-contract.fn1"),
            arg("ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940.my-contract"),
        ];
        let out = normalize_contract_args(input);
        assert_eq!(out.len(), 1);
        assert!(out[0].function_name.is_none());
    }

    #[test]
    fn normalize_dedups_exact_duplicates() {
        let input = vec![
            arg("ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940.my-contract.fn1"),
            arg("ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940.my-contract.fn1"),
        ];
        let out = normalize_contract_args(input);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn normalize_keeps_distinct_function_targets() {
        let input = vec![
            arg("ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940.my-contract.fn1"),
            arg("ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940.my-contract.fn2"),
        ];
        let out = normalize_contract_args(input);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn normalize_independent_groups() {
        let input = vec![
            arg("ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940.alpha"),
            arg("ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940.beta.do-it"),
        ];
        let out = normalize_contract_args(input);
        assert_eq!(out.len(), 2);
    }
}
