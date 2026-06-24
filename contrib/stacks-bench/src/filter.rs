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

use blockstack_lib::burnchains::Txid;
use blockstack_lib::chainstate::stacks::{
    StacksTransaction, TransactionContractCall, TransactionPayload,
};
use clarity::vm::representations::{ClarityName, ContractName};
use stacks_common::types::chainstate::StacksAddress;

#[derive(Debug, Clone)]
pub enum TxFilter {
    /// Match `ContractCall` payloads. Empty matchers vec matches *any*
    /// contract-call; a non-empty vec matches payloads accepted by at least
    /// one matcher (OR semantics).
    ContractCall(Vec<ContractMatcher>),
    Txid(Txid),
}

/// A single contract-call match predicate. Accepts a `TransactionContractCall`
/// iff `address` and `contract_name` match exactly and, when `function_name`
/// is `Some`, the call's function name also matches.
#[derive(Debug, Clone)]
pub struct ContractMatcher {
    address: StacksAddress,
    contract_name: ContractName,
    function_name: Option<ClarityName>,
}

impl ContractMatcher {
    pub fn new(
        address: StacksAddress,
        contract_name: ContractName,
        function_name: Option<ClarityName>,
    ) -> Self {
        Self {
            address,
            contract_name,
            function_name,
        }
    }

    pub fn matches_call(&self, cc: &TransactionContractCall) -> bool {
        self.address == cc.address
            && self.contract_name == cc.contract_name
            && self
                .function_name
                .as_ref()
                .is_none_or(|f| f == &cc.function_name)
    }
}

impl TxFilter {
    pub fn matches(&self, tx: &StacksTransaction) -> bool {
        match self {
            TxFilter::ContractCall(matchers) => {
                let TransactionPayload::ContractCall(cc) = &tx.payload else {
                    return false;
                };
                matchers.is_empty() || matchers.iter().any(|m| m.matches_call(cc))
            }
            TxFilter::Txid(target) => tx.txid() == *target,
        }
    }
}

#[cfg(test)]
mod tests {
    use clarity::vm::Value;
    use stacks_common::types::Address;

    use super::*;

    fn addr() -> StacksAddress {
        StacksAddress::from_string("ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940").unwrap()
    }

    fn cname(s: &str) -> ContractName {
        ContractName::try_from(s.to_string()).unwrap()
    }

    fn fname(s: &str) -> ClarityName {
        ClarityName::try_from(s.to_string()).unwrap()
    }

    fn call(contract: &str, function: &str) -> TransactionContractCall {
        TransactionContractCall {
            address: addr(),
            contract_name: cname(contract),
            function_name: fname(function),
            function_args: Vec::<Value>::new(),
        }
    }

    #[test]
    fn matches_when_address_contract_and_function_all_match() {
        let m = ContractMatcher::new(addr(), cname("my-contract"), Some(fname("do-thing")));
        assert!(m.matches_call(&call("my-contract", "do-thing")));
    }

    #[test]
    fn matches_when_function_unspecified() {
        let m = ContractMatcher::new(addr(), cname("my-contract"), None);
        assert!(m.matches_call(&call("my-contract", "any-fn")));
    }

    #[test]
    fn does_not_match_wrong_function() {
        let m = ContractMatcher::new(addr(), cname("my-contract"), Some(fname("do-thing")));
        assert!(!m.matches_call(&call("my-contract", "other-fn")));
    }

    #[test]
    fn does_not_match_wrong_contract_name() {
        let m = ContractMatcher::new(addr(), cname("my-contract"), None);
        assert!(!m.matches_call(&call("other-contract", "any-fn")));
    }

    #[test]
    fn matches_any_of_multiple_matchers() {
        let matchers = [
            ContractMatcher::new(addr(), cname("alpha"), None),
            ContractMatcher::new(addr(), cname("beta"), Some(fname("hit"))),
        ];
        let any = |cc: &TransactionContractCall| matchers.iter().any(|m| m.matches_call(cc));
        assert!(any(&call("alpha", "anything")));
        assert!(any(&call("beta", "hit")));
        assert!(!any(&call("beta", "miss")));
        assert!(!any(&call("gamma", "anything")));
    }

    /// Exercise the full `TxFilter::matches` dispatcher (not just
    /// `ContractMatcher::matches_call`), confirming that non-`ContractCall`
    /// payloads short-circuit to `false` and matching `ContractCall` payloads
    /// flow through to the matcher set.
    #[test]
    fn tx_filter_matches_dispatcher() {
        use blockstack_lib::chainstate::stacks::{
            StacksPrivateKey, StacksTransaction, TransactionAuth, TransactionPayload,
            TransactionVersion,
        };

        let auth = TransactionAuth::from_p2pkh(&StacksPrivateKey::random()).unwrap();

        let tx_contract_call = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_contract_call(addr(), "my-contract", "do-thing", vec![])
                .unwrap(),
        );
        let tx_smart_contract = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth.clone(),
            TransactionPayload::new_smart_contract("hello", "(define-public (f) (ok u1))", None)
                .unwrap(),
        );

        let f = TxFilter::ContractCall(vec![ContractMatcher::new(
            addr(),
            cname("my-contract"),
            None,
        )]);

        assert!(f.matches(&tx_contract_call));
        assert!(!f.matches(&tx_smart_contract));

        // Empty matchers vec acts as "any contract call".
        let any_cc = TxFilter::ContractCall(vec![]);
        assert!(any_cc.matches(&tx_contract_call));
        assert!(!any_cc.matches(&tx_smart_contract));
    }
}
