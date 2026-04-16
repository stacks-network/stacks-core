// Copyright (C) 2026 Stacks Open Internet Foundation
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

use std::sync::Arc;

use clarity::vm::types::PrincipalData;
use clarity::vm::{ClarityName, ClarityVersion, ContractName, Value};
use madhouse::{Command, CommandWrapper};
use proptest::array::uniform4;
use proptest::prelude::{any, Just, Strategy};

use super::{ok_true, unwrap_block_failure, unwrap_multi_tx_success, unwrap_single_tx_success};
use crate::chainstate::stacks::{
    AssetInfo, FungibleConditionCode, NonfungibleConditionCode, PostConditionPrincipal,
    TransactionPostCondition, TransactionPostConditionMode,
};
use crate::chainstate::tests::consensus::{ConsensusUtils, TestBlock, FAUCET_ADDRESS};
use crate::chainstate::tests::madhouse::context::Epoch33ToEpoch34TestContext;
use crate::chainstate::tests::madhouse::state::Epoch33ToEpoch34TestState;
use crate::core::test_util::to_addr;

/// NFT contract with mint, send, as-contract operations, and STX burn.
const NFT_CONTRACT: &str = "\
(define-non-fungible-token asset uint)
(define-public (mint (id uint))
    (begin (try! (nft-mint? asset id tx-sender)) (ok true)))
(define-public (send (id uint) (recipient principal))
    (begin (try! (nft-transfer? asset id tx-sender recipient)) (ok true)))
(define-public (mint-and-send-as-contract (id uint) (recipient principal))
    (begin
        (try! (nft-mint? asset id current-contract))
        (try! (nft-transfer? asset id current-contract recipient))
        (ok true)))
(define-public (burn-stx (amount uint))
    (stx-burn? amount tx-sender))
";

/// Build the `AssetInfo` for the NFT contract's `asset` token.
fn nft_asset_info() -> AssetInfo {
    AssetInfo {
        contract_address: FAUCET_ADDRESS.clone(),
        contract_name: ContractName::try_from("nft".to_string()).unwrap(),
        asset_name: ClarityName::try_from("asset".to_string()).unwrap(),
    }
}

/// Recipient derived from a strategy-provided seed.
fn recipient_principal(seed: &[u8]) -> PrincipalData {
    use stacks_common::util::secp256k1::Secp256k1PrivateKey;
    let sk = Secp256k1PrivateKey::from_seed(seed);
    PrincipalData::from(to_addr(&sk))
}

/// Assert that a transaction output was aborted by post-conditions.
fn assert_postcond_abort(
    tx_out: &crate::chainstate::tests::consensus::ExpectedTransactionOutput,
    label: &str,
) {
    assert!(
        tx_out
            .vm_error
            .as_ref()
            .is_some_and(|e| e.contains("Post-condition check failure")),
        "{label}: expected post-condition abort, got vm_error: {:?}",
        tx_out.vm_error,
    );
}

/// Deploys the NFT contract at the current epoch's default Clarity version.
pub struct DeployNftContract;

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for DeployNftContract {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        !state.deployed.contains("nft")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let version = ClarityVersion::default_for_epoch(state.current_epoch);
        let deploy_tx =
            ConsensusUtils::new_deploy_tx(state.next_nonce, "nft", NFT_CONTRACT, Some(version));

        let block = TestBlock {
            transactions: vec![deploy_tx],
        };
        let is_naka = state.current_epoch.uses_nakamoto_blocks();
        let result = state.chain.append_block(block, is_naka);

        let tx_out = unwrap_single_tx_success(&result, "DeployNftContract");
        assert!(
            tx_out.vm_error.is_none(),
            "DeployNftContract: VM error: {:?}",
            tx_out.vm_error,
        );

        state.next_nonce += 1;
        state.deployed.insert("nft".to_string());

        info!("DeployNftContract: deployed in {}", state.current_epoch);
    }

    fn label(&self) -> String {
        "DEPLOY_NFT_CONTRACT".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        Just(CommandWrapper::new(DeployNftContract))
    }
}

/// Originator mode allows the contract to move assets without post-conditions
/// covering its operations.
pub struct MintSendOriginatorMode {
    recipient_seed: [u8; 4],
}

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for MintSendOriginatorMode {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        state.is_epoch34() && state.deployed.contains("nft")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let nft_id = state.nft_next_id;
        state.nft_next_id += 1;

        let call_tx = ConsensusUtils::new_call_tx_with_postconds(
            state.next_nonce,
            "nft",
            "mint-and-send-as-contract",
            &[
                Value::UInt(nft_id as u128),
                Value::Principal(recipient_principal(&self.recipient_seed)),
            ],
            TransactionPostConditionMode::Originator,
            vec![],
        );

        let block = TestBlock {
            transactions: vec![call_tx],
        };
        let result = state.chain.append_block(block, true);

        let tx_out = unwrap_single_tx_success(&result, "MintSendOriginatorMode");
        assert!(
            tx_out.vm_error.is_none(),
            "MintSendOriginatorMode: VM error: {:?}",
            tx_out.vm_error
        );
        assert_eq!(
            tx_out.return_type,
            ok_true(),
            "MintSendOriginatorMode: expected (ok true)"
        );

        state.next_nonce += 1;
        info!("MintSendOriginatorMode: succeeded with nft_id={nft_id}");
    }

    fn label(&self) -> String {
        "MINT_SEND_ORIGINATOR_MODE".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        uniform4(any::<u8>()).prop_map(|seed| {
            CommandWrapper::new(MintSendOriginatorMode {
                recipient_seed: seed,
            })
        })
    }
}

/// Same operation under Deny mode fails because the contract's unchecked asset
/// movement is denied.
pub struct MintSendDenyMode {
    recipient_seed: [u8; 4],
}

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for MintSendDenyMode {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        state.is_epoch34() && state.deployed.contains("nft")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let nft_id = state.nft_next_id;
        state.nft_next_id += 1;

        let call_tx = ConsensusUtils::new_call_tx_with_postconds(
            state.next_nonce,
            "nft",
            "mint-and-send-as-contract",
            &[
                Value::UInt(nft_id as u128),
                Value::Principal(recipient_principal(&self.recipient_seed)),
            ],
            TransactionPostConditionMode::Deny,
            vec![],
        );

        let block = TestBlock {
            transactions: vec![call_tx],
        };
        let result = state.chain.append_block(block, true);

        let tx_out = unwrap_single_tx_success(&result, "MintSendDenyMode");
        assert_postcond_abort(tx_out, "MintSendDenyMode");

        state.next_nonce += 1;
        info!("MintSendDenyMode: post-condition abort as expected with nft_id={nft_id}");
    }

    fn label(&self) -> String {
        "MINT_SEND_DENY_MODE".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        uniform4(any::<u8>()).prop_map(|seed| {
            CommandWrapper::new(MintSendDenyMode {
                recipient_seed: seed,
            })
        })
    }
}

/// Originator can transfer own NFT with `Sent` post-condition.
pub struct OriginatorSendsWithPostCond {
    recipient_seed: [u8; 4],
}

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>
    for OriginatorSendsWithPostCond
{
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        state.is_epoch34() && state.deployed.contains("nft")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let nft_id = state.nft_next_id;
        state.nft_next_id += 1;

        // tx1: mint NFT to originator (Deny mode, no postconds — mint is not a
        // "send").
        let tx_mint = ConsensusUtils::new_call_tx_with_postconds(
            state.next_nonce,
            "nft",
            "mint",
            &[Value::UInt(nft_id as u128)],
            TransactionPostConditionMode::Deny,
            vec![],
        );

        // tx2: send NFT with Originator mode + Sent post-condition on Origin.
        let tx_send = ConsensusUtils::new_call_tx_with_postconds(
            state.next_nonce + 1,
            "nft",
            "send",
            &[
                Value::UInt(nft_id as u128),
                Value::Principal(recipient_principal(&self.recipient_seed)),
            ],
            TransactionPostConditionMode::Originator,
            vec![TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Origin,
                nft_asset_info(),
                Value::UInt(nft_id as u128),
                NonfungibleConditionCode::Sent,
            )],
        );

        let block = TestBlock {
            transactions: vec![tx_mint, tx_send],
        };
        let result = state.chain.append_block(block, true);
        let txs = unwrap_multi_tx_success(&result, "OriginatorSendsWithPostCond", 2);

        assert!(
            txs[0].vm_error.is_none(),
            "OriginatorSendsWithPostCond: mint VM error: {:?}",
            txs[0].vm_error
        );
        assert_eq!(txs[0].return_type, ok_true());
        assert!(
            txs[1].vm_error.is_none(),
            "OriginatorSendsWithPostCond: send VM error: {:?}",
            txs[1].vm_error
        );
        assert_eq!(txs[1].return_type, ok_true());

        state.next_nonce += 2;
        info!("OriginatorSendsWithPostCond: both txs succeeded with nft_id={nft_id}");
    }

    fn label(&self) -> String {
        "ORIGINATOR_SENDS_WITH_POSTCOND".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        uniform4(any::<u8>()).prop_map(|seed| {
            CommandWrapper::new(OriginatorSendsWithPostCond {
                recipient_seed: seed,
            })
        })
    }
}

/// `MaybeSent` on an NFT that IS sent always passes.
pub struct SendNftMaybeSentActuallySent {
    recipient_seed: [u8; 4],
}

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>
    for SendNftMaybeSentActuallySent
{
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        state.is_epoch34() && state.deployed.contains("nft")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let nft_id = state.nft_next_id;
        state.nft_next_id += 1;

        let tx_mint = ConsensusUtils::new_call_tx_with_postconds(
            state.next_nonce,
            "nft",
            "mint",
            &[Value::UInt(nft_id as u128)],
            TransactionPostConditionMode::Deny,
            vec![],
        );

        // MaybeSent always passes, regardless of whether the NFT was sent.
        let tx_send = ConsensusUtils::new_call_tx_with_postconds(
            state.next_nonce + 1,
            "nft",
            "send",
            &[
                Value::UInt(nft_id as u128),
                Value::Principal(recipient_principal(&self.recipient_seed)),
            ],
            TransactionPostConditionMode::Deny,
            vec![TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Origin,
                nft_asset_info(),
                Value::UInt(nft_id as u128),
                NonfungibleConditionCode::MaybeSent,
            )],
        );

        let block = TestBlock {
            transactions: vec![tx_mint, tx_send],
        };
        let result = state.chain.append_block(block, true);
        let txs = unwrap_multi_tx_success(&result, "SendNftMaybeSentActuallySent", 2);

        assert!(txs[0].vm_error.is_none());
        assert_eq!(txs[0].return_type, ok_true());
        assert!(
            txs[1].vm_error.is_none(),
            "SendNftMaybeSentActuallySent: send VM error: {:?}",
            txs[1].vm_error
        );
        assert_eq!(txs[1].return_type, ok_true());

        state.next_nonce += 2;
        info!("SendNftMaybeSentActuallySent: succeeded with nft_id={nft_id}");
    }

    fn label(&self) -> String {
        "SEND_NFT_MAYBE_SENT_ACTUALLY_SENT".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        uniform4(any::<u8>()).prop_map(|seed| {
            CommandWrapper::new(SendNftMaybeSentActuallySent {
                recipient_seed: seed,
            })
        })
    }
}

/// `MaybeSent` on an NFT that is NOT sent still passes.
pub struct MintNftMaybeSentNotSent;

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for MintNftMaybeSentNotSent {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        state.is_epoch34() && state.deployed.contains("nft")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let nft_id = state.nft_next_id;
        state.nft_next_id += 1;

        // Mint only. MaybeSent still passes because it is always true
        // regardless of whether the NFT was actually sent.
        let tx_mint = ConsensusUtils::new_call_tx_with_postconds(
            state.next_nonce,
            "nft",
            "mint",
            &[Value::UInt(nft_id as u128)],
            TransactionPostConditionMode::Deny,
            vec![TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Origin,
                nft_asset_info(),
                Value::UInt(nft_id as u128),
                NonfungibleConditionCode::MaybeSent,
            )],
        );

        let block = TestBlock {
            transactions: vec![tx_mint],
        };
        let result = state.chain.append_block(block, true);

        let tx_out = unwrap_single_tx_success(&result, "MintNftMaybeSentNotSent");
        assert!(
            tx_out.vm_error.is_none(),
            "MintNftMaybeSentNotSent: VM error: {:?}",
            tx_out.vm_error
        );
        assert_eq!(tx_out.return_type, ok_true());

        state.next_nonce += 1;
        info!("MintNftMaybeSentNotSent: succeeded with nft_id={nft_id}");
    }

    fn label(&self) -> String {
        "MINT_NFT_MAYBE_SENT_NOT_SENT".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        Just(CommandWrapper::new(MintNftMaybeSentNotSent))
    }
}

/// Originator's own asset movement without post-condition is denied in
/// Originator mode.
pub struct OriginatorSendsNoPostCond {
    recipient_seed: [u8; 4],
}

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for OriginatorSendsNoPostCond {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        state.is_epoch34() && state.deployed.contains("nft")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let nft_id = state.nft_next_id;
        state.nft_next_id += 1;

        // tx1: mint to originator.
        let tx_mint = ConsensusUtils::new_call_tx_with_postconds(
            state.next_nonce,
            "nft",
            "mint",
            &[Value::UInt(nft_id as u128)],
            TransactionPostConditionMode::Deny,
            vec![],
        );

        // tx2: send with Originator mode but NO post-conditions. The
        // originator sends an NFT without a covering post-condition -> denied.
        let tx_send = ConsensusUtils::new_call_tx_with_postconds(
            state.next_nonce + 1,
            "nft",
            "send",
            &[
                Value::UInt(nft_id as u128),
                Value::Principal(recipient_principal(&self.recipient_seed)),
            ],
            TransactionPostConditionMode::Originator,
            vec![],
        );

        let block = TestBlock {
            transactions: vec![tx_mint, tx_send],
        };
        let result = state.chain.append_block(block, true);
        let txs = unwrap_multi_tx_success(&result, "OriginatorSendsNoPostCond", 2);

        // tx1 succeeds (mint is not a "send").
        assert!(txs[0].vm_error.is_none());
        assert_eq!(txs[0].return_type, ok_true());

        // tx2 aborted by post-conditions.
        assert_postcond_abort(&txs[1], "OriginatorSendsNoPostCond");

        state.next_nonce += 2;
        info!("OriginatorSendsNoPostCond: tx2 aborted as expected with nft_id={nft_id}");
    }

    fn label(&self) -> String {
        "ORIGINATOR_SENDS_NO_POSTCOND".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        uniform4(any::<u8>()).prop_map(|seed| {
            CommandWrapper::new(OriginatorSendsNoPostCond {
                recipient_seed: seed,
            })
        })
    }
}

/// Both SIP-040 features (Originator mode and MaybeSent) are rejected
/// pre-Epoch34 by the static epoch validation.
pub struct PreEpoch34SIP040Rejected;

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for PreEpoch34SIP040Rejected {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        !state.is_epoch34() && state.deployed.contains("nft")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let is_naka = state.current_epoch.uses_nakamoto_blocks();

        // Block 1: Originator mode rejected pre-Epoch34.
        let tx_originator = ConsensusUtils::new_call_tx_with_postconds(
            state.next_nonce,
            "nft",
            "mint",
            &[Value::UInt(state.nft_next_id as u128)],
            TransactionPostConditionMode::Originator,
            vec![],
        );
        state.nft_next_id += 1;

        let block1 = TestBlock {
            transactions: vec![tx_originator],
        };
        let result1 = state.chain.append_block(block1, is_naka);
        unwrap_block_failure(&result1, "PreEpoch34SIP040Rejected: Originator mode");

        // Block 2: MaybeSent post-condition rejected pre-Epoch34.
        let nft_id_2 = state.nft_next_id;
        state.nft_next_id += 1;

        let tx_maybesent = ConsensusUtils::new_call_tx_with_postconds(
            state.next_nonce,
            "nft",
            "mint",
            &[Value::UInt(nft_id_2 as u128)],
            TransactionPostConditionMode::Deny,
            vec![TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Origin,
                nft_asset_info(),
                Value::UInt(nft_id_2 as u128),
                NonfungibleConditionCode::MaybeSent,
            )],
        );

        let block2 = TestBlock {
            transactions: vec![tx_maybesent],
        };
        let result2 = state.chain.append_block(block2, is_naka);
        unwrap_block_failure(&result2, "PreEpoch34SIP040Rejected: MaybeSent");

        // No nonces consumed (both blocks were rejected).
        info!("PreEpoch34SIP040Rejected: both blocks rejected as expected");
    }

    fn label(&self) -> String {
        "PRE_EPOCH34_SIP040_REJECTED".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        Just(CommandWrapper::new(PreEpoch34SIP040Rejected))
    }
}

/// Mint in tx1, send in tx2 of the same block. Post-conditions are per-tx.
pub struct MultiTxMintThenSend {
    recipient_seed: [u8; 4],
}

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for MultiTxMintThenSend {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        state.is_epoch34() && state.deployed.contains("nft")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let nft_id = state.nft_next_id;
        state.nft_next_id += 1;

        let tx_mint = ConsensusUtils::new_call_tx_with_postconds(
            state.next_nonce,
            "nft",
            "mint",
            &[Value::UInt(nft_id as u128)],
            TransactionPostConditionMode::Deny,
            vec![],
        );

        // tx2: send with Deny mode + `Sent` post-condition. The post-condition
        // sees the transfer in tx2's asset map.
        let tx_send = ConsensusUtils::new_call_tx_with_postconds(
            state.next_nonce + 1,
            "nft",
            "send",
            &[
                Value::UInt(nft_id as u128),
                Value::Principal(recipient_principal(&self.recipient_seed)),
            ],
            TransactionPostConditionMode::Deny,
            vec![TransactionPostCondition::Nonfungible(
                PostConditionPrincipal::Origin,
                nft_asset_info(),
                Value::UInt(nft_id as u128),
                NonfungibleConditionCode::Sent,
            )],
        );

        let block = TestBlock {
            transactions: vec![tx_mint, tx_send],
        };
        let result = state.chain.append_block(block, true);
        let txs = unwrap_multi_tx_success(&result, "MultiTxMintThenSend", 2);

        assert!(txs[0].vm_error.is_none());
        assert_eq!(txs[0].return_type, ok_true());
        assert!(
            txs[1].vm_error.is_none(),
            "MultiTxMintThenSend: send VM error: {:?}",
            txs[1].vm_error
        );
        assert_eq!(txs[1].return_type, ok_true());

        state.next_nonce += 2;
        info!("MultiTxMintThenSend: both txs succeeded with nft_id={nft_id}");
    }

    fn label(&self) -> String {
        "MULTI_TX_MINT_THEN_SEND".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        uniform4(any::<u8>()).prop_map(|seed| {
            CommandWrapper::new(MultiTxMintThenSend {
                recipient_seed: seed,
            })
        })
    }
}

/// Multiple STX burns in one block. Each tx's post-condition checks only that
/// tx's asset map.
pub struct MultiTxStxPerTxPostConds {
    amount_x: u64,
    amount_y: u64,
}

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for MultiTxStxPerTxPostConds {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        state.is_epoch34() && state.deployed.contains("nft")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let tx1 = ConsensusUtils::new_call_tx_with_postconds(
            state.next_nonce,
            "nft",
            "burn-stx",
            &[Value::UInt(self.amount_x as u128)],
            TransactionPostConditionMode::Deny,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentEq,
                self.amount_x,
            )],
        );

        let tx2 = ConsensusUtils::new_call_tx_with_postconds(
            state.next_nonce + 1,
            "nft",
            "burn-stx",
            &[Value::UInt(self.amount_y as u128)],
            TransactionPostConditionMode::Deny,
            vec![TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentEq,
                self.amount_y,
            )],
        );

        let block = TestBlock {
            transactions: vec![tx1, tx2],
        };
        let result = state.chain.append_block(block, true);
        let txs = unwrap_multi_tx_success(&result, "MultiTxStxPerTxPostConds", 2);

        assert!(
            txs[0].vm_error.is_none(),
            "MultiTxStxPerTxPostConds: tx1 VM error: {:?}",
            txs[0].vm_error
        );
        assert!(
            txs[1].vm_error.is_none(),
            "MultiTxStxPerTxPostConds: tx2 VM error: {:?}",
            txs[1].vm_error
        );

        state.next_nonce += 2;
        info!(
            "MultiTxStxPerTxPostConds: both txs succeeded (x={}, y={})",
            self.amount_x, self.amount_y,
        );
    }

    fn label(&self) -> String {
        "MULTI_TX_STX_PER_TX_POSTCONDS".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        (1u64..1_000, 1u64..1_000).prop_map(|(x, y)| {
            CommandWrapper::new(MultiTxStxPerTxPostConds {
                amount_x: x,
                amount_y: y,
            })
        })
    }
}

/// Originator mode applies per-tx, not across a block. tx1 uses Originator
/// mode (succeeds), tx2 uses Deny mode (post-condition abort).
pub struct OriginatorMultiTxMixed {
    recipient_seed: [u8; 4],
}

impl Command<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext> for OriginatorMultiTxMixed {
    fn check(&self, state: &Epoch33ToEpoch34TestState) -> bool {
        state.is_epoch34() && state.deployed.contains("nft")
    }

    fn apply(&self, state: &mut Epoch33ToEpoch34TestState) {
        let nft_id1 = state.nft_next_id;
        let nft_id2 = state.nft_next_id + 1;
        state.nft_next_id += 2;

        // tx1: Originator mode —> contract's asset movement is allowed.
        let tx1 = ConsensusUtils::new_call_tx_with_postconds(
            state.next_nonce,
            "nft",
            "mint-and-send-as-contract",
            &[
                Value::UInt(nft_id1 as u128),
                Value::Principal(recipient_principal(&self.recipient_seed)),
            ],
            TransactionPostConditionMode::Originator,
            vec![],
        );

        // tx2: Deny mode —> contract's asset movement is denied.
        let tx2 = ConsensusUtils::new_call_tx_with_postconds(
            state.next_nonce + 1,
            "nft",
            "mint-and-send-as-contract",
            &[
                Value::UInt(nft_id2 as u128),
                Value::Principal(recipient_principal(&self.recipient_seed)),
            ],
            TransactionPostConditionMode::Deny,
            vec![],
        );

        let block = TestBlock {
            transactions: vec![tx1, tx2],
        };
        let result = state.chain.append_block(block, true);
        let txs = unwrap_multi_tx_success(&result, "OriginatorMultiTxMixed", 2);

        // tx1 succeeds.
        assert!(
            txs[0].vm_error.is_none(),
            "OriginatorMultiTxMixed: tx1 VM error: {:?}",
            txs[0].vm_error
        );
        assert_eq!(txs[0].return_type, ok_true());

        // tx2 aborted by post-conditions.
        assert_postcond_abort(&txs[1], "OriginatorMultiTxMixed");

        state.next_nonce += 2;
        info!("OriginatorMultiTxMixed: tx1 passed, tx2 aborted as expected");
    }

    fn label(&self) -> String {
        "ORIGINATOR_MULTI_TX_MIXED".to_string()
    }

    fn build(
        _ctx: Arc<Epoch33ToEpoch34TestContext>,
    ) -> impl Strategy<Value = CommandWrapper<Epoch33ToEpoch34TestState, Epoch33ToEpoch34TestContext>>
    {
        uniform4(any::<u8>()).prop_map(|seed| {
            CommandWrapper::new(OriginatorMultiTxMixed {
                recipient_seed: seed,
            })
        })
    }
}
